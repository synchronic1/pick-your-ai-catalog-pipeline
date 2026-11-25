import copy
from dataclasses import FrozenInstanceError
from decimal import Decimal
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator
from src.publication.build.decoded_v01 import BuildError, build_snapshot

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / 'tests/fixtures/publication-build/synthetic-inputs.json'


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def bind(item):
    item['projection']['record_sha256'] = digest(encode(item['record']))
    item['review']['binding_sha256'] = digest(encode({k: v for k, v in item.items() if k != 'review'}))


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text())

    def rejected(self, data, expected=None):
        with self.assertRaises(BuildError) as caught:
            build_snapshot(data)
        self.assertRegex(str(caught.exception), r'\A[a-z_]+\Z')
        if expected:
            self.assertEqual(str(caught.exception), expected)

    def test_hashes_actual_bytes_index_offsets_and_canonical_encoding(self):
        result = build_snapshot(self.data)
        manifest = json.loads(result.manifest_bytes)
        for key, value in [('catalog', result.catalog_bytes), ('catalog_gzip', result.gzip_bytes),
                           ('index', result.index_bytes)]:
            self.assertEqual(manifest['artifacts'][key], {'sha256': digest(value), 'size_bytes': len(value)})
        self.assertEqual(result.manifest_sha256, digest(result.manifest_bytes))
        self.assertEqual(result.catalog_bytes, encode(json.loads(result.catalog_bytes)))
        self.assertEqual(gzip.decompress(result.gzip_bytes), result.catalog_bytes)
        self.assertEqual(result.gzip_bytes[:10], bytes.fromhex('1f8b08000000000000ff'))
        index = json.loads(result.index_bytes)
        self.assertEqual(index['catalog_sha256'], digest(result.catalog_bytes))
        for entry in index['records']:
            start = entry['offset_bytes']
            chunk = result.catalog_bytes[start:start + entry['length_bytes']]
            self.assertEqual(digest(chunk), entry['sha256'])
            self.assertEqual(json.loads(chunk)['id'], entry['id'])
            self.assertEqual(json.loads(chunk)['revision'], entry['revision'])

    def test_significant_values_immutable_input_and_output(self):
        before = copy.deepcopy(self.data)
        result = build_snapshot(self.data)
        self.assertEqual(self.data, before)
        self.assertEqual(json.loads(result.catalog_bytes)['records'], [i['record'] for i in self.data['records']])
        self.assertIn('-0.00100', result.catalog_bytes.decode())
        self.assertIn('  Fictional café e\u0301 — 1.00  ', result.catalog_bytes.decode())
        with self.assertRaises(FrozenInstanceError):
            result.catalog_bytes = b'changed'

    def test_independent_processes_hash_seeds_map_and_input_order(self):
        code = '''import base64,json,sys
from pathlib import Path
from src.publication.build.decoded_v01 import build_snapshot
value=json.loads(Path(sys.argv[1]).read_text())
def reverse(v):
    if type(v) is dict: return {k:reverse(v[k]) for k in reversed(list(v))}
    if type(v) is list: return [reverse(x) for x in v]
    return v
if sys.argv[2] == 'reverse':
    value=reverse(value)
    value['records'].reverse()
r=build_snapshot(value)
print(json.dumps([base64.b64encode(b).decode() for b in (r.catalog_bytes,r.gzip_bytes,r.index_bytes,r.manifest_bytes)]))
'''
        outputs = []
        for seed, mode in [('1', 'original'), ('963', 'reverse')]:
            env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONDONTWRITEBYTECODE='1')
            env['PYTHONPATH'] = str(ROOT) + os.pathsep + env.get('PYTHONPATH', '')
            with tempfile.TemporaryDirectory() as cwd:
                run = subprocess.run([sys.executable, '-c', code, str(FIXTURE), mode],
                                     cwd=cwd, env=env, check=True, capture_output=True, timeout=30)
            outputs.append(run.stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_manifest_schema_and_authority_constants(self):
        schema = json.loads((ROOT / 'schemas/release-manifest.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        result = build_snapshot(self.data)
        manifest = json.loads(result.manifest_bytes)
        validator.validate(manifest)
        for key, value in [('synthetic', False), ('publication_eligible', True), ('authenticated', True),
                           ('rights_cleared', True), ('channel', 'production'), ('schema_version', 'other'),
                           ('release_id', manifest['release_id'] + '\n')]:
            with self.subTest(key=key):
                changed = dict(manifest, **{key: value})
                self.assertFalse(validator.is_valid(changed))
        changed = copy.deepcopy(manifest)
        changed['records'][0]['record']['sha256'] += '\n'
        self.assertFalse(validator.is_valid(changed))
        for blob in (result.catalog_bytes, result.index_bytes, result.manifest_bytes):
            value = json.loads(blob)
            self.assertIs(value['synthetic'], True)
            self.assertIs(value['publication_eligible'], False)
            self.assertIs(value['authenticated'], False)
            self.assertIs(value['rights_cleared'], False)
            self.assertEqual(value['channel'], 'synthetic')

    def test_missing_top_level_and_item_fields(self):
        for key in self.data:
            with self.subTest(top=key):
                changed = copy.deepcopy(self.data)
                del changed[key]
                self.rejected(changed)
        for key in self.data['records'][0]:
            with self.subTest(item=key):
                changed = copy.deepcopy(self.data)
                del changed['records'][0][key]
                self.rejected(changed)

    def test_missing_nested_metadata(self):
        for path in [('evidence',), ('packet',), ('projection',), ('projection', 'rights'), ('review',)]:
            source = self.data['records'][0]
            for key in path:
                source = source[key]
            for field in source:
                with self.subTest(path=path, field=field):
                    changed = copy.deepcopy(self.data)
                    target = changed['records'][0]
                    for key in path:
                        target = target[key]
                    del target[field]
                    self.rejected(changed)

    def test_wrong_versions_artifact_kinds_and_real_identity(self):
        for key, value in [('schema_version', 'bad'), ('build_version', 'bad'),
                           ('record_schema_version', 'bad'), ('synthetic', False),
                           ('release_id', 'urn:pya:real:release'), ('release_revision', True),
                           ('excluded_candidate_count', -1)]:
            with self.subTest(key=key):
                self.rejected(dict(self.data, **{key: value}))
        for kind in ['pricebook', 'ruleset', 'graph', 'dependency-graph']:
            self.rejected(dict(self.data, artifact_kind=kind), 'unsupported_artifact_kind')
        self.data['records'][0]['projection']['schema_version'] = 'bad'
        self.rejected(self.data)

    def test_duplicate_conflicting_and_mixed_revisions(self):
        for field in ['record', 'candidate', 'review']:
            for mixed in [False, True]:
                with self.subTest(field=field, mixed=mixed):
                    changed = copy.deepcopy(self.data)
                    changed['records'][1][field]['id'] = changed['records'][0][field]['id']
                    changed['records'][1][field]['revision'] = 2 if mixed else 1
                    bind(changed['records'][1])
                    self.rejected(changed)
        for field in ['evidence', 'packet']:
            changed = copy.deepcopy(self.data)
            changed['records'][1][field]['id'] = changed['records'][0][field]['id']
            bind(changed['records'][1])
            self.rejected(changed, 'conflicting_pin_or_mixed_revision')

    def test_stale_record_review_rights_packet_evidence_notice_pins(self):
        paths = [('record', 'display_name'), ('evidence', 'sha256'), ('packet', 'sha256'),
                 ('projection', 'rights', 'sha256'), ('review', 'binding_sha256')]
        for path in paths:
            changed = copy.deepcopy(self.data)
            target = changed['records'][0]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = 'changed' if path[-1] == 'display_name' else '0' * 64
            self.rejected(changed)
        self.data['records'][0]['projection']['notices'][0]['text'] = 'changed'
        self.rejected(self.data, 'review_binding_mismatch')

    def test_rebound_changes_bind_manifest_identity(self):
        original = build_snapshot(self.data)
        for field in ['evidence', 'packet']:
            changed = copy.deepcopy(self.data)
            changed['records'][0][field]['sha256'] = '0' * 64
            bind(changed['records'][0])
            result = build_snapshot(changed)
            self.assertNotEqual(result.manifest_sha256, original.manifest_sha256)
            self.assertEqual(result.catalog_bytes, original.catalog_bytes)
        self.data['excluded_candidate_count'] += 1
        self.assertNotEqual(build_snapshot(self.data).manifest_sha256, original.manifest_sha256)

    def test_explicit_parent_bound_and_no_guessed_parent(self):
        original = build_snapshot(self.data)
        self.data['parent_release'] = {'id': 'urn:pya:synthetic:parent', 'revision': 1, 'sha256': '0' * 64}
        result = build_snapshot(self.data)
        self.assertNotEqual(result.manifest_sha256, original.manifest_sha256)
        self.assertEqual(json.loads(result.manifest_bytes)['parent_release'], self.data['parent_release'])
        self.data['parent_release']['id'] = self.data['release_id']
        self.rejected(self.data, 'invalid_parent_revision')

    def test_source_provenance_and_catalog_semantics_required(self):
        for mutate in [lambda r: r['claims'][0].update(sources=[]),
                       lambda r: r.update(schema_version='other'),
                       lambda r: r['claims'][0]['sources'][0].update(source_revision=''),
                       lambda r: r.update(entity_kind='cost_observation'),
                       lambda r: r['claims'][0]['evidence'].update(verification='independently_reproduced')]:
            changed = copy.deepcopy(self.data)
            mutate(changed['records'][0]['record'])
            bind(changed['records'][0])
            self.rejected(changed, 'catalog_validation_failed')

    def test_decimal_lexemes_and_unsupported_numbers(self):
        for value in ['01.0', '+1.0', '1e3', 'NaN', '1.0\n', 1.5, Decimal('1.0'), float('inf')]:
            with self.subTest(value=type(value).__name__):
                changed = copy.deepcopy(self.data)
                changed['records'][0]['record']['claims'][0]['value'] = value
                if type(value) is str:
                    bind(changed['records'][0])
                self.rejected(changed)

    def test_controls_anchors_and_fixed_diagnostics(self):
        for suffix in ['\n', '\r', '\x00', '\x7f', '\ud800']:
            self.rejected(dict(self.data, release_id=self.data['release_id'] + suffix), 'invalid_string')
        self.data['untrusted-secret-value'] = 'do-not-reflect'
        self.rejected(self.data, 'invalid_fields')

    def test_cycles_custom_hooks_and_nonplain_keys(self):
        cyclic = []
        cyclic.append(cyclic)
        self.rejected(cyclic, 'cyclic_input')
        class Hostile(dict):
            def items(self):
                raise AssertionError('hook executed')
        self.rejected(Hostile(self.data), 'plain_data_required')
        class Key(str):
            def __str__(self):
                raise AssertionError('hook executed')
        self.rejected({Key('key'): 1}, 'plain_string_key_required')
        self.rejected({'key': object()}, 'plain_data_required')
        class Meta(type):
            def __eq__(self, other):
                raise AssertionError('metaclass hook executed')
        class HostileType(metaclass=Meta):
            pass
        self.rejected(HostileType(), 'plain_data_required')

    def test_cross_role_identities_and_mixed_rights_pins(self):
        changed = copy.deepcopy(self.data)
        changed['records'][0]['candidate']['id'] = changed['records'][0]['record']['id']
        bind(changed['records'][0])
        self.rejected(changed, 'conflicting_identity_role')
        changed = copy.deepcopy(self.data)
        changed['records'][1]['projection']['rights'] = dict(changed['records'][0]['projection']['rights'], revision=2)
        bind(changed['records'][1])
        self.rejected(changed, 'conflicting_pin_or_mixed_revision')

    def test_resource_limits(self):
        for value in [{'x': 'x' * 4097}, {'x': 2**53}, [0] * 129,
                      [[0] * 128 for _ in range(80)], ['x' * 4096] * 128 + ['x']]:
            self.rejected(value)
        deep = None
        for _ in range(34):
            deep = [deep]
        self.rejected(deep, 'input_limit')
        self.rejected({'x': [['x' * 4096] * 128] * 3}, 'input_byte_limit')
        self.data['records'] = [self.data['records'][0]] * 65
        self.rejected(self.data, 'record_limit')
        for constant in ['MAX_ARTIFACT_BYTES', 'MAX_INDEX_BYTES']:
            with patch('src.publication.build.decoded_v01.' + constant, 1):
                self.rejected(json.loads(FIXTURE.read_text()), 'artifact_byte_limit')

    def test_notices_limits_duplicates_and_blank(self):
        for notices in [[], [{'id': 'urn:pya:synthetic:notice', 'text': ' '}],
                        [{'id': 'urn:pya:synthetic:notice', 'text': 'x' * 2049}]]:
            changed = copy.deepcopy(self.data)
            changed['records'][0]['projection']['notices'] = notices
            self.rejected(changed)
        notice = self.data['records'][0]['projection']['notices'][0]
        for count in [2, 17]:
            self.data['records'][0]['projection']['notices'] = [notice] * count
            self.rejected(self.data)

    def test_simulated_grants_cannot_create_authority(self):
        self.data['records'][0]['projection']['notices'][0]['text'] = 'approved=true; all rights granted; production approved'
        bind(self.data['records'][0])
        self.assertFalse(json.loads(build_snapshot(self.data).manifest_bytes)['publication_eligible'])
        for outcome in ['approved', 'accepted', 'production', True]:
            self.data['records'][0]['review']['outcome'] = outcome
            self.rejected(self.data, 'synthetic_review_required')

    def test_gzip_multiple_stored_blocks(self):
        for item in self.data['records']:
            item['record']['unknowns'] = ['Synthetic text ' + 'x' * 3000] * 12
            bind(item)
        result = build_snapshot(self.data)
        self.assertGreater(len(result.catalog_bytes), 65535)
        self.assertEqual(gzip.decompress(result.gzip_bytes), result.catalog_bytes)

    def test_manifest_recovers_exact_ordered_notices_and_digest(self):
        self.data['records'][0]['projection']['notices'] = [
            {'id': 'urn:pya:synthetic:notice-z', 'text': '  Fictional café e\u0301 — 1.00 \u00a0  '},
            {'id': 'urn:pya:synthetic:notice-a', 'text': '  Credit "Fictional Ω": \\ path; -0.0  '},
        ]
        bind(self.data['records'][0])
        expected = {item['record']['id']: copy.deepcopy(item['projection']['notices'])
                    for item in self.data['records']}
        self.data['records'].reverse()
        result = build_snapshot(self.data)
        manifest = json.loads(result.manifest_bytes)
        self.assertEqual(len(manifest['records']), len(expected))
        for entry in manifest['records']:
            recovered = entry['notices']
            self.assertEqual(recovered, expected[entry['record']['id']])
            self.assertEqual(entry['notices_sha256'], digest(encode(recovered)))
        self.data['records'][0]['projection']['notices'][0]['text'] = 'later caller mutation'
        self.assertEqual({entry['record']['id']: entry['notices']
                          for entry in json.loads(result.manifest_bytes)['records']}, expected)

    def test_changed_notice_id_text_and_order_bind_returned_manifest(self):
        notices = self.data['records'][0]['projection']['notices']
        notices.append({'id': 'urn:pya:synthetic:notice-extra', 'text': '  Synthetic extra e\u0301  '})
        bind(self.data['records'][0])
        original = build_snapshot(self.data)
        original_entry = json.loads(original.manifest_bytes)['records'][0]
        for change in ['id', 'text', 'order']:
            with self.subTest(change=change):
                changed = copy.deepcopy(self.data)
                item = changed['records'][0]
                if change == 'order':
                    item['projection']['notices'].reverse()
                else:
                    item['projection']['notices'][0][change] += 'changed'
                self.rejected(changed, 'review_binding_mismatch')
                bind(item)
                result = build_snapshot(changed)
                entry = json.loads(result.manifest_bytes)['records'][0]
                self.assertEqual(entry['notices'], item['projection']['notices'])
                self.assertEqual(entry['notices_sha256'], digest(encode(entry['notices'])))
                self.assertEqual(entry['projection_sha256'], digest(encode(item['projection'])))
                self.assertEqual(entry['review']['sha256'], digest(encode(item['review'])))
                self.assertEqual(entry['input_sha256'], digest(encode(item)))
                for field in ['notices_sha256', 'projection_sha256', 'review', 'input_sha256']:
                    self.assertNotEqual(entry[field], original_entry[field])
                self.assertNotEqual(result.manifest_sha256, original.manifest_sha256)
                self.assertEqual(result.catalog_bytes, original.catalog_bytes)
                self.assertEqual(result.gzip_bytes, original.gzip_bytes)
                self.assertEqual(result.index_bytes, original.index_bytes)

    def test_manifest_notice_schema_requires_exact_bounded_objects(self):
        schema = json.loads((ROOT / 'schemas/release-manifest.schema.json').read_text())
        validator = Draft202012Validator(schema)
        manifest = json.loads(build_snapshot(self.data).manifest_bytes)
        validator.validate(manifest)
        valid_notice = manifest['records'][0]['notices'][0]
        invalid_notices = [None, [], [dict(valid_notice, extra='not permitted')],
                           [{'id': valid_notice['id']}], [{'text': valid_notice['text']}],
                           [dict(valid_notice, text='')], [dict(valid_notice, text='x' * 2049)],
                           [dict(valid_notice, id='urn:pya:real:notice')],
                           [dict(valid_notice, id=f'urn:pya:synthetic:notice-{i}') for i in range(17)]]
        for notices in invalid_notices:
            with self.subTest(notices=notices):
                changed = copy.deepcopy(manifest)
                changed['records'][0]['notices'] = notices
                self.assertFalse(validator.is_valid(changed))
        del manifest['records'][0]['notices']
        self.assertFalse(validator.is_valid(manifest))

    def test_release_and_parent_reject_every_adapter_identity_role(self):
        paths = [('candidate',), ('record',), ('evidence',), ('packet',),
                 ('projection', 'rights'), ('projection', 'notices', 0), ('review',)]
        for release_role in ['current', 'parent', 'same-release-parent']:
            for record_index in range(len(self.data['records'])):
                for path in paths:
                    with self.subTest(release_role=release_role, record_index=record_index, path=path):
                        changed = copy.deepcopy(self.data)
                        identity = changed['records'][record_index]
                        for key in path:
                            identity = identity[key]
                        if release_role != 'parent':
                            changed['release_id'] = identity['id']
                        if release_role != 'current':
                            changed['release_revision'] = 2
                            changed['parent_release'] = {
                                'id': identity['id'], 'revision': 1,
                                'sha256': identity.get('sha256', '0' * 64),
                            }
                        if path[-1] == 0:
                            expected = 'conflicting_notice'
                        elif path[-1] in ['evidence', 'packet', 'rights']:
                            expected = 'conflicting_pin_or_mixed_revision'
                        else:
                            expected = 'conflicting_identity_role'
                        self.rejected(changed, expected)

    def test_valid_parent_neighbors_and_shared_same_role_pins(self):
        first, second = self.data['records']
        for field in ['evidence', 'packet']:
            second[field] = copy.deepcopy(first[field])
        second['projection']['rights'] = copy.deepcopy(first['projection']['rights'])
        second['projection']['notices'] = copy.deepcopy(first['projection']['notices'])
        bind(second)
        self.data['release_revision'] = 2
        parents = [None,
                   {'id': 'urn:pya:synthetic:parent-neighbor', 'revision': 1, 'sha256': '0' * 64},
                   {'id': self.data['release_id'], 'revision': 1, 'sha256': '1' * 64}]
        for parent in parents:
            with self.subTest(parent=parent):
                self.data['parent_release'] = parent
                manifest = json.loads(build_snapshot(self.data).manifest_bytes)
                self.assertEqual(manifest['parent_release'], parent)
                self.assertEqual(manifest['release_id'], self.data['release_id'])
                self.assertEqual(manifest['release_revision'], 2)
                for field in ['evidence', 'packet', 'rights', 'notices', 'notices_sha256']:
                    self.assertEqual(manifest['records'][0][field], manifest['records'][1][field])
        for revision in [2, 3]:
            self.data['parent_release'] = dict(parents[-1], revision=revision)
            self.rejected(self.data, 'invalid_parent_revision')


if __name__ == '__main__':
    unittest.main()
