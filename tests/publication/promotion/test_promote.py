"""Offline synthetic tests; checksums below are deliberately not signatures."""
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from src.publication.build.decoded_v01 import BuildResult, build_snapshot
from src.publication.promote import (FixturePromoter, PromotionError, fixture_packet,
                                     fixture_proof, MAX_BYTES, MAX_HISTORY)
from src.storage import FixtureStore

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / 'tests/fixtures/publication-build/synthetic-inputs.json'
PEOPLE = ['urn:pya:synthetic:reviewer-a', 'urn:pya:synthetic:reviewer-b']


def bundle(n=1, parent=None):
    data = json.loads(FIXTURE.read_text())
    data.update(release_revision=n, parent_release=parent)
    return build_snapshot(data)


def packet(build, suffix='one'):
    return fixture_packet(build, 'urn:pya:synthetic:operation-' + suffix, PEOPLE)


def parent(receipt):
    return dict(id=receipt['release_id'], revision=receipt['release_revision'],
                sha256=receipt['manifest_sha256'])


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name
        self.store = FixtureStore(self.root + '/store', 'synthetic_public_artifact')
        self.p = FixturePromoter(self.root + '/pointer', self.store)
        self.addCleanup(self.store.close)
        self.addCleanup(self.p.close)
        self.build = bundle()
        self.packet = packet(self.build)
        self.p.set_fixture_decision(self.packet, state='active', expected_version=0)

    def promote(self, build=None, p=None, expected=None):
        build, p = build or self.build, p or self.packet
        return self.p.promote(build, p, fixture_proof(p),
            expected_revision=expected['revision'] if expected else 0,
            expected_sha256=expected['manifest_sha256'] if expected else None)

    def reject(self, code, function, *args, **kwargs):
        with self.assertRaisesRegex(PromotionError, '^' + code + '$'):
            function(*args, **kwargs)

    def next_release(self, current):
        build = bundle(2, parent(current))
        p = packet(build, 'two')
        self.p.set_fixture_decision(p, state='active', expected_version=0)
        return build, p

    def test_exact_bytes_and_nonauthority_flags_reopen(self):
        receipt = self.promote()
        self.assertEqual(receipt, self.p.current())
        for key in ('actual_signature_verified', 'actual_rights_cleared', 'authenticated', 'publication_eligible'):
            self.assertIs(receipt[key], False)
        for name, blob in [('manifest', self.build.manifest_bytes), ('catalog', self.build.catalog_bytes),
                           ('catalog_gzip', self.build.gzip_bytes), ('index', self.build.index_bytes)]:
            self.assertEqual(self.store.read_bytes(receipt['objects'][name]), blob)
        other = FixturePromoter(self.root + '/pointer', self.store)
        try:
            self.assertEqual(other.current(), receipt)
        finally:
            other.close()
        receipt['packet']['approvers'].clear()
        self.assertEqual(self.p.current()['packet']['approvers'], PEOPLE)

    def test_proof_gate_precedes_storage(self):
        for proof in (None, {}, {'protocol': 'signature', 'packet_sha256': '0' * 64},
                      dict(fixture_proof(self.packet), packet_sha256='0' * 64)):
            self.reject('invalid_fixture_proof', self.p.promote, self.build, self.packet, proof,
                        expected_revision=0, expected_sha256=None)
            self.assertEqual(self.store.inventory()['objects'], [])
            self.assertIsNone(self.p.current())

    def test_bundle_corruption_missing_wrong_size_and_flags(self):
        for field in ('catalog_bytes', 'gzip_bytes', 'index_bytes'):
            for blob in (b'', b'corrupted', bytearray(b'x')):
                bad = replace(self.build, **{field: blob})
                with self.assertRaises(PromotionError):
                    self.promote(bad)
        m = json.loads(self.build.manifest_bytes)
        for key, value in [('schema_version', 'unknown'), ('synthetic', False), ('authenticated', True),
                           ('publication_eligible', True), ('channel', 'public'), ('rights_cleared', True),
                           ('release_revision', True)]:
            bad = replace(self.build, manifest_bytes=json.dumps(dict(m, **{key: value})).encode())
            self.reject('invalid_manifest', fixture_packet, bad, self.packet['operation_id'], PEOPLE)
        for mutate in (lambda v: v['artifacts'].pop('index'),
                       lambda v: v['artifacts'].update(extra=v['artifacts']['index']),
                       lambda v: v['artifacts']['catalog'].update(size_bytes=1)):
            changed = copy.deepcopy(m)
            mutate(changed)
            with self.assertRaises(PromotionError):
                fixture_packet(replace(self.build, manifest_bytes=json.dumps(changed).encode()),
                               self.packet['operation_id'], PEOPLE)
        self.assertEqual(self.store.inventory()['objects'], [])

    def test_exact_manifest_bytes_and_packet_bindings(self):
        changed = replace(self.build, manifest_bytes=self.build.manifest_bytes + b'\n')
        self.reject('packet_binding_mismatch', self.promote, changed)
        for field, value in [('manifest_sha256', '0' * 64), ('records_sha256', '0' * 64),
                             ('release_revision', 2), ('release_id', 'urn:pya:synthetic:other')]:
            p = dict(self.packet, **{field: value})
            self.reject('packet_binding_mismatch', self.promote, p=p)
        p = dict(self.packet, approvers=['urn:pya:synthetic:other', PEOPLE[1]])
        self.reject('inactive_fixture_decision', self.promote, p=p)

    def test_duplicate_json_and_resource_types(self):
        m = self.build.manifest_bytes
        self.reject('duplicate_json_key', fixture_packet,
                    replace(self.build, manifest_bytes=b'{"synthetic":true,' + m[1:]),
                    self.packet['operation_id'], PEOPLE)
        for blob in (b'[' * 1500, b'\xff', b'{'):
            self.reject('invalid_json', fixture_packet, replace(self.build, manifest_bytes=blob),
                        self.packet['operation_id'], PEOPLE)
        self.reject('unsupported_object_size', fixture_packet,
                    replace(self.build, catalog_bytes=b'x' * (MAX_BYTES + 1)),
                    self.packet['operation_id'], PEOPLE)
        class Hostile(dict):
            def items(self):
                raise AssertionError('hook called')
        self.reject('plain_data_required', fixture_proof, Hostile(self.packet))
        class HostileBuild(BuildResult):
            pass
        self.reject('build_result_required', fixture_packet,
                    HostileBuild(b'', b'', b'', b''), self.packet['operation_id'], PEOPLE)
        cyclic = {}; cyclic['self'] = cyclic
        self.reject('metadata_limit', fixture_proof, cyclic)
        self.reject('invalid_integer', self.p.promote, self.build, self.packet, fixture_proof(self.packet),
                    expected_revision=True, expected_sha256=None)

    def test_exact_retry_and_obsolete_retry(self):
        first = self.promote()
        self.assertEqual(first, self.promote())
        build, p = self.next_release(first)
        second = self.promote(build, p, first)
        self.reject('obsolete_retry', self.promote)
        self.assertEqual(self.p.current(), second)
        self.assertEqual(len(self.p.history()), 2)

    def test_stale_cas_and_parent_mismatch(self):
        first = self.promote()
        build, p = self.next_release(first)
        self.reject('pointer_conflict', self.promote, build, p)
        wrong = bundle(2)
        wrong_p = packet(wrong, 'wrong')
        self.p.set_fixture_decision(wrong_p, state='active', expected_version=0)
        self.reject('parent_mismatch', self.promote, wrong, wrong_p, first)
        self.assertEqual(self.p.current(), first)

    def test_revocation_is_terminal_and_rechecked_after_staging(self):
        original = self.store.stage
        called = False
        def stage(*args):
            nonlocal called
            result = original(*args)
            if not called:
                called = True
                other = FixturePromoter(self.root + '/pointer', self.store)
                try:
                    other.set_fixture_decision(self.packet, state='revoked', expected_version=1)
                finally:
                    other.close()
            return result
        with patch.object(self.store, 'stage', stage):
            self.reject('inactive_fixture_decision', self.promote)
        self.assertIsNone(self.p.current())
        self.reject('decision_conflict', self.p.set_fixture_decision, self.packet,
                    state='active', expected_version=2)

    def test_revoked_current_refuses_reads_and_retries_retains_history(self):
        first = self.promote()
        self.p.set_fixture_decision(self.packet, state='revoked', expected_version=1)
        self.reject('inactive_fixture_decision', self.p.current)
        self.reject('inactive_fixture_decision', self.promote)
        self.assertEqual(self.p.history(), [first])

    def test_full_decision_history_keeps_terminal_revocation_available(self):
        first = self.promote()
        for version in range(1, MAX_HISTORY):
            self.p.set_fixture_decision(self.packet, state='active', expected_version=version)
        self.assertEqual(self.p.current(), first)
        self.reject('decision_capacity', self.p.set_fixture_decision, self.packet,
                    state='active', expected_version=MAX_HISTORY)
        self.reject('decision_conflict', self.p.set_fixture_decision, self.packet,
                    state='revoked', expected_version=MAX_HISTORY - 1)
        changed = dict(self.packet, approvers=['urn:pya:synthetic:other-a', PEOPLE[1]])
        self.reject('decision_conflict', self.p.set_fixture_decision, changed,
                    state='revoked', expected_version=MAX_HISTORY)
        result = self.p.set_fixture_decision(self.packet, state='revoked', expected_version=MAX_HISTORY)
        self.assertEqual(result['decision_version'], MAX_HISTORY + 1)
        self.reject('inactive_fixture_decision', self.p.current)
        self.reject('inactive_fixture_decision', self.promote)
        self.reject('decision_conflict', self.p.set_fixture_decision, self.packet,
                    state='active', expected_version=MAX_HISTORY + 1)
        self.assertEqual(self.p.history(), [first])
        other = FixturePromoter(self.root + '/pointer', self.store)
        try:
            self.reject('inactive_fixture_decision', other.current)
        finally:
            other.close()

    def test_all_admitted_manifests_can_revoke_with_bounded_terminal_history(self):
        packets = [self.packet]
        for n in range(1, MAX_HISTORY):
            p = dict(self.packet, manifest_sha256=hashlib.sha256(str(n).encode()).hexdigest(),
                     operation_id='urn:pya:synthetic:capacity-' + str(n))
            packets.append(p)
            self.p.set_fixture_decision(p, state='active', expected_version=0)
        extra = dict(self.packet, manifest_sha256='0' * 64)
        for state in ('active', 'revoked'):
            self.reject('decision_capacity', self.p.set_fixture_decision, extra,
                        state=state, expected_version=0)
        for p in packets:
            self.p.set_fixture_decision(p, state='revoked', expected_version=1)
            self.reject('decision_conflict', self.p.set_fixture_decision, p,
                        state='revoked', expected_version=2)
        with sqlite3.connect(self.root + '/pointer/promotion.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0],
                             2 * MAX_HISTORY)
        for state in ('active', 'revoked'):
            self.reject('decision_capacity', self.p.set_fixture_decision, extra,
                        state=state, expected_version=0)

    def test_parser_errors_retain_no_decoding_exception_context(self):
        marker = b'benign-synthetic-parser-marker'
        for blob in (b'{"marker":"' + marker + b'",', b'"' + marker + bytes([255]) + b'"'):
            bad = replace(self.build, manifest_bytes=blob)
            with self.assertRaises(PromotionError) as raised:
                fixture_packet(bad, self.packet['operation_id'], PEOPLE)
            error = raised.exception
            self.assertEqual(str(error), 'invalid_json')
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
            self.assertNotIn(marker.decode(), str(error))

    def test_real_stored_corruption_and_missing_object(self):
        first = self.promote()
        location = Path(self.root) / 'store/synthetic_public_artifact/objects' / first['objects']['index']['sha256']
        original = location.read_bytes()
        for missing in (False, True):
            if missing:
                location.unlink()
            else:
                location.write_bytes(b'bad bytes')
            self.reject('store_verification_failed', self.p.current)
            with self.assertRaises(PromotionError):
                self.promote()
            location.write_bytes(original)
            self.assertEqual(self.p.current(), first)

    def test_partial_stage_and_sqlite_abort_keep_prior_pointer(self):
        first = self.promote()
        build, p = self.next_release(first)
        original = self.store.stage
        count = 0
        def stage(*args):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('synthetic interruption')
            return original(*args)
        with patch.object(self.store, 'stage', stage):
            with self.assertRaises(OSError):
                self.promote(build, p, first)
        self.assertEqual(self.p.current(), first)
        db = sqlite3.connect(self.root + '/pointer/promotion.sqlite')
        db.execute("CREATE TRIGGER abort_pointer BEFORE UPDATE ON pointer BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        db.commit(); db.close()
        self.reject('promotion_unavailable', self.promote, build, p, first)
        self.assertEqual(self.p.current(), first)
        self.assertEqual(self.p.history(), [first])

    def test_real_two_connection_race_one_commit(self):
        first = self.promote()
        a, pa = self.next_release(first)
        b = bundle(3, parent(first)); pb = packet(b, 'three')
        self.p.set_fixture_decision(pb, state='active', expected_version=0)
        barrier = threading.Barrier(2)
        outcomes = []
        def worker(build, p):
            store = FixtureStore(self.root + '/store', 'synthetic_public_artifact')
            promoter = FixturePromoter(self.root + '/pointer', store)
            try:
                barrier.wait(timeout=5)
                outcomes.append(promoter.promote(build, p, fixture_proof(p),
                    expected_revision=1, expected_sha256=first['manifest_sha256']))
            except PromotionError as error:
                outcomes.append(str(error))
            finally:
                promoter.close(); store.close()
        threads = [threading.Thread(target=worker, args=args) for args in [(a, pa), (b, pb)]]
        for t in threads: t.start()
        for t in threads: t.join(10); self.assertFalse(t.is_alive())
        self.assertEqual(len([x for x in outcomes if type(x) is dict]), 1)
        self.assertIn('pointer_conflict', outcomes)
        self.assertEqual(self.p.current()['revision'], 2)

    def test_packet_detached_before_real_lock_wait(self):
        ready = threading.Event(); waiting = threading.Event(); done = []
        p = copy.deepcopy(self.packet); proof = fixture_proof(p)
        def worker():
            store = FixtureStore(self.root + '/store', 'synthetic_public_artifact')
            promoter = FixturePromoter(self.root + '/pointer', store)
            promoter._db.set_trace_callback(lambda sql: waiting.set() if sql == 'BEGIN IMMEDIATE' else None)
            ready.set(); start.wait(5)
            try:
                done.append(promoter.promote(self.build, p, proof, expected_revision=0, expected_sha256=None))
            finally:
                promoter.close(); store.close()
        start = threading.Event()
        t = threading.Thread(target=worker); t.start(); self.assertTrue(ready.wait(5))
        db = sqlite3.connect(self.root + '/pointer/promotion.sqlite', isolation_level=None)
        db.execute('BEGIN IMMEDIATE'); start.set(); self.assertTrue(waiting.wait(5))
        p['approvers'].clear(); proof['packet_sha256'] = '0' * 64
        db.execute('COMMIT'); db.close(); t.join(10)
        self.assertFalse(t.is_alive()); self.assertEqual(done[0]['packet'], self.packet)

    def test_process_exit_before_and_after_pointer_commit(self):
        first = self.promote()
        build, p = self.next_release(first)
        code = '''
import os, sys
from tests.publication.promotion.test_promote import bundle, packet, parent
from src.publication.promote import FixturePromoter, fixture_proof
from src.storage import FixtureStore
root, phase = sys.argv[1:]
s = FixtureStore(root + '/store', 'synthetic_public_artifact')
p = FixturePromoter(root + '/pointer', s)
first = p.current(); b = bundle(2, parent(first)); q = packet(b, 'two')
if phase == 'before':
    original = s.stage
    def stage(*args):
        original(*args)
        os._exit(23)
    s.stage = stage
p.promote(b, q, fixture_proof(q), expected_revision=1, expected_sha256=first['manifest_sha256'])
os._exit(24)
'''
        for phase, exitcode in [('before', 23), ('after', 24)]:
            run = subprocess.run([sys.executable, '-c', code, self.root, phase],
                                 cwd=ROOT, capture_output=True, timeout=15)
            self.assertEqual(run.returncode, exitcode, run.stderr)
            self.assertEqual(self.p.current()['revision'], 1 if phase == 'before' else 2)
        self.assertEqual(self.promote(build, p, first), self.p.current())

    def test_cross_role_ids_changed_operation_and_fixed_diagnostics(self):
        for identity in (self.packet['release_id'], PEOPLE[0]):
            self.reject('identity_role_conflict', fixture_packet, self.build, identity, PEOPLE)
        m = json.loads(self.build.manifest_bytes)
        m['records'][0]['rights']['id'] = m['release_id']
        bad = replace(self.build, manifest_bytes=json.dumps(m).encode())
        self.reject('identity_role_conflict', fixture_packet, bad, self.packet['operation_id'], PEOPLE)
        first = self.promote()
        b, p = self.next_release(first)
        p['operation_id'] = self.packet['operation_id']
        # The existing decision binds another operation: this is rejected before storage.
        self.reject('inactive_fixture_decision', self.promote, b, p, first)
        self.reject('operation_conflict', self.p.promote, self.build, self.packet,
                    fixture_proof(self.packet), expected_revision=1,
                    expected_sha256=first['manifest_sha256'])
        self.reject('invalid_packet', fixture_proof, dict(self.packet, secret='never reflect this'))
        self.assertEqual(self.p.current(), first)

    def test_bounded_decisions_and_objects(self):
        # Exercise the actual 64-row decision limit without relaxing constants.
        for version in range(1, 64):
            self.p.set_fixture_decision(self.packet, state='active', expected_version=version)
        self.reject('decision_capacity', self.p.set_fixture_decision, self.packet,
                    state='active', expected_version=64)
        for n in range(64):
            blob = str(n).encode(); self.store.stage(blob, hashlib.sha256(blob).hexdigest())
        self.reject('store_staging_failed', self.promote)
        self.assertIsNone(self.p.current())


if __name__ == '__main__':
    unittest.main()
