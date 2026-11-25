"""Private, bounded synthetic promotion rehearsal. No signing authority."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from jsonschema import Draft202012Validator
from src.publication.build.decoded_v01 import BuildResult
from src.storage import FixtureStore, StorageError

MAX_BYTES = 65536
MAX_HISTORY = 64
PACKET_VERSION = "synthetic-promotion-packet-0.1"
PROOF_VERSION = "NONAUTHORITATIVE-fixture-checksum-0.1"
STATUS = dict(synthetic=True, actual_signature_verified=False,
              actual_rights_cleared=False, authenticated=False, publication_eligible=False)
_SCHEMA = json.loads((Path(__file__).resolve().parents[3] /
                      'schemas/release-manifest.schema.json').read_text())


class PromotionError(ValueError):
    """Fixed diagnostics; exception frames are not sanitized."""


def _require(ok, code):
    if not ok:
        raise PromotionError(code) from None


def _encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _id(value):
    _require(type(value) is str and len(value) <= 160 and
             re.fullmatch(r'urn:pya:synthetic:[a-z0-9][a-z0-9:._-]*', value), 'invalid_identity')


def _digest(value):
    _require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid_digest')


def _int(value, low=0, high=1000000):
    _require(type(value) is int and low <= value <= high, 'invalid_integer')


def _capture(value):
    """Bound and detach plain caller values before any IO or lock wait."""
    nodes = 0
    budget = 0
    active = set()

    def visit(item, depth):
        nonlocal nodes, budget
        nodes += 1
        _require(nodes <= 4096 and depth <= 24, 'metadata_limit')
        kind = type(item)
        budget += 8
        _require(budget <= MAX_BYTES, 'metadata_limit')
        _require(any(kind is t for t in (dict, list, str, int, bool, type(None))), 'plain_data_required')
        if kind is dict or kind is list:
            _require(len(item) <= 128 and id(item) not in active, 'metadata_limit')
            active.add(id(item))
            if kind is dict:
                result = {}
                for key, child in item.items():
                    _require(type(key) is str, 'plain_data_required')
                    result[visit(key, depth + 1)] = visit(child, depth + 1)
            else:
                result = [visit(child, depth + 1) for child in item]
            active.remove(id(item))
            return result
        if kind is str:
            budget += len(item) * 4
            _require(budget <= MAX_BYTES, 'metadata_limit')
            _require(len(item) <= 4096 and all(32 <= ord(c) and not 127 <= ord(c) <= 159
                     and not 0xD800 <= ord(c) <= 0xDFFF for c in item), 'invalid_string')
        if kind is int:
            _int(item, 0, 1000000000)
        return item

    try:
        result = visit(value, 0)
    except RuntimeError:
        raise PromotionError('metadata_limit') from None
    _require(len(_encode(result)) <= MAX_BYTES, 'metadata_limit')
    return result


def _json(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result
    try:
        return _capture(json.loads(blob, object_pairs_hook=pairs))
    except (ValueError, RecursionError, UnicodeError) as error:
        if isinstance(error, PromotionError):
            raise
        code = 'invalid_json'
    raise PromotionError(code) from None


def _bundle(build):
    _require(type(build) is BuildResult, 'build_result_required')
    objects = dict(catalog=build.catalog_bytes, catalog_gzip=build.gzip_bytes,
                   index=build.index_bytes, manifest=build.manifest_bytes)
    _require(all(type(b) is bytes for b in objects.values()), 'exact_bytes_required')
    _require(all(0 < len(b) <= MAX_BYTES for b in objects.values()), 'unsupported_object_size')
    manifest = _json(objects['manifest'])
    _require(Draft202012Validator(_SCHEMA).is_valid(manifest), 'invalid_manifest')
    _require(type(manifest['release_revision']) is int, 'invalid_manifest')
    for name in ('catalog', 'catalog_gzip', 'index'):
        item = manifest['artifacts'][name]
        _require(type(item['size_bytes']) is int and item['size_bytes'] == len(objects[name])
                 and item['sha256'] == _hash(objects[name]), 'artifact_mismatch')
    pins = {manifest['release_id']: ('release',)}
    if manifest['parent_release'] is not None:
        pins[manifest['parent_release']['id']] = ('release',)
    for entry in manifest['records']:
        for role in ('candidate', 'record', 'review', 'evidence', 'packet', 'rights'):
            pin = entry[role]
            _require(type(pin['revision']) is int, 'invalid_manifest')
            binding = (role, pin['revision'], pin.get('sha256'))
            if role in ('candidate', 'record', 'review'):
                _require(pin['id'] not in pins, 'identity_role_conflict')
            _require(pins.setdefault(pin['id'], binding) == binding, 'identity_role_conflict')
        for notice in entry['notices']:
            binding = ('notice', _hash(_encode(notice)))
            _require(pins.setdefault(notice['id'], binding) == binding, 'identity_role_conflict')
        _require(entry['notices_sha256'] == _hash(_encode(entry['notices'])), 'notice_binding_mismatch')
    # Bytes and all source/review/rights pins are bound by the manifest. This is
    # not a rebuild or a source truth check; the pinned builder owns semantics.
    return objects, manifest


def _packet(value):
    packet = _capture(value)
    _require(type(packet) is dict and packet.keys() == {
        'schema_version', 'operation_id', 'channel', 'manifest_sha256', 'release_id',
        'release_revision', 'parent_release', 'records_sha256', 'approvers'}, 'invalid_packet')
    _require(packet['schema_version'] == PACKET_VERSION and packet['channel'] == 'synthetic',
             'invalid_packet')
    for key in ('operation_id', 'release_id'):
        _id(packet[key])
    for key in ('manifest_sha256', 'records_sha256'):
        _digest(packet[key])
    _int(packet['release_revision'], 1)
    parent = packet['parent_release']
    if parent is not None:
        _require(type(parent) is dict and parent.keys() == {'id', 'revision', 'sha256'}, 'invalid_parent')
        _id(parent['id'])
        _int(parent['revision'], 1)
        _digest(parent['sha256'])
    people = packet['approvers']
    _require(type(people) is list and 2 <= len(people) <= 4, 'invalid_approvers')
    for person in people:
        _id(person)
    _require(len(set(people)) == len(people), 'invalid_approvers')
    return packet


def fixture_packet(build, operation_id, approvers):
    """Create a caller-asserted packet, never an approval or signing packet."""
    _, m = _bundle(build)
    result = _packet(dict(schema_version=PACKET_VERSION, operation_id=operation_id,
        channel='synthetic', manifest_sha256=build.manifest_sha256,
        release_id=m['release_id'], release_revision=m['release_revision'],
        parent_release=m['parent_release'], records_sha256=_hash(_encode(m['records'])),
        approvers=approvers))
    identities = {m['release_id']}
    if m['parent_release']:
        identities.add(m['parent_release']['id'])
    for entry in m['records']:
        identities.update(entry[role]['id'] for role in ('candidate', 'record', 'review', 'evidence', 'packet', 'rights'))
        identities.update(notice['id'] for notice in entry['notices'])
    for identity in [result['operation_id'], *result['approvers']]:
        _require(identity not in identities, 'identity_role_conflict')
        identities.add(identity)
    return result


def fixture_proof(packet):
    """Publicly reproducible test checksum; no secret, signature or authentication."""
    return {'protocol': PROOF_VERSION, 'packet_sha256': _hash(_encode(_packet(packet)))}


class FixturePromoter:
    """One connection per worker, trusted private temporary root and FixtureStore.

    Stores remain independent. Orphaned objects/references can survive a failed
    pointer commit. No filesystem owner adversary or power-loss guarantee.
    """

    def __init__(self, root, store):
        _require(type(root) is str and 0 < len(root) <= 4096 and '\x00' not in root,
                 'invalid_configuration')
        _require(type(store) is FixtureStore and store.storage_class == 'synthetic_public_artifact',
                 'invalid_store')
        self.store = store
        self._db = None
        try:
            Path(root).mkdir(parents=True, exist_ok=True, mode=0o700)
            self._db = sqlite3.connect(str(Path(root) / 'promotion.sqlite'), timeout=1, isolation_level=None)
            self._db.execute('PRAGMA synchronous=FULL')
            self._db.executescript('''
                CREATE TABLE IF NOT EXISTS decisions (
                    digest TEXT, version INTEGER, packet BLOB, state TEXT,
                    PRIMARY KEY(digest, version));
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY, request BLOB, receipt BLOB);
                CREATE TABLE IF NOT EXISTS pointer (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1), receipt BLOB);
            ''')
        except (OSError, sqlite3.Error):
            if self._db:
                self._db.close()
            raise PromotionError('promotion_unavailable') from None

    def close(self):
        self._db.close()

    @contextmanager
    def _transaction(self):
        try:
            self._db.execute('BEGIN IMMEDIATE')
            try:
                yield
                self._db.execute('COMMIT')
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute('ROLLBACK')
                raise
        except (sqlite3.Error, OSError):
            raise PromotionError('promotion_unavailable') from None

    def _decision(self, packet):
        row = self._db.execute('SELECT version,packet,state FROM decisions WHERE digest=? '
                               'ORDER BY version DESC LIMIT 1', (packet['manifest_sha256'],)).fetchone()
        _require(row is not None and row[1] == _encode(packet) and row[2] == 'active',
                 'inactive_fixture_decision')
        return row[0]

    def set_fixture_decision(self, packet, *, state, expected_version):
        """Append an unauthenticated local aggregate source/review/rights decision.

        Revocation is terminal. It blocks retries and reads, but does not erase
        pointer history or select a fallback release. Each ordinary admission
        reserves one terminal revocation, including when history is full.
        No real source is queried.
        """
        packet = _packet(packet)
        _require(type(state) is str and state in ('active', 'revoked'), 'invalid_state')
        _int(expected_version)
        encoded = _encode(packet)
        with self._transaction():
            row = self._db.execute('SELECT version,packet,state FROM decisions WHERE digest=? '
                                  'ORDER BY version DESC LIMIT 1', (packet['manifest_sha256'],)).fetchone()
            _require((row[0] if row else 0) == expected_version, 'decision_conflict')
            _require(row is None or (row[1] == encoded and row[2] != 'revoked'), 'decision_conflict')
            # Ordinary updates and initially revoked manifests consume the
            # bounded admission budget. A previously active manifest retains
            # its one terminal slot even after that budget fills. Terminal
            # rows cannot be updated: at most 2 * MAX_HISTORY rows can exist.
            if state != 'revoked' or row is None:
                used = self._db.execute(
                    "SELECT COUNT(*) FROM decisions WHERE state='active' OR version=1"
                ).fetchone()[0]
                _require(used < MAX_HISTORY, 'decision_capacity')
            self._db.execute('INSERT INTO decisions VALUES(?,?,?,?)',
                             (packet['manifest_sha256'], expected_version + 1, encoded, state))
            return dict(STATUS, decision_version=expected_version + 1, state=state)

    def _current(self):
        row = self._db.execute('SELECT receipt FROM pointer WHERE singleton=1').fetchone()
        return _json(row[0]) if row else None

    def _verify_objects(self, receipt):
        try:
            for item in receipt['objects'].values():
                blob = self.store.read_bytes(item)
                _require(_hash(blob) == item['sha256'] and len(blob) == item['size'], 'stored_object_mismatch')
        except StorageError:
            raise PromotionError('store_verification_failed') from None

    def current(self):
        """Read current only after local decision and all stored bytes revalidate."""
        with self._transaction():
            receipt = self._current()
            if receipt:
                self._decision(receipt['packet'])
                self._verify_objects(receipt)
            return receipt

    def history(self):
        """Detached historical receipts; NOT current eligibility or byte verification."""
        with self._transaction():
            return [_json(row[0]) for row in self._db.execute('SELECT receipt FROM operations ORDER BY rowid')]

    def promote(self, build, packet, proof, *, expected_revision, expected_sha256):
        objects, manifest = _bundle(build)
        packet = _packet(packet)
        proof = _capture(proof)
        _int(expected_revision)
        if expected_sha256 is not None:
            _digest(expected_sha256)
        _require((expected_revision == 0) == (expected_sha256 is None), 'invalid_expectation')
        _require(packet == fixture_packet(build, packet['operation_id'], packet['approvers']), 'packet_binding_mismatch')
        _require(proof == fixture_proof(packet), 'invalid_fixture_proof')
        request = _encode(dict(packet=packet, proof=proof, expected_revision=expected_revision,
                               expected_sha256=expected_sha256))
        # Early refusal prevents staging rejected/revoked packets. Recheck after
        # staging because decisions can change while independent stores commit.
        with self._transaction():
            self._decision(packet)
            old = self._db.execute('SELECT request,receipt FROM operations WHERE id=?',
                                   (packet['operation_id'],)).fetchone()
            if old:
                _require(old[0] == request, 'operation_conflict')
                receipt = _json(old[1])
                _require(self._current() == receipt, 'obsolete_retry')
                self._verify_objects(receipt)
                return receipt
        metadata = {}
        try:
            for name, blob in objects.items():
                digest = _hash(blob)
                item = dict(synthetic=True, publication_eligible=False,
                    candidate_id='urn:pya:synthetic:promotion-object:' + digest,
                    revision=1, source_revision=packet['manifest_sha256'],
                    storage_class='synthetic_public_artifact', sha256=digest, size=len(blob))
                # Equal artifact bytes can belong to several manifests; bind the
                # immutable object reference to its own exact-byte source identity.
                item['source_revision'] = digest
                self.store.stage(blob, digest)
                self.store.reference(item, expected_revision=0)
                metadata[name] = item
        except StorageError:
            raise PromotionError('store_staging_failed') from None
        with self._transaction():
            version = self._decision(packet)
            old = self._db.execute('SELECT request,receipt FROM operations WHERE id=?',
                                   (packet['operation_id'],)).fetchone()
            current = self._current()
            if old:
                _require(old[0] == request, 'operation_conflict')
                receipt = _json(old[1])
                _require(current == receipt, 'obsolete_retry')
                self._verify_objects(receipt)
                return receipt
            _require(current is None or current['manifest_sha256'] != packet['manifest_sha256'],
                     'duplicate_release')
            _require((current['revision'] if current else 0) == expected_revision and
                     (current['manifest_sha256'] if current else None) == expected_sha256, 'pointer_conflict')
            parent = None if current is None else dict(id=current['release_id'],
                revision=current['release_revision'], sha256=current['manifest_sha256'])
            _require(manifest['parent_release'] == parent, 'parent_mismatch')
            if current and current['release_id'] == packet['release_id']:
                _require(packet['release_revision'] > current['release_revision'], 'obsolete_release')
            _require(self._db.execute('SELECT COUNT(*) FROM operations').fetchone()[0] < MAX_HISTORY,
                     'operation_capacity')
            # Prevent any new operation from republishing a historical manifest.
            for row in self._db.execute('SELECT receipt FROM operations'):
                historical = _json(row[0])
                _require(historical['manifest_sha256'] != packet['manifest_sha256'], 'obsolete_release')
                if historical['release_id'] == packet['release_id']:
                    _require(packet['release_revision'] > historical['release_revision'], 'obsolete_release')
            receipt = dict(STATUS, channel='synthetic', revision=expected_revision + 1,
                release_id=packet['release_id'], release_revision=packet['release_revision'],
                manifest_sha256=packet['manifest_sha256'], operation_id=packet['operation_id'],
                decision_version=version, packet=packet, fixture_proof=proof, objects=metadata,
                evidence_level='synthetic_local_promotion_rehearsal')
            self._verify_objects(receipt)
            encoded = _encode(receipt)
            self._db.execute('INSERT INTO operations VALUES(?,?,?)', (packet['operation_id'], request, encoded))
            self._db.execute('INSERT INTO pointer VALUES(1,?) ON CONFLICT(singleton) '
                             'DO UPDATE SET receipt=excluded.receipt', (encoded,))
            return receipt
