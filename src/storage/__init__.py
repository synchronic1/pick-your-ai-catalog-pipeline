"""Bounded local fixture storage, never canonical PostgreSQL/service authority.

Only synthetic caller assertions are admitted. No dispatch, credentials, source
policy, deletion API, or authenticated canonical import is implemented here.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile

MAX_BYTES = 65536
MAX_OBJECTS = 64
MAX_REFERENCES = 64
CLASSES = frozenset({"synthetic_restricted_observation", "synthetic_public_artifact"})
_FIELDS = {"synthetic", "publication_eligible", "candidate_id", "revision",
           "source_revision", "storage_class", "sha256", "size"}


class StorageError(ValueError):
    """Fixed diagnostic without caller content or local paths."""


def _fail(code):
    raise StorageError(code) from None


def _text(value, pattern, limit=160):
    if type(value) is not str or len(value) > limit or re.fullmatch(pattern, value) is None:
        _fail("invalid_metadata")


def _identity(value):
    _text(value, r"urn:pya:synthetic:[a-z0-9][a-z0-9:._-]*")


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("invalid_metadata")


def _capture(value):
    # Flat bounded plain metadata: do not deepcopy/serialize caller objects.
    if type(value) is not dict or len(value) != len(_FIELDS):
        _fail("invalid_metadata")
    result = {}
    try:
        for index, (key, child) in enumerate(value.items()):
            if index >= len(_FIELDS) or type(key) is not str or len(key) > 32:
                _fail("invalid_metadata")
            if type(child) is str:
                if len(child) > 160:
                    _fail("invalid_metadata")
            elif type(child) is int:
                _integer(child, 0, 1000000)
            elif type(child) is not bool:
                _fail("invalid_metadata")
            result[key] = child
    except RuntimeError:
        _fail("invalid_metadata")
    if result.keys() != _FIELDS:
        _fail("invalid_metadata")
    if result["synthetic"] is not True or result["publication_eligible"] is not False:
        _fail("synthetic_boundary")
    _identity(result["candidate_id"])
    _integer(result["revision"], 1, 1000000)
    _integer(result["size"], 0, MAX_BYTES)
    _text(result["source_revision"], r"[0-9a-f]{40}|[0-9a-f]{64}", 64)
    _text(result["sha256"], r"[0-9a-f]{64}", 64)
    if type(result["storage_class"]) is not str or result["storage_class"] not in CLASSES:
        _fail("invalid_metadata")
    return result


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class FixtureStore:
    """Use only a caller-owned temporary directory and synthetic material.

    Each class has its own database and byte directory. The local filesystem and
    database are trusted test infrastructure, not an adversarial multi-user host.
    Each connection stays on its creating thread; use one instance per worker.
    """

    def __init__(self, root, storage_class):
        if type(root) is not str or not root or len(root) > 4096 or "\x00" in root:
            _fail("invalid_configuration")
        if type(storage_class) is not str or storage_class not in CLASSES:
            _fail("invalid_configuration")
        self.storage_class = storage_class
        self._root = Path(root) / storage_class
        self._objects = self._root / "objects"
        self._db = None
        try:
            self._objects.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._db = sqlite3.connect(str(self._root / "metadata.sqlite"),
                                       timeout=1, isolation_level=None)
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS candidates (
                    id TEXT, revision INTEGER, metadata TEXT NOT NULL,
                    PRIMARY KEY(id, revision));
                CREATE TABLE IF NOT EXISTS heads (id TEXT PRIMARY KEY, revision INTEGER);
                CREATE TABLE IF NOT EXISTS receipts (
                    id TEXT UNIQUE NOT NULL, candidate TEXT, revision INTEGER,
                    version INTEGER NOT NULL CHECK(version=1),
                    PRIMARY KEY(candidate, revision),
                    FOREIGN KEY(candidate, revision) REFERENCES candidates(id, revision));
            """)
        except (OSError, sqlite3.Error):
            if self._db is not None:
                self._db.close()
            raise StorageError("storage_unavailable") from None

    def close(self):
        self._db.close()

    @contextmanager
    def _transaction(self):
        try:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise
        except (OSError, sqlite3.Error):
            raise StorageError("storage_unavailable") from None

    def _metadata(self, metadata):
        captured = _capture(metadata)
        if captured["storage_class"] != self.storage_class:
            _fail("class_mismatch")
        return captured

    def _entries(self):
        entries = []
        with os.scandir(self._objects) as scan:
            for entry in scan:
                # A crash between link and unlink can leave one extra entry.
                if len(entries) >= MAX_OBJECTS + 1:
                    _fail("object_capacity")
                entries.append(entry.name)
        return entries

    def _read(self, digest):
        try:
            fd = os.open(self._objects / digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            _fail("missing_object")
        except OSError:
            _fail("corrupt_object")
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                _fail("corrupt_object")
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != digest:
            _fail("corrupt_object")
        return data

    def _sync_directory(self):
        fd = os.open(self._objects, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def stage(self, data, sha256):
        """Stage original immutable bytes first; no reference or receipt implied.

        Exact bytes only, bounded before hashing/waiting. Interrupted writes can
        leave a partial object, or a complete orphan; inventory never deletes it.
        """
        if type(data) is not bytes or len(data) > MAX_BYTES:
            _fail("invalid_bytes")
        _text(sha256, r"[0-9a-f]{64}", 64)
        if hashlib.sha256(data).hexdigest() != sha256:
            _fail("hash_mismatch")
        with self._transaction():
            entries = self._entries()
            if sha256 in entries:
                if self._read(sha256) != data:
                    _fail("corrupt_object")
                return {"synthetic": True, "publication_eligible": False,
                        "sha256": sha256, "size": len(data), "storage_class": self.storage_class}
            if len(entries) >= MAX_OBJECTS:
                _fail("object_capacity")
            # Publish a complete file exclusively; never overwrite an identity.
            fd, temporary = tempfile.mkstemp(prefix=".partial-", dir=self._objects)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.link(temporary, self._objects / sha256)
            self._sync_directory()
            os.unlink(temporary)
            self._sync_directory()
        return {"synthetic": True, "publication_eligible": False,
                "sha256": sha256, "size": len(data), "storage_class": self.storage_class}

    def _verify(self, metadata):
        data = self._read(metadata["sha256"])
        if len(data) != metadata["size"]:
            _fail("size_mismatch")
        return data

    def _existing(self, metadata):
        row = self._db.execute("SELECT metadata FROM candidates WHERE id=? AND revision=?",
                               (metadata["candidate_id"], metadata["revision"])).fetchone()
        if row is None:
            _fail("missing_reference")
        if row[0] != _encoded(metadata):
            _fail("identity_conflict")

    def reference(self, metadata, *, expected_revision):
        """Commit a local candidate revision after verifying its staged bytes.

        Exact historical retries are idempotent and never move the head backward.
        expected_revision pins the previous head; revisions advance one at a time.
        """
        metadata = self._metadata(metadata)
        _integer(expected_revision, 0, 999999)
        if metadata["revision"] != expected_revision + 1:
            _fail("revision_mismatch")
        encoded = _encoded(metadata)
        with self._transaction():
            self._verify(metadata)
            old = self._db.execute("SELECT metadata FROM candidates WHERE id=? AND revision=?",
                                   (metadata["candidate_id"], metadata["revision"])).fetchone()
            if old:
                if old[0] != encoded:
                    _fail("identity_conflict")
                return self._snapshot(metadata)
            head = self._db.execute("SELECT revision FROM heads WHERE id=?",
                                    (metadata["candidate_id"],)).fetchone()
            if (head[0] if head else 0) != expected_revision:
                _fail("revision_conflict")
            if self._db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0] >= MAX_REFERENCES:
                _fail("reference_capacity")
            self._db.execute("INSERT INTO candidates VALUES(?,?,?)",
                             (metadata["candidate_id"], metadata["revision"], encoded))
            self._db.execute("INSERT INTO heads VALUES(?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision",
                             (metadata["candidate_id"], metadata["revision"]))
            return self._snapshot(metadata)

    def record_fixture_receipt(self, metadata, receipt_id, *, expected_version):
        """Record a local assertion only; no canonical import is authenticated.

        One immutable version-1 receipt per exact candidate revision. CAS expects
        version zero. An exact retry with that same expectation returns history.
        """
        metadata = self._metadata(metadata)
        _identity(receipt_id)
        _integer(expected_version, 0, 1)
        if self.storage_class != "synthetic_public_artifact":
            _fail("handoff_class_denied")
        with self._transaction():
            self._existing(metadata)
            self._verify(metadata)
            old = self._db.execute("SELECT id FROM receipts WHERE candidate=? AND revision=?",
                                   (metadata["candidate_id"], metadata["revision"])).fetchone()
            if expected_version != 0 or (old and old[0] != receipt_id):
                _fail("receipt_conflict")
            if not old:
                if self._db.execute("SELECT 1 FROM receipts WHERE id=?", (receipt_id,)).fetchone():
                    _fail("receipt_conflict")
                self._db.execute("INSERT INTO receipts VALUES(?,?,?,1)",
                                 (receipt_id, metadata["candidate_id"], metadata["revision"]))
            return self._snapshot(metadata)

    def _snapshot(self, metadata):
        row = self._db.execute("SELECT id,version FROM receipts WHERE candidate=? AND revision=?",
                               (metadata["candidate_id"], metadata["revision"])).fetchone()
        head = self._db.execute("SELECT revision FROM heads WHERE id=?",
                                (metadata["candidate_id"],)).fetchone()[0]
        return {**metadata, "head_revision": head,
                "state": "local_receipt_asserted" if row else "referenced",
                "receipt_id": row[0] if row else None, "receipt_version": row[1] if row else 0,
                "canonical_import_authenticated": False, "rights_cleared": False,
                "evidence_level": "synthetic_local_storage_rehearsal"}

    def snapshot(self, metadata):
        metadata = self._metadata(metadata)
        with self._transaction():
            self._existing(metadata)
            self._verify(metadata)
            return self._snapshot(metadata)

    def snapshot_metadata(self, metadata):
        """Read an exact existing reference/head without asserting byte custody.

        Metadata-only withdrawal checks can use this while historical raw bytes
        are unavailable. Ordinary snapshot/read operations still verify bytes.
        """
        metadata = self._metadata(metadata)
        with self._transaction():
            self._existing(metadata)
            return {**self._snapshot(metadata), "content_verified": False,
                    "evidence_level": "synthetic_local_metadata_rehearsal"}

    def read_bytes(self, metadata):
        metadata = self._metadata(metadata)
        with self._transaction():
            self._existing(metadata)
            return self._verify(metadata)

    def inventory(self):
        """Bounded integrity report; no repair, garbage collection or deletion.

        Metadata database corruption is an error; this is not a tamper-proof log.
        Unexpected filenames are never reflected in diagnostics or output.
        """
        with self._transaction():
            entries = self._entries()
            rows = self._db.execute("SELECT metadata FROM candidates LIMIT ?",
                                    (MAX_REFERENCES + 1,)).fetchall()
            if len(rows) > MAX_REFERENCES:
                _fail("reference_capacity")
            references = {}
            for row in rows:
                try:
                    if len(row[0]) > 2048:
                        _fail("corrupt_metadata")
                    metadata = self._metadata(json.loads(row[0]))
                except (ValueError, TypeError):
                    raise StorageError("corrupt_metadata") from None
                references.setdefault(metadata["sha256"], set()).add(metadata["size"])
            result = []
            digests = set(references)
            for entry in entries:
                if re.fullmatch(r"[0-9a-f]{64}", entry):
                    digests.add(entry)
                else:
                    result.append({"state": "partial" if entry.startswith(".partial-") else "unexpected"})
            for digest in sorted(digests):
                try:
                    data = self._read(digest)
                    state = "referenced" if digest in references else "orphan"
                    if digest in references and references[digest] != {len(data)}:
                        state = "size_mismatch"
                except StorageError as error:
                    state = str(error)
                result.append({"sha256": digest, "state": state})
            return {"synthetic": True, "publication_eligible": False,
                    "canonical_import_authenticated": False, "storage_class": self.storage_class,
                    "objects": result}
