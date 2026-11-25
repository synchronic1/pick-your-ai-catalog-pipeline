"""Synthetic fixtures on real local files and SQLite; no canonical service."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import traceback
import unittest
from unittest.mock import patch

from src.storage import FixtureStore, StorageError, MAX_BYTES, MAX_OBJECTS, MAX_REFERENCES

PUBLIC = "synthetic_public_artifact"
RESTRICTED = "synthetic_restricted_observation"
BODY = b'  { "synthetic": true, "value": "1.00" }\r\n\n'


def metadata(data=BODY, revision=1, name="candidate", storage_class=PUBLIC):
    return {"synthetic": True, "publication_eligible": False,
            "candidate_id": "urn:pya:synthetic:" + name, "revision": revision,
            "source_revision": "a" * 40, "storage_class": storage_class,
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = self.temporary.name
        self.store = FixtureStore(self.root, PUBLIC)
        self.meta = metadata()

    def tearDown(self):
        self.store.close()
        self.temporary.cleanup()

    def staged(self, data=BODY, meta=None):
        meta = metadata(data) if meta is None else meta
        self.store.stage(data, meta["sha256"])
        return meta

    def referenced(self, data=BODY, meta=None):
        meta = self.staged(data, meta)
        self.store.reference(meta, expected_revision=meta["revision"] - 1)
        return meta

    def object_path(self, digest=None):
        return Path(self.root) / PUBLIC / "objects" / (digest or self.meta["sha256"])

    def database(self):
        return sqlite3.connect(str(Path(self.root) / PUBLIC / "metadata.sqlite"), isolation_level=None)

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaisesRegex(StorageError, "^" + code + "$"):
            function(*args, **kwargs)

    def test_exact_bytes_whitespace_and_restart(self):
        self.referenced()
        self.store.close()
        self.store = FixtureStore(self.root, PUBLIC)
        self.assertEqual(self.store.read_bytes(self.meta), BODY)
        self.assertEqual(self.store.reference(self.meta, expected_revision=0)["head_revision"], 1)
        self.assertEqual(self.object_path().read_bytes(), BODY)

    def test_stage_before_reference_and_orphan_is_retained(self):
        self.assert_code("missing_object", self.store.reference, self.meta, expected_revision=0)
        self.staged()
        self.assertEqual(self.store.inventory()["objects"], [{"sha256": self.meta["sha256"], "state": "orphan"}])
        self.assert_code("missing_reference", self.store.read_bytes, self.meta)
        self.assertTrue(self.object_path().exists())
        self.referenced()
        self.assertEqual(self.store.inventory()["objects"][0]["state"], "referenced")

    def test_wrong_bytes_and_hash_never_stage(self):
        self.assert_code("hash_mismatch", self.store.stage, BODY + b" ", self.meta["sha256"])
        self.assertEqual(self.store.inventory()["objects"], [])

    def test_wrong_size_and_source_revision(self):
        self.referenced()
        self.assert_code("size_mismatch", self.store.reference,
                         {**self.meta, "size": 0}, expected_revision=0)
        self.assert_code("identity_conflict", self.store.snapshot,
                         {**self.meta, "source_revision": "b" * 40})

    def test_revision_cas_and_historical_retry_preserve_head(self):
        self.referenced()
        second = self.staged(b"synthetic revision 2", metadata(b"synthetic revision 2", revision=2))
        self.assert_code("revision_mismatch", self.store.reference, second, expected_revision=0)
        self.store.reference(second, expected_revision=1)
        self.assertEqual(self.store.reference(self.meta, expected_revision=0)["head_revision"], 2)
        self.assertEqual(self.store.read_bytes(self.meta), BODY)
        third = self.staged(b"synthetic revision 4", metadata(b"synthetic revision 4", revision=4))
        self.assert_code("revision_conflict", self.store.reference, third, expected_revision=3)

    def test_same_revision_cannot_change_bytes(self):
        self.referenced()
        changed = self.staged(b"synthetic changed")
        self.assert_code("identity_conflict", self.store.reference, changed, expected_revision=0)
        self.assertEqual(self.store.read_bytes(self.meta), BODY)

    def test_receipt_is_local_unverified_idempotent_history(self):
        self.referenced()
        receipt = self.store.record_fixture_receipt(self.meta, "urn:pya:synthetic:receipt", expected_version=0)
        self.store.close()
        self.store = FixtureStore(self.root, PUBLIC)
        self.assertEqual(receipt, self.store.record_fixture_receipt(
            self.meta, "urn:pya:synthetic:receipt", expected_version=0))
        self.assertFalse(receipt["canonical_import_authenticated"])
        self.assertFalse(receipt["publication_eligible"])
        self.assertFalse(receipt["rights_cleared"])
        self.assertEqual(receipt["state"], "local_receipt_asserted")
        self.assertEqual(receipt["receipt_version"], 1)

    def test_receipt_requires_exact_reference_and_bytes(self):
        self.staged()
        self.assert_code("missing_reference", self.store.record_fixture_receipt,
                         self.meta, "urn:pya:synthetic:receipt", expected_version=0)
        self.referenced()
        for changed in ({"source_revision": "b" * 40}, {"revision": 2}, {"sha256": "0" * 64}):
            with self.assertRaises(StorageError):
                self.store.record_fixture_receipt({**self.meta, **changed},
                                                 "urn:pya:synthetic:receipt", expected_version=0)
        self.object_path().write_bytes(b"synthetic corruption")
        self.assert_code("corrupt_object", self.store.record_fixture_receipt,
                         self.meta, "urn:pya:synthetic:receipt", expected_version=0)

    def test_receipt_cas_and_global_identity_conflict(self):
        self.referenced()
        self.assert_code("receipt_conflict", self.store.record_fixture_receipt,
                         self.meta, "urn:pya:synthetic:receipt", expected_version=1)
        self.store.record_fixture_receipt(self.meta, "urn:pya:synthetic:receipt", expected_version=0)
        self.assert_code("receipt_conflict", self.store.record_fixture_receipt,
                         self.meta, "urn:pya:synthetic:other", expected_version=0)
        other = metadata(name="other")
        self.referenced(meta=other)
        self.assert_code("receipt_conflict", self.store.record_fixture_receipt,
                         other, "urn:pya:synthetic:receipt", expected_version=0)

    def test_class_separation_and_restricted_handoff_denial(self):
        self.referenced()
        restricted = FixtureStore(self.root, RESTRICTED)
        try:
            meta = metadata(storage_class=RESTRICTED)
            self.assert_code("class_mismatch", restricted.snapshot, self.meta)
            self.assert_code("missing_object", restricted.reference, meta, expected_revision=0)
            restricted.stage(BODY, meta["sha256"])
            restricted.reference(meta, expected_revision=0)
            self.assert_code("handoff_class_denied", restricted.record_fixture_receipt,
                             meta, "urn:pya:synthetic:receipt", expected_version=0)
            self.object_path().write_bytes(b"synthetic corruption")
            self.assertEqual(restricted.read_bytes(meta), BODY)
        finally:
            restricted.close()

    def test_missing_object_detected_without_history_deletion(self):
        self.referenced()
        self.object_path().unlink()  # Test-only corruption of temporary fixtures.
        self.assert_code("missing_object", self.store.snapshot, self.meta)
        self.assertEqual(self.store.inventory()["objects"][0]["state"], "missing_object")
        self.staged()
        self.assertEqual(self.store.snapshot(self.meta)["head_revision"], 1)

    def test_metadata_snapshot_survives_byte_outage_without_claiming_custody(self):
        self.referenced()
        newer = metadata(data=BODY + b"new revision", revision=2)
        self.referenced(data=BODY + b"new revision", meta=newer)
        with patch.object(self.store, "_read", side_effect=StorageError("missing_object")) as read:
            result = self.store.snapshot_metadata(self.meta)
            self.assertEqual(result["revision"], 1)
            self.assertEqual(result["head_revision"], 2)
            self.assertIs(result["content_verified"], False)
            self.assertIs(result["canonical_import_authenticated"], False)
            self.assertEqual(result["evidence_level"], "synthetic_local_metadata_rehearsal")
            read.assert_not_called()
            self.assert_code("missing_object", self.store.snapshot, self.meta)
            self.assert_code("missing_object", self.store.read_bytes, self.meta)
        result["size"] = 0
        self.assertEqual(self.store.snapshot_metadata(self.meta)["size"], len(BODY))
        self.assertEqual(self.store.read_bytes(self.meta), BODY)

    def test_metadata_snapshot_still_requires_an_exact_existing_reference(self):
        self.assert_code("missing_reference", self.store.snapshot_metadata, self.meta)
        self.referenced()
        for key, value in (("size", len(BODY) + 1), ("sha256", "0" * 64),
                           ("source_revision", "b" * 40)):
            with self.subTest(key=key):
                self.assert_code("identity_conflict", self.store.snapshot_metadata,
                                 dict(self.meta, **{key: value}))
        with self.assertRaises(StorageError):
            self.store.snapshot_metadata(dict(self.meta, storage_class=RESTRICTED))

    def test_formatted_error_suppresses_underlying_path_context(self):
        try:
            self.store.reference(self.meta, expected_revision=0)
        except StorageError as error:
            formatted = "".join(traceback.format_exception(error))
            self.assertEqual(str(error), "missing_object")
            self.assertNotIn(self.root, formatted)
            self.assertNotIn("FileNotFoundError", formatted)
            self.assertTrue(error.__suppress_context__)
            # Context and caller frames still exist: this is not object erasure.
            self.assertIsInstance(error.__context__, FileNotFoundError)
        else:
            self.fail("missing object must fail")

    def test_corruption_cannot_be_overwritten_by_stage_retry(self):
        self.referenced()
        self.object_path().write_bytes(b"synthetic corruption")
        self.assert_code("corrupt_object", self.store.stage, BODY, self.meta["sha256"])
        self.assertEqual(self.store.inventory()["objects"][0]["state"], "corrupt_object")
        self.assertEqual(self.object_path().read_bytes(), b"synthetic corruption")

    def test_oversized_and_nonregular_objects_fail_closed(self):
        self.referenced()
        self.object_path().write_bytes(b"x" * (MAX_BYTES + 1))
        self.assert_code("corrupt_object", self.store.read_bytes, self.meta)
        self.object_path().unlink()
        os.mkfifo(self.object_path())
        self.assert_code("corrupt_object", self.store.read_bytes, self.meta)

    def test_symlink_object_is_not_followed(self):
        self.referenced()
        self.object_path().unlink()
        target = Path(self.root) / "synthetic-target"
        target.write_bytes(BODY)
        self.object_path().symlink_to(target)
        self.assert_code("corrupt_object", self.store.read_bytes, self.meta)

    def test_interruption_before_object_link_leaves_only_partial(self):
        with patch("src.storage.os.link", side_effect=OSError("unreflected fixture detail")):
            self.assert_code("storage_unavailable", self.store.stage, BODY, self.meta["sha256"])
        self.assertEqual(self.store.inventory()["objects"], [{"state": "partial"}])
        self.referenced()
        self.assertEqual(self.store.read_bytes(self.meta), BODY)

    def test_interruption_after_object_link_leaves_recoverable_orphan(self):
        with patch.object(self.store, "_sync_directory", side_effect=OSError("fixture failure")):
            self.assert_code("storage_unavailable", self.store.stage, BODY, self.meta["sha256"])
        states = [entry["state"] for entry in self.store.inventory()["objects"]]
        self.assertCountEqual(states, ["partial", "orphan"])
        self.referenced()
        self.assertEqual(self.store.read_bytes(self.meta), BODY)

    def test_failed_reference_transaction_preserves_staged_object(self):
        self.staged()
        with self.database() as db:
            db.execute("CREATE TRIGGER fail_head BEFORE INSERT ON heads BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.assert_code("storage_unavailable", self.store.reference, self.meta, expected_revision=0)
        self.assert_code("missing_reference", self.store.snapshot, self.meta)
        with self.database() as db:
            db.execute("DROP TRIGGER fail_head")
        self.referenced()

    def test_failed_receipt_transaction_keeps_reference(self):
        self.referenced()
        with self.database() as db:
            db.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END")
        self.assert_code("storage_unavailable", self.store.record_fixture_receipt,
                         self.meta, "urn:pya:synthetic:receipt", expected_version=0)
        self.assertEqual(self.store.snapshot(self.meta)["state"], "referenced")
        with self.database() as db:
            db.execute("DROP TRIGGER fail_receipt")
        self.store.record_fixture_receipt(self.meta, "urn:pya:synthetic:receipt", expected_version=0)

    def test_process_exit_at_each_committed_boundary_is_recoverable(self):
        script = """
import hashlib,json,os,sys
from src.storage import FixtureStore
root, boundary, raw = sys.argv[1:]
m=json.loads(raw); s=FixtureStore(root,m['storage_class'])
if boundary != 'before_stage': s.stage(%r,m['sha256'])
if boundary in ('reference','receipt'): s.reference(m,expected_revision=0)
if boundary == 'receipt': s.record_fixture_receipt(m,'urn:pya:synthetic:receipt',expected_version=0)
os._exit(23)
""" % BODY
        for boundary in ("before_stage", "stage", "reference", "receipt"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as root:
                run = subprocess.run([sys.executable, "-c", script, root, boundary, json.dumps(self.meta)],
                                     capture_output=True, timeout=10)
                self.assertEqual(run.returncode, 23, run.stderr)
                reopened = FixtureStore(root, PUBLIC)
                try:
                    states = [entry["state"] for entry in reopened.inventory()["objects"]]
                    self.assertEqual(states, [] if boundary == "before_stage" else
                                     ["orphan" if boundary == "stage" else "referenced"])
                    reopened.stage(BODY, self.meta["sha256"])
                    reopened.reference(self.meta, expected_revision=0)
                    receipt = reopened.record_fixture_receipt(self.meta, "urn:pya:synthetic:receipt", expected_version=0)
                    self.assertFalse(receipt["canonical_import_authenticated"])
                finally:
                    reopened.close()

    def race(self, operations):
        barrier = threading.Barrier(len(operations))
        results = []
        def worker(operation):
            store = FixtureStore(self.root, PUBLIC)
            try:
                barrier.wait(timeout=5)
                try:
                    results.append(operation(store))
                except StorageError as error:
                    results.append(str(error))
            finally:
                store.close()
        threads = [threading.Thread(target=worker, args=(operation,)) for operation in operations]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(results), len(operations))
        return results

    def test_two_connection_revision_race_has_one_winner(self):
        first = self.staged()
        second = self.staged(b"synthetic competitor")
        results = self.race([lambda s: s.reference(first, expected_revision=0),
                             lambda s: s.reference(second, expected_revision=0)])
        self.assertEqual(sum(type(result) is dict for result in results), 1)
        self.assertIn("identity_conflict", results)

    def test_two_connection_exact_stage_retry_has_one_object(self):
        results = self.race([lambda s: s.stage(BODY, self.meta["sha256"]),
                             lambda s: s.stage(BODY, self.meta["sha256"])])
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(self.store.inventory()["objects"]), 1)

    def test_two_connection_receipt_race_has_one_winner(self):
        self.referenced()
        results = self.race([lambda s: s.record_fixture_receipt(self.meta, "urn:pya:synthetic:a", expected_version=0),
                             lambda s: s.record_fixture_receipt(self.meta, "urn:pya:synthetic:b", expected_version=0)])
        self.assertEqual(sum(type(result) is dict for result in results), 1)
        self.assertIn("receipt_conflict", results)

    def test_metadata_detached_before_real_sqlite_lock_wait(self):
        self.staged()
        ready, begin, proceed = threading.Event(), threading.Event(), threading.Event()
        mutable = dict(self.meta)
        results = []
        def worker():
            store = FixtureStore(self.root, PUBLIC)
            try:
                store._db.set_trace_callback(lambda sql: begin.set() if sql == "BEGIN IMMEDIATE" else None)
                ready.set()
                proceed.wait(5)
                results.append(store.reference(mutable, expected_revision=0))
            finally:
                store.close()
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertTrue(ready.wait(5))
        db = self.database()
        try:
            db.execute("BEGIN IMMEDIATE")
            proceed.set()
            self.assertTrue(begin.wait(5))
            mutable.update(candidate_id="urn:pya:synthetic:changed", source_revision="b" * 40)
            db.execute("COMMIT")
        finally:
            db.close()
            thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["candidate_id"], self.meta["candidate_id"])
        self.assertEqual(self.store.read_bytes(self.meta), BODY)

    def test_locked_database_has_fixed_error_and_no_reference(self):
        self.staged()
        db = self.database()
        try:
            db.execute("BEGIN IMMEDIATE")
            self.assert_code("storage_unavailable", self.store.reference, self.meta, expected_revision=0)
        finally:
            db.close()
        self.assert_code("missing_reference", self.store.snapshot, self.meta)

    def test_plain_input_and_synthetic_boundaries(self):
        class Hostile(dict):
            def items(self):
                self.fail("must not execute")
        for value in (Hostile(self.meta), {**self.meta, "candidate_id": object()},
                      {**self.meta, "extra": 1}, {**self.meta, "revision": True},
                      {**self.meta, "source_revision": []}, {**self.meta, "candidate_id": "x" * 10000}):
            self.assert_code("invalid_metadata", self.store.reference, value, expected_revision=0)
        for field, value in (("synthetic", False), ("publication_eligible", True)):
            self.assert_code("synthetic_boundary", self.store.reference,
                             {**self.meta, field: value}, expected_revision=0)
        self.assert_code("invalid_bytes", self.store.stage, bytearray(BODY), self.meta["sha256"])

    def test_byte_and_object_ceilings(self):
        self.assert_code("invalid_bytes", self.store.stage, b"x" * (MAX_BYTES + 1), "0" * 64)
        maximum = b"x" * MAX_BYTES
        self.staged(maximum)
        for index in range(MAX_OBJECTS - 1):
            self.staged(f"synthetic {index}".encode())
        self.assertEqual(len(self.store.inventory()["objects"]), MAX_OBJECTS)
        self.assert_code("object_capacity", self.staged, b"synthetic overflow")
        self.staged(maximum)  # Exact retry still works at capacity.

    def test_reference_ceiling_preserves_retry(self):
        self.staged()
        for index in range(MAX_REFERENCES):
            self.store.reference(metadata(name=f"candidate-{index}"), expected_revision=0)
        self.assert_code("reference_capacity", self.store.reference, self.meta, expected_revision=0)
        self.store.reference(metadata(name="candidate-0"), expected_revision=0)

    def test_interrupted_final_slot_is_still_inspectable(self):
        for index in range(MAX_OBJECTS - 1):
            self.staged(f"synthetic {index}".encode())
        with patch.object(self.store, "_sync_directory", side_effect=OSError("fixture failure")):
            self.assert_code("storage_unavailable", self.store.stage, BODY, self.meta["sha256"])
        self.assertEqual(len(self.store.inventory()["objects"]), MAX_OBJECTS + 1)
        self.referenced()
        self.assert_code("object_capacity", self.staged, b"synthetic overflow")

    def test_unexpected_files_and_metadata_corruption_fail_closed(self):
        (self.object_path().parent / "unreflected-details").write_bytes(b"synthetic")
        self.assertEqual(self.store.inventory()["objects"], [{"state": "unexpected"}])
        self.referenced()
        with self.database() as db:
            db.execute("UPDATE candidates SET metadata='invalid JSON'")
        self.assert_code("corrupt_metadata", self.store.inventory)


if __name__ == "__main__":
    unittest.main()
