"""Bounded offline synthetic catalog bytes; no release or rights authority."""
from dataclasses import dataclass
import binascii
import hashlib
import json
import re
import struct

from src.validation import VERSION as RECORD_VERSION, validate_catalog

INPUT_VERSION = "synthetic-snapshot-input-0.1"
BUILD_VERSION = "synthetic-catalog-builder-0.1.0"
MANIFEST_VERSION = "synthetic-release-manifest-0.1"
PROJECTION_VERSION = "synthetic-whole-record-projection-0.1"
MAX_INPUT_BYTES = 1_048_576
MAX_ARTIFACT_BYTES = 2_097_152
MAX_INDEX_BYTES = 65_536
MAX_NODES = 10_000
MAX_DEPTH = 32
MAX_COLLECTION = 128
MAX_STRING = 4096
MAX_RECORDS = 64
MAX_NOTICES = 16
MAX_NOTICE_CHARS = 2048
MAX_REVISION = 1_000_000_000
_ID = re.compile(r"urn:pya:synthetic:[a-z0-9][a-z0-9:._-]{0,139}\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_STATUS = dict(synthetic=True, publication_eligible=False, channel="synthetic",
               authenticated=False, rights_cleared=False)


class BuildError(ValueError):
    """Fixed diagnostics contain no caller values or paths."""


def _require(condition, code):
    if not condition:
        raise BuildError(code)


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _copy_plain(value):
    """Reject hooks before traversal; bound work before encoding or validation."""
    active = set()
    nodes = 0
    # Conservative encoded-size accounting prevents a huge temporary JSON value.
    budget = 0

    def visit(item, depth):
        nonlocal nodes, budget
        nodes += 1
        _require(nodes <= MAX_NODES and depth <= MAX_DEPTH, "input_limit")
        kind = type(item)
        _require(any(kind is plain for plain in (dict, list, str, int, bool, type(None))),
                 "plain_data_required")
        if kind is dict or kind is list:
            _require(len(item) <= MAX_COLLECTION, "collection_limit")
            _require(id(item) not in active, "cyclic_input")
            active.add(id(item))
            budget += 2 + len(item)
            if kind is dict:
                result = {}
                for key, child in item.items():
                    _require(type(key) is str, "plain_string_key_required")
                    copied_key = visit(key, depth + 1)
                    budget += 1
                    result[copied_key] = visit(child, depth + 1)
            else:
                result = [visit(child, depth + 1) for child in item]
            active.remove(id(item))
        elif kind is str:
            _require(len(item) <= MAX_STRING, "string_limit")
            _require(all(ord(c) >= 32 and not 127 <= ord(c) <= 159
                         and not 0xD800 <= ord(c) <= 0xDFFF for c in item),
                     "invalid_string")
            budget += len(_encode(item))
            result = item
        elif kind is int:
            _require(abs(item) <= 9_007_199_254_740_991, "integer_limit")
            budget += len(str(item))
            result = item
        else:
            budget += 5
            result = item
        _require(budget <= MAX_INPUT_BYTES, "input_byte_limit")
        return result

    return visit(value, 0)


def _fields(value, fields):
    _require(type(value) is dict and value.keys() == set(fields.split()), "invalid_fields")


def _identity(value):
    _require(type(value) is str and _ID.fullmatch(value) is not None,
             "synthetic_identity_required")


def _revision(value):
    _require(type(value) is int and 1 <= value <= MAX_REVISION, "invalid_revision")


def _digest(value):
    _require(type(value) is str and _HASH.fullmatch(value) is not None, "invalid_digest")


def _pin(value):
    _fields(value, "id revision sha256")
    _identity(value["id"])
    _revision(value["revision"])
    _digest(value["sha256"])


def _stored_gzip(data):
    """RFC 1952 gzip with RFC 1951 stored blocks: runtime-independent bytes.

    This prioritizes stable identity over compression ratio. No zlib compressor,
    host OS identifier, filename or clock contributes to the stream.
    """
    chunks = [data[i:i + 65535] for i in range(0, len(data), 65535)] or [b""]
    result = bytearray(b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff")
    for i, chunk in enumerate(chunks):
        result += bytes([int(i == len(chunks) - 1)])
        result += struct.pack("<HH", len(chunk), 65535 - len(chunk)) + chunk
    result += struct.pack("<II", binascii.crc32(data), len(data))
    return bytes(result)


@dataclass(frozen=True, slots=True)
class BuildResult:
    catalog_bytes: bytes
    gzip_bytes: bytes
    index_bytes: bytes
    manifest_bytes: bytes

    @property
    def manifest_sha256(self):
        return _hash(self.manifest_bytes)


def build_snapshot(payload):
    """Return immutable bytes from a plain decoded synthetic input envelope.

    Records use the existing draft schema; the candidate/projection/review
    adapter is a new partial proposal, not ReviewQueue's flat-data contract.
    All pins and include decisions are caller assertions, never authentic grants.
    Array ordering is significant inside records and notices; only the outer
    record set and mapping keys are canonicalized. No path/IO API is provided.
    """
    data = _copy_plain(payload)
    _fields(data, "schema_version build_version record_schema_version synthetic artifact_kind "
            "release_id release_revision parent_release excluded_candidate_count records")
    _require(data["schema_version"] == INPUT_VERSION
             and data["build_version"] == BUILD_VERSION
             and data["record_schema_version"] == RECORD_VERSION, "unsupported_version")
    _require(data["synthetic"] is True, "synthetic_required")
    _require(data["artifact_kind"] == "catalog", "unsupported_artifact_kind")
    _identity(data["release_id"])
    _revision(data["release_revision"])
    if data["parent_release"] is not None:
        _pin(data["parent_release"])
        _require(data["parent_release"]["id"] != data["release_id"]
                 or data["parent_release"]["revision"] < data["release_revision"],
                 "invalid_parent_revision")
    count = data["excluded_candidate_count"]
    _require(type(count) is int and 0 <= count <= 1_000_000, "invalid_excluded_count")
    items = data["records"]
    _require(type(items) is list and 1 <= len(items) <= MAX_RECORDS, "record_limit")
    seen_candidates, seen_records, seen_reviews = set(), set(), set()
    # Reserve release roles before binding record metadata. A same-ID parent is
    # permitted only at an earlier revision, as checked above.
    pins = {data["release_id"]: ("release",)}
    if data["parent_release"] is not None:
        pins[data["parent_release"]["id"]] = ("release",)
    entries = []
    for item in items:
        _fields(item, "candidate record evidence packet projection review")
        candidate, record = item["candidate"], item["record"]
        _fields(candidate, "id revision")
        _identity(candidate["id"])
        _revision(candidate["revision"])
        _require(type(record) is dict and "id" in record and "revision" in record,
                 "record_shape")
        _identity(record["id"])
        _revision(record["revision"])
        _require(candidate["id"] not in seen_candidates and record["id"] not in seen_records,
                 "duplicate_identity_or_mixed_revision")
        seen_candidates.add(candidate["id"])
        seen_records.add(record["id"])
        record_hash = _hash(_encode(record))
        projection = item["projection"]
        _fields(projection, "schema_version record_sha256 rights notices")
        _require(projection["schema_version"] == PROJECTION_VERSION, "unsupported_projection")
        _digest(projection["record_sha256"])
        _require(projection["record_sha256"] == record_hash, "record_binding_mismatch")
        for role, pin in (("evidence", item["evidence"]), ("packet", item["packet"]),
                          ("rights", projection["rights"])):
            _pin(pin)
            binding = (role, pin["revision"], pin["sha256"])
            _require(pins.setdefault(pin["id"], binding) == binding,
                     "conflicting_pin_or_mixed_revision")
        notices = projection["notices"]
        _require(type(notices) is list and 1 <= len(notices) <= MAX_NOTICES, "notice_limit")
        notice_ids = set()
        for notice in notices:
            _fields(notice, "id text")
            _identity(notice["id"])
            _require(type(notice["text"]) is str and notice["text"].strip()
                     and len(notice["text"]) <= MAX_NOTICE_CHARS, "invalid_notice")
            _require(notice["id"] not in notice_ids, "duplicate_notice")
            notice_ids.add(notice["id"])
            binding = ("notice", _hash(_encode(notice)))
            _require(pins.setdefault(notice["id"], binding) == binding, "conflicting_notice")
        review = item["review"]
        _fields(review, "id revision binding_sha256 outcome")
        _identity(review["id"])
        _revision(review["revision"])
        _digest(review["binding_sha256"])
        _require(review["outcome"] == "include-synthetic", "synthetic_review_required")
        _require(review["id"] not in seen_reviews, "duplicate_review")
        seen_reviews.add(review["id"])
        reviewed = {key: value for key, value in item.items() if key != "review"}
        _require(review["binding_sha256"] == _hash(_encode(reviewed)), "review_binding_mismatch")
        for role, identity in (("candidate", candidate), ("record", record), ("review", review)):
            _require(identity["id"] not in pins, "conflicting_identity_role")
            pins[identity["id"]] = (role, identity["revision"])
        entries.append(dict(candidate=candidate,
                            record=dict(id=record["id"], revision=record["revision"], sha256=record_hash),
                            input_sha256=_hash(_encode(item)),
                            evidence=item["evidence"], packet=item["packet"],
                            projection_sha256=_hash(_encode(projection)),
                            rights=projection["rights"], notices=notices,
                            notices_sha256=_hash(_encode(notices)),
                            review=dict(id=review["id"], revision=review["revision"],
                                        sha256=_hash(_encode(review)))))
    items.sort(key=lambda item: (item["record"]["id"], item["record"]["revision"],
                                 item["candidate"]["id"], item["candidate"]["revision"]))
    entries.sort(key=lambda entry: (entry["record"]["id"], entry["record"]["revision"],
                                    entry["candidate"]["id"], entry["candidate"]["revision"]))
    records = [item["record"] for item in items]
    report = validate_catalog(_encode(records))
    _require(report["schema_status"] == "pass" and report["semantic_status"] == "pass",
             "catalog_validation_failed")
    envelope = dict(_STATUS, schema_version="synthetic-catalog-artifact-0.1",
                    record_schema_version=RECORD_VERSION, records=[])
    before, after = _encode(envelope).split(b'"records":[]')
    prefix, suffix = before + b'"records":[', b']' + after
    offset, chunks, offsets = len(prefix), [], []
    for record in records:
        chunk = _encode(record)
        chunks.append(chunk)
        offsets.append(dict(id=record["id"], revision=record["revision"],
                            offset_bytes=offset, length_bytes=len(chunk), sha256=_hash(chunk)))
        offset += len(chunk) + 1
    catalog = prefix + b",".join(chunks) + suffix
    compressed = _stored_gzip(catalog)
    index = _encode(dict(_STATUS, schema_version="synthetic-catalog-index-0.1",
                         catalog_sha256=_hash(catalog), records=offsets))
    manifest = dict(_STATUS, schema_version=MANIFEST_VERSION, build_version=BUILD_VERSION,
                    input_schema_version=INPUT_VERSION, record_schema_version=RECORD_VERSION,
                    projection_schema_version=PROJECTION_VERSION, artifact_kind="catalog",
                    release_id=data["release_id"], release_revision=data["release_revision"],
                    parent_release=data["parent_release"], excluded_candidate_count=count,
                    input_sha256=_hash(_encode(data)), records=entries,
                    artifacts={name: dict(sha256=_hash(value), size_bytes=len(value)) for name, value in
                               (("catalog", catalog), ("catalog_gzip", compressed), ("index", index))})
    manifest_bytes = _encode(manifest)
    _require(max(map(len, (catalog, compressed, manifest_bytes))) <= MAX_ARTIFACT_BYTES
             and len(index) <= MAX_INDEX_BYTES, "artifact_byte_limit")
    return BuildResult(catalog, compressed, index, manifest_bytes)
