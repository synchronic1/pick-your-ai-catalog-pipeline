"""Bounded offline synthetic catalog checks, never a publication authorizer."""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker

from src.normalization import INPUT_VERSION, NormalizationError, normalize
from src.security.input_controls import UnsafeJSONError, parse_untrusted_json

VERSION = "catalog-pipeline-draft-0.1.0"
MAX_RECORDS = 64
MAX_COLLECTION = 128
MAX_ERRORS = 64
_SCHEMA = json.loads((Path(__file__).resolve().parents[2] /
                      "schemas/v0.1/catalog-record.schema.json").read_text())
# This is the sole repository-owned schema, not a caller-controlled resolver.
# Refuse future reference-bearing schema changes until explicitly reviewed.
_pending = [_SCHEMA]
while _pending:
    _item = _pending.pop()
    if type(_item) is dict:
        if any(key in _item for key in ("$ref", "$dynamicRef", "$recursiveRef")):
            raise RuntimeError("catalog schema references require offline review")
        _pending.extend(_item.values())
    elif type(_item) is list:
        _pending.extend(_item)
Draft202012Validator.check_schema(_SCHEMA)
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())
_ID = re.compile(r"urn:pya:synthetic:[a-z0-9][a-z0-9:._-]{0,139}\Z", re.ASCII)
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z", re.ASCII)
_DECIMAL = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?", re.ASCII)
_CLAIM_PATH = re.compile(r"[a-z][a-z0-9_.-]+", re.ASCII)
_FIELDS = {"schema_version", "synthetic", "id", "revision", "entity_kind",
           "display_name", "lifecycle", "claims", "relationships", "unknowns",
           "path", "value_type", "value", "unknown_reason", "unit", "evidence",
           "class", "confidence", "verification", "basis", "receipt_ref", "sources",
           "source_id", "material_id", "url", "observed_at", "source_revision",
           "conditions", "relation", "target_id", "target_revision"}
# Only these proposed hierarchical edges are required acyclic. Citation/support
# cycles do not imply invalid real-world facts and are intentionally permitted.
_ACYCLIC = {"member_of", "derived_from", "supersedes"}


def _path(parts):
    """Only known schema fields and integer offsets enter public diagnostics."""
    if any(type(p) is not int and p not in _FIELDS for p in parts):
        return "$"
    return "$" + "".join(f"/{p}" for p in parts)


def _add(errors, parts, code):
    if len(errors) < MAX_ERRORS:
        errors.append({"path": _path(parts), "code": code})


def _report(schema, semantic, errors):
    return {"schema_version": "synthetic-validation-report-0.1",
            "synthetic": True, "schema_status": schema, "semantic_status": semantic,
            "evidence_status": "not_assessed", "rights_status": "not_assessed",
            "review_status": "not_assessed", "acceptance_status": "not_accepted",
            "publication_eligible": False,
            "errors": sorted(errors, key=lambda e: (e["path"], e["code"]))}


def validate_catalog(payload: bytes | str) -> dict:
    """Validate a closed JSON array of existing draft catalog records.

    Input is raw UTF-8, never a decoded mapping or a schema supplied by a caller.
    The shared parser retains numeric tokens as int/Decimal before type checks.
    Public diagnostics contain fixed codes and schema paths, never input values.
    Limits: 1 MiB, depth 32, 10,000 nodes, 64 records, 128 collection entries,
    64 diagnostics. Limits are fixed and cannot be raised by untrusted callers.
    """
    errors = []
    if type(payload) not in (bytes, str):
        return _report("fail", "not_run", [{"path": "$", "code": "raw_json_required"}])
    try:
        records = parse_untrusted_json(payload)
    except UnsafeJSONError:
        return _report("fail", "not_run", [{"path": "$", "code": "invalid_or_unbounded_json"}])
    if type(records) is not list or not 1 <= len(records) <= MAX_RECORDS:
        return _report("fail", "not_run", [{"path": "$", "code": "record_collection_limit_or_type"}])
    # Bound every list before schema traversal; node/depth/byte limits are already
    # checked. Reject Decimal even when integral: revision pins require int tokens.
    stack = [(records, [])]
    while stack:
        item, path = stack.pop()
        if type(item) is list:
            if len(item) > MAX_COLLECTION:
                _add(errors, path, "collection_limit")
            stack.extend((child, path + [i]) for i, child in enumerate(item))
        elif type(item) is dict:
            stack.extend((child, path + [key]) for key, child in item.items())
        elif type(item) is Decimal:
            _add(errors, path, "numeric_token_requires_integer_or_decimal_string")
    if errors:
        return _report("fail", "not_run", errors)
    for i, record in enumerate(records):
        if type(record) is dict and record.get("schema_version") != VERSION:
            _add(errors, [i, "schema_version"], "unsupported_schema_version")
            continue
        # Stop schema diagnostics at the public error ceiling. No instance text
        # or jsonschema message is retained, including unknown field names.
        for error in _VALIDATOR.iter_errors(record):
            _add(errors, [i, *error.absolute_path], "schema_" + error.validator.lower())
            if len(errors) == MAX_ERRORS:
                break
    if errors:
        return _report("fail", "not_run", errors)
    _semantics(records, errors)
    return _report("pass", "fail" if errors else "pass", errors)


def _semantics(records, errors):
    identities, by_id, materials = set(), {}, {}
    for i, record in enumerate(records):
        by_id.setdefault(record["id"], record)
        entries = [(record["id"], [i, "id"])]
        entries += [(claim["id"], [i, "claims", j, "id"])
                    for j, claim in enumerate(record["claims"])]
        for identity, path in entries:
            if not _ID.fullmatch(identity):
                _add(errors, path, "synthetic_identity_required")
            if identity in identities:
                _add(errors, path, "duplicate_identity")
            identities.add(identity)
        if record["synthetic"] is not True:
            _add(errors, [i, "synthetic"], "synthetic_required")
        if record["entity_kind"] == "cost_observation":
            _add(errors, [i, "entity_kind"], "currency_meter_contract_unsupported")
        paths = set()
        for j, claim in enumerate(record["claims"]):
            path = [i, "claims", j]
            if not _CLAIM_PATH.fullmatch(claim["path"]):
                _add(errors, path + ["path"], "invalid_claim_path_lexeme")
            if claim["path"] in paths:
                _add(errors, path + ["path"], "duplicate_claim_path")
            paths.add(claim["path"])
            if claim["value_type"] == "integer" and type(claim["value"]) is not int:
                _add(errors, path + ["value"], "integer_token_required")
            if claim["value_type"] == "unknown" and not claim["unknown_reason"].strip():
                _add(errors, path + ["unknown_reason"], "unknown_reason_required")
            if claim["value_type"] == "decimal":
                # JSON Schema's $ anchor may match before final LF. Check the
                # entire supplied lexeme independently, including unitless data.
                if not _DECIMAL.fullmatch(claim["value"]):
                    _add(errors, path + ["value"], "invalid_decimal_lexeme")
                if len(claim["value"]) > 1024:
                    _add(errors, path + ["value"], "decimal_precision_limit")
            if "unit" in claim:
                if claim["value_type"] not in {"integer", "decimal"}:
                    _add(errors, path + ["unit"], "unit_requires_numeric_claim")
                else:
                    # Reuse the existing bounded mathematical-unit draft. No
                    # field-family dimensions or physical truth are inferred.
                    packet = {"schema_version": INPUT_VERSION, "synthetic": True,
                              "id": "urn:pya:synthetic:validation",
                              "source_revision": "urn:pya:synthetic:observation",
                              "field": "value", "value_type": "quantity", "state": "known",
                              "value": str(claim["value"]), "unit": claim["unit"],
                              "target_unit": claim["unit"]}
                    try:
                        normalize(packet)
                    except NormalizationError:
                        _add(errors, path + ["unit"], "unsupported_unit_or_quantity")
            evidence = claim["evidence"]
            if evidence["verification"] == "independently_reproduced":
                _add(errors, path + ["evidence", "verification"], "synthetic_reproduction_forbidden")
            if "receipt_ref" in evidence:
                # No receipt-resolution contract is adopted by this API. Never
                # let a supplied URN masquerade as an authenticated review.
                _add(errors, path + ["evidence", "receipt_ref"], "receipt_resolution_unsupported")
            sources = set()
            for k, source in enumerate(claim["sources"]):
                prefix = path + ["sources", k]
                for field in ("source_id", "material_id"):
                    if not _ID.fullmatch(source[field]):
                        _add(errors, prefix + [field], "synthetic_identity_required")
                if not source["source_revision"].strip():
                    _add(errors, prefix + ["source_revision"], "exact_source_revision_required")
                binding = (source["source_id"], source["material_id"], source["source_revision"])
                if binding in sources:
                    _add(errors, prefix, "duplicate_source_binding")
                sources.add(binding)
                previous = materials.setdefault(source["material_id"], source["source_id"])
                if previous != source["source_id"]:
                    _add(errors, prefix, "conflicting_material_source")
                try:
                    locator = urlsplit(source["url"])
                    if (locator.scheme != "https" or locator.hostname != "example.invalid"
                            or locator.username or locator.password or locator.query
                            or locator.fragment or locator.port is not None):
                        raise ValueError
                except ValueError:
                    _add(errors, prefix + ["url"], "reserved_synthetic_locator_required")
                timestamp = source["observed_at"]
                try:
                    if not _TIME.fullmatch(timestamp):
                        raise ValueError
                    datetime.fromisoformat(timestamp[:-1] + "+00:00")
                except ValueError:
                    _add(errors, prefix + ["observed_at"], "explicit_utc_timestamp_required")
    graph = {identity: [] for identity in by_id}
    for i, record in enumerate(records):
        seen = set()
        for j, edge in enumerate(record["relationships"]):
            path = [i, "relationships", j]
            binding = (edge["relation"], edge["target_id"], edge["target_revision"])
            if binding in seen:
                _add(errors, path, "duplicate_relationship")
            seen.add(binding)
            target = by_id.get(edge["target_id"])
            if target is None:
                _add(errors, path, "unresolved_record_target")
            elif edge["target_revision"] != target["revision"]:
                _add(errors, path + ["target_revision"], "target_revision_mismatch")
            if edge["relation"] in _ACYCLIC and target is not None:
                graph[record["id"]].append(edge["target_id"])
    # At most 64 vertices. Iterative traversal avoids recursion on untrusted data.
    active, complete = set(), set()
    for origin in graph:
        stack = [(origin, False)]
        while stack:
            vertex, leaving = stack.pop()
            if leaving:
                active.discard(vertex)
                complete.add(vertex)
            elif vertex in active:
                _add(errors, [], "hierarchical_relationship_cycle")
                return
            elif vertex not in complete:
                active.add(vertex)
                stack.append((vertex, True))
                stack.extend((child, False) for child in reversed(graph[vertex]))
