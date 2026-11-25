"""Pure, bounded synthetic normalization proposal; no acquisition or authority."""
from datetime import datetime
from fractions import Fraction
import re

INPUT_VERSION = "synthetic-normalization-input-0.1"
OUTPUT_VERSION = "synthetic-normalization-output-0.1"
TRANSFORM_VERSION = "synthetic-normalizer-0.1.0"
MAX_VALUE_CHARS = 4096
MAX_NUMBER_CHARS = 1024
MAX_EXPONENT = 256
_TYPES = {"integer", "decimal", "quantity", "utc_timestamp", "text", "version"}
_STATES = {"known", "absent", "unknown", "unsupported", "not_applicable"}
_REQUIRED = {"schema_version", "synthetic", "id", "source_revision", "field", "value_type", "state"}
_OPTIONAL = {"value", "reason", "unit", "target_unit", "currency"}
_URN = re.compile(r"urn:pya:synthetic:[a-z0-9][a-z0-9:._-]{0,139}", re.ASCII)
_NUMBER = re.compile(r"(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]{1,3}))?", re.ASCII)
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)", re.ASCII)
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.([0-9]{1,6}))?Z", re.ASCII)
_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,7})\.(?:0|[1-9][0-9]{0,7})\.(?:0|[1-9][0-9]{0,7})", re.ASCII)
# A deliberately small mathematical unit proposal, not a domain qualification policy.
_UNITS = {"B": ("data", 1), "KiB": ("data", 1024), "MiB": ("data", 1048576),
          "s": ("duration", 1000000), "ms": ("duration", 1000), "us": ("duration", 1),
          "W": ("power", 1), "kW": ("power", 1000)}


class NormalizationError(ValueError):
    """Fixed diagnostics intentionally contain no supplied value or identifier."""


def _fail(code):
    raise NormalizationError(code)


def _coefficient(digits):
    """Parse already bounded ASCII digits without process-wide int settings."""
    value = 0
    for start in range(0, len(digits), 9):
        chunk = digits[start:start + 9]
        value = value * 10 ** len(chunk) + int(chunk)
    return value


def _coefficient_text(value):
    """Render a bounded nonnegative coefficient using small decimal chunks."""
    chunks = []
    while value >= 1_000_000_000:
        value, tail = divmod(value, 1_000_000_000)
        chunks.append(str(tail).zfill(9))
    return str(value) + "".join(reversed(chunks))


def _number(value):
    if len(value) > MAX_NUMBER_CHARS:
        _fail("number_limit")
    match = _NUMBER.fullmatch(value)
    if match is None:
        _fail("invalid_number")
    sign, whole, fraction, exponent = match.groups()
    exponent = int(exponent or "0")
    if abs(exponent) > MAX_EXPONENT:
        _fail("number_limit")
    digits = whole + (fraction or "")
    coefficient = _coefficient(digits) * (-1 if sign else 1)
    scale = exponent - len(fraction or "")
    return Fraction(coefficient * 10 ** max(scale, 0), 10 ** max(-scale, 0))


def _decimal(value):
    """Render the finite rational exactly without any float/Decimal context."""
    numerator, denominator = value.numerator, value.denominator
    twos = fives = 0
    while denominator % 2 == 0:
        denominator //= 2
        twos += 1
    while denominator % 5 == 0:
        denominator //= 5
        fives += 1
    if denominator != 1:
        _fail("nonterminating_conversion")
    places = max(twos, fives)
    coefficient = abs(numerator) * 2 ** (places - twos) * 5 ** (places - fives)
    digits = _coefficient_text(coefficient).rjust(places + 1, "0")
    rendered = digits if places == 0 else (digits[:-places] + "." + digits[-places:]).rstrip("0").rstrip(".")
    return ("-" if numerator < 0 else "") + rendered


def normalize(packet):
    """Return a new synthetic receipt or raise NormalizationError with a fixed code.

    Only exact built-in dict/str/bool scalars are supported. All known values are
    lexical strings; missing values are reported explicitly rather than inferred.
    The caller must retain the receipt: this function has no storage or custody.
    """
    if (type(packet) is not dict or len(packet) > len(_REQUIRED | _OPTIONAL)
            or any(type(key) is not str for key in packet)):
        _fail("invalid_packet")
    if not _REQUIRED <= packet.keys() or packet.keys() - (_REQUIRED | _OPTIONAL):
        _fail("invalid_fields")
    for key, value in packet.items():
        if key == "synthetic":
            if value is not True:
                _fail("synthetic_required")
        elif type(value) is not str:
            _fail("invalid_type")
        elif len(value) > MAX_VALUE_CHARS or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            _fail("string_limit")
    if packet["schema_version"] != INPUT_VERSION:
        _fail("unsupported_schema")
    if not _URN.fullmatch(packet["id"]) or not _URN.fullmatch(packet["source_revision"]):
        _fail("synthetic_identity_required")
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,127}", packet["field"], re.ASCII):
        _fail("invalid_field")
    kind, state = packet["value_type"], packet["state"]
    if kind not in _TYPES or state not in _STATES:
        _fail("unsupported_type_or_state")
    result = {"value_type": kind, "state": state}
    extras = packet.keys() & _OPTIONAL
    if state != "known":
        if extras != {"reason"} or not packet["reason"].strip() or len(packet["reason"]) > 256:
            _fail("invalid_missing_state")
        result["reason"] = packet["reason"]
    else:
        expected = {"value", "unit", "target_unit"} if kind == "quantity" else {"value"}
        if kind == "decimal" and "currency" in packet:
            expected.add("currency")
        if extras != expected:
            _fail("invalid_known_fields")
        value = packet["value"]
        if kind == "integer":
            if len(value) > MAX_NUMBER_CHARS:
                _fail("number_limit")
            if not _INTEGER.fullmatch(value):
                _fail("invalid_integer")
            # The grammar already forbids a plus sign and leading zeroes.
            result["value"] = "0" if value == "-0" else value
        elif kind in {"decimal", "quantity"}:
            number = _number(value)
            if kind == "quantity":
                unit, target = packet["unit"], packet["target_unit"]
                if unit not in _UNITS or target not in _UNITS:
                    _fail("unsupported_unit")
                if _UNITS[unit][0] != _UNITS[target][0]:
                    _fail("unit_dimension_mismatch")
                number *= Fraction(_UNITS[unit][1], _UNITS[target][1])
                result.update(unit=target, dimension=_UNITS[target][0])
            elif "currency" in packet:
                if not re.fullmatch(r"[A-Z]{3}", packet["currency"], re.ASCII):
                    _fail("invalid_currency_label")
                result["currency"] = packet["currency"]
            result["value"] = _decimal(number)
        elif kind == "utc_timestamp":
            match = _TIMESTAMP.fullmatch(value)
            if match is None:
                _fail("invalid_utc_timestamp")
            try:
                datetime.fromisoformat(value[:-1] + "+00:00")
            except ValueError:
                _fail("invalid_utc_timestamp")
            fraction = (match.group(1) or "").rstrip("0")
            result["value"] = value[:19] + ("." + fraction if fraction else "") + "Z"
        elif kind == "version":
            if not _VERSION.fullmatch(value):
                _fail("unsupported_version_lexeme")
            result["value"] = value
        else:
            result["value"] = value  # Unicode, whitespace and empty text remain exact.
    return {"schema_version": OUTPUT_VERSION, "synthetic": True,
            "original": dict(packet), "transformation_version": TRANSFORM_VERSION,
            "normalized": result, "evidence_level": "synthetic_unverified",
            "source_authenticated": False, "normalization_authorized": False,
            "rights_cleared": False, "publication_eligible": False}
