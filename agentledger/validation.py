"""
Structural validation for the AuditEvent contract (composed with RecordEnvelope).

This validates the exact shape approved in:
  schemas/core_wire/RecordEnvelope-1.0.0.schema.json
  schemas/audit_value_packaging/AuditEvent-1.0.0.schema.json

It is a hand-written, dependency-free validator rather than a generic JSON
Schema engine. For a single, already-frozen v1.0.0 contract this is more
maintainable than pulling in a schema library, and it makes every rule
traceable to a line of code instead of a generic engine's error message.
If/when more contracts are implemented, replace with `jsonschema` and keep
this module's semantic checks (digest/hash catalog matching) as-is.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

_DATETIME_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$"
)
# Component ids are `<VENDOR>-<COMPONENT>-<NNN>`, e.g. ACME-BILLING-001.
# The original Neo-internal contract fixed the vendor prefix to NEO-; it is
# generalised here so any owner can emit into this ledger. Every previously
# valid NEO-* id still matches.
_MODULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SCREAM_CASE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,126}$")

_CLOCK_QUALITIES = {"SYNCHRONIZED", "ESTIMATED", "UNSYNCHRONIZED", "UNKNOWN"}

# Fields RecordEnvelope + AuditEvent close the shape with (unevaluatedProperties: false).
_KNOWN_FIELDS = {
    # RecordEnvelope
    "contract_name", "contract_version", "record_id", "created_at",
    "producer_module_id", "correlation_ids", "provenance", "schema_hash",
    "record_digest", "digest_algorithm", "canonicalization_profile",
    # AuditEvent required
    "event_id", "event_schema_version", "event_type", "actor_module",
    "subject_refs", "authority_refs_if_relevant", "truth_refs_if_relevant",
    "payload_ref_or_summary", "payload_digest", "data_classification",
    "producer_emitted_at", "producer_clock_quality",
    # AuditEvent optional
    "producer_occurred_at_if_known", "producer_signature_ref_if_used",
}

_REQUIRED_FIELDS = _KNOWN_FIELDS - {
    "producer_occurred_at_if_known", "producer_signature_ref_if_used",
}


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def add(self, msg: str) -> None:
        self.errors.append(msg)


def _is_str_in_range(v: Any, lo: int, hi: int) -> bool:
    return isinstance(v, str) and not isinstance(v, bool) and lo <= len(v) <= hi


def _check_refs_array(v: Any, name: str, r: ValidationResult) -> None:
    if not isinstance(v, list):
        r.add(f"{name}: must be an array")
        return
    seen = set()
    for i, item in enumerate(v):
        if not _is_str_in_range(item, 1, 256):
            r.add(f"{name}[{i}]: must be a string of length 1..256")
        if item in seen:
            r.add(f"{name}[{i}]: duplicate value not allowed (uniqueItems)")
        seen.add(item)


def validate_audit_event(record: Mapping[str, Any]) -> ValidationResult:
    r = ValidationResult()

    if not isinstance(record, dict):
        r.add("record: must be a JSON object")
        return r

    unknown = set(record.keys()) - _KNOWN_FIELDS
    for f in sorted(unknown):
        r.add(f"{f}: unknown field (unevaluatedProperties: false)")

    missing = _REQUIRED_FIELDS - set(record.keys())
    for f in sorted(missing):
        r.add(f"{f}: required field missing")

    def get(name: str) -> Any:
        return record.get(name)

    # --- consts ---
    if "contract_name" in record and get("contract_name") != "AuditEvent":
        r.add("contract_name: must equal 'AuditEvent'")
    if "contract_version" in record and get("contract_version") != "1.0.0":
        r.add("contract_version: must equal '1.0.0' (unsupported version)")
    if "digest_algorithm" in record and get("digest_algorithm") != "SHA-256":
        r.add("digest_algorithm: must equal 'SHA-256'")
    if "canonicalization_profile" in record and get("canonicalization_profile") != "JCS-1":
        r.add("canonicalization_profile: must equal 'JCS-1'")

    # --- RecordEnvelope fields ---
    if "record_id" in record and not _is_str_in_range(get("record_id"), 8, 128):
        r.add("record_id: must be a string of length 8..128")
    for dt_field in ("created_at",):
        if dt_field in record:
            v = get(dt_field)
            if not (isinstance(v, str) and _DATETIME_RE.match(v)):
                r.add(f"{dt_field}: must be an RFC3339 UTC timestamp ('...Z')")
    if "producer_module_id" in record:
        v = get("producer_module_id")
        if not (isinstance(v, str) and _MODULE_ID_RE.match(v)):
            r.add("producer_module_id: must match ^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$")
    if "correlation_ids" in record:
        v = get("correlation_ids")
        if not isinstance(v, list):
            r.add("correlation_ids: must be an array")
        else:
            for i, item in enumerate(v):
                if not isinstance(item, dict):
                    r.add(f"correlation_ids[{i}]: must be an object")
                    continue
                if set(item.keys()) - {"kind", "id"}:
                    r.add(f"correlation_ids[{i}]: unknown field")
                if not _is_str_in_range(item.get("kind"), 1, 64):
                    r.add(f"correlation_ids[{i}].kind: must be a string of length 1..64")
                if not _is_str_in_range(item.get("id"), 8, 128):
                    r.add(f"correlation_ids[{i}].id: must be a string of length 8..128")
    if "provenance" in record:
        v = get("provenance")
        if not isinstance(v, list):
            r.add("provenance: must be an array")
        else:
            for i, item in enumerate(v):
                if not isinstance(item, dict):
                    r.add(f"provenance[{i}]: must be an object")
                    continue
                if set(item.keys()) - {"source_type", "source_ref", "source_digest"}:
                    r.add(f"provenance[{i}]: unknown field")
                st = item.get("source_type")
                if not (isinstance(st, str) and _SCREAM_CASE_RE.match(st) and len(st) <= 64):
                    r.add(f"provenance[{i}].source_type: must match ^[A-Z][A-Z0-9_]{{0,63}}$")
                if not _is_str_in_range(item.get("source_ref"), 1, 256):
                    r.add(f"provenance[{i}].source_ref: must be a string of length 1..256")
                if "source_digest" in item and not (
                    isinstance(item["source_digest"], str) and _HEX64_RE.match(item["source_digest"])
                ):
                    r.add(f"provenance[{i}].source_digest: must be a 64-char hex SHA-256")
    for hex_field in ("schema_hash", "record_digest", "payload_digest"):
        if hex_field in record:
            v = get(hex_field)
            if not (isinstance(v, str) and _HEX64_RE.match(v)):
                r.add(f"{hex_field}: must be a 64-char lowercase hex string")

    # --- AuditEvent fields ---
    if "event_id" in record and not _is_str_in_range(get("event_id"), 8, 128):
        r.add("event_id: must be a string of length 8..128")
    if "event_schema_version" in record:
        v = get("event_schema_version")
        if not (isinstance(v, str) and _SEMVER_RE.match(v)):
            r.add("event_schema_version: must be a semver string")
    if "event_type" in record:
        v = get("event_type")
        if not (isinstance(v, str) and _SCREAM_CASE_RE.match(v) and len(v) <= 127):
            r.add("event_type: must match ^[A-Z][A-Z0-9_]{0,126}$")
    if "actor_module" in record:
        v = get("actor_module")
        if not (isinstance(v, str) and _MODULE_ID_RE.match(v)):
            r.add("actor_module: must match ^[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}$ (null is not allowed)")
    for arr_field in ("subject_refs", "authority_refs_if_relevant", "truth_refs_if_relevant"):
        if arr_field in record:
            _check_refs_array(get(arr_field), arr_field, r)
    if "payload_ref_or_summary" in record:
        v = get("payload_ref_or_summary")
        if not isinstance(v, dict):
            r.add("payload_ref_or_summary: must be an object")
        else:
            has_ref = set(v.keys()) == {"payload_ref"} and _is_str_in_range(v.get("payload_ref"), 1, 256)
            has_summary = set(v.keys()) == {"summary"} and _is_str_in_range(v.get("summary"), 1, 2048)
            if not (has_ref or has_summary):
                r.add(
                    "payload_ref_or_summary: must be exactly {'payload_ref': str} "
                    "or exactly {'summary': str} (oneOf)"
                )
    if "data_classification" in record:
        v = get("data_classification")
        if not (isinstance(v, str) and _SCREAM_CASE_RE.match(v) and len(v) <= 127):
            r.add("data_classification: must match ^[A-Z][A-Z0-9_]{0,126}$")
    if "producer_emitted_at" in record:
        v = get("producer_emitted_at")
        if not (isinstance(v, str) and _DATETIME_RE.match(v)):
            r.add("producer_emitted_at: must be an RFC3339 UTC timestamp ('...Z')")
    if "producer_occurred_at_if_known" in record:
        v = get("producer_occurred_at_if_known")
        if not (isinstance(v, str) and _DATETIME_RE.match(v)):
            r.add("producer_occurred_at_if_known: must be an RFC3339 UTC timestamp ('...Z')")
    if "producer_clock_quality" in record and get("producer_clock_quality") not in _CLOCK_QUALITIES:
        r.add(f"producer_clock_quality: must be one of {sorted(_CLOCK_QUALITIES)}")
    if "producer_signature_ref_if_used" in record and not _is_str_in_range(
        get("producer_signature_ref_if_used"), 1, 256
    ):
        r.add("producer_signature_ref_if_used: must be a string of length 1..256")

    return r
