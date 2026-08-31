"""
Build a valid AuditEvent without hand-assembling the envelope.

The `AuditEvent` contract this ledger enforces is deliberately strict: 22
required fields, a closed shape, two content digests and a canonicalisation
profile. That strictness is the point — it is what makes a stored record
independently checkable months later — but it makes the first five minutes
with the library harder than they need to be.

`make_event()` fills in everything that can be derived (the contract
constants, the timestamps, the identifiers, the schema hash, and both
digests) and leaves the caller with the handful of fields that actually carry
meaning: what happened, who did it, what it was about. The result is a plain
dict that `AuditLedger.append_event()` accepts, and that `validate_audit_event`
independently agrees is well-formed — this helper is a convenience, never a
bypass.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence

from .canonical import compute_record_digest, sha256_hex

# Imported lazily-by-name to keep the module graph one-directional
# (events -> ledger is fine; ledger never imports events).
from .ledger import SCHEMA_HASH_CATALOG

__all__ = ["make_event"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id(prefix: str) -> str:
    # record_id / event_id must be 8..128 chars; a prefixed uuid4 hex is 37.
    return f"{prefix}_{uuid.uuid4().hex}"


def make_event(
    event_type: str,
    actor: str,
    *,
    summary: Optional[str] = None,
    payload_ref: Optional[str] = None,
    subject_refs: Sequence[str] = (),
    truth_refs: Sequence[str] = (),
    authority_refs: Sequence[str] = (),
    data_classification: str = "OWNER_PRIVATE",
    producer: Optional[str] = None,
    correlation_ids: Iterable[Mapping[str, str]] = (),
    provenance: Iterable[Mapping[str, str]] = (),
    payload_digest: Optional[str] = None,
    occurred_at: Optional[str] = None,
    clock_quality: str = "SYNCHRONIZED",
    record_id: Optional[str] = None,
    event_id: Optional[str] = None,
    created_at: Optional[str] = None,
) -> dict[str, Any]:
    """Return a complete, digest-correct AuditEvent dict.

    `event_type` and `data_classification` are SCREAMING_SNAKE labels you
    choose (e.g. `TOOL_CALL`, `POLICY_DECISION`). `actor` is the component
    that did the thing, as `VENDOR-COMPONENT-NNN` (e.g. `ACME-AGENT-001`);
    `producer` is the component writing the record, and defaults to `actor`.

    Exactly one of `summary` or `payload_ref` must be given: a short
    human-readable line, or a pointer to the payload held elsewhere. The
    ledger stores the pointer or the summary — never a payload it was not
    given ownership of.

    `payload_digest` should be the SHA-256 of the real payload when you have
    it. When omitted it is derived from the summary or ref, which keeps the
    record structurally valid and self-consistent but says nothing about a
    payload the ledger never saw.
    """
    if (summary is None) == (payload_ref is None):
        raise ValueError("make_event: pass exactly one of summary= or payload_ref=")

    payload = {"summary": summary} if summary is not None else {"payload_ref": payload_ref}
    now = created_at or _now_iso()

    record: dict[str, Any] = {
        "contract_name": "AuditEvent",
        "contract_version": "1.0.0",
        "record_id": record_id or _new_id("record"),
        "created_at": now,
        "producer_module_id": producer or actor,
        "correlation_ids": [dict(c) for c in correlation_ids],
        "provenance": [dict(p) for p in provenance],
        "schema_hash": SCHEMA_HASH_CATALOG[("AuditEvent", "1.0.0")],
        "digest_algorithm": "SHA-256",
        "canonicalization_profile": "JCS-1",
        "event_id": event_id or _new_id("event"),
        "event_schema_version": "1.0.0",
        "event_type": event_type,
        "actor_module": actor,
        "subject_refs": list(subject_refs),
        "authority_refs_if_relevant": list(authority_refs),
        "truth_refs_if_relevant": list(truth_refs),
        "payload_ref_or_summary": payload,
        "payload_digest": payload_digest or sha256_hex(summary if summary is not None else payload_ref),
        "data_classification": data_classification,
        "producer_emitted_at": now,
        "producer_clock_quality": clock_quality,
    }
    if occurred_at is not None:
        record["producer_occurred_at_if_known"] = occurred_at

    record["record_digest"] = compute_record_digest(record)
    return record
