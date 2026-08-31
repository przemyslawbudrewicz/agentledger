"""
Canonical JSON serialization and digest helpers.

The RecordEnvelope contract (urn:neo:contract:RecordEnvelope:1.0.0) requires every
record to be content-addressable: ``record_digest`` must equal SHA-256 over the
record's JCS-1 canonical JSON with ``record_digest`` itself omitted.

This module implements a canonicalization profile sufficient for records that
never contain floats (Neo's schemas only use strings, ints, bools, null, arrays
and objects), which covers every contract in this pack. It intentionally does
NOT depend on any third-party library.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


def canonicalize(value: Any) -> str:
    """Serialize ``value`` to canonical JSON text (sorted keys, no insignificant
    whitespace, UTF-8 safe)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_record_digest(record: Mapping[str, Any]) -> str:
    """Compute the record_digest a well-formed record MUST carry: SHA-256 of the
    canonical JSON of the record with ``record_digest`` omitted."""
    stripped = {k: v for k, v in record.items() if k != "record_digest"}
    return sha256_hex(canonicalize(stripped))


def verify_record_digest(record: Mapping[str, Any]) -> bool:
    """True iff record['record_digest'] matches the value computed from the rest
    of the record."""
    claimed = record.get("record_digest")
    if not isinstance(claimed, str):
        return False
    return claimed == compute_record_digest(record)
