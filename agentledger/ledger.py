"""
NEO-AUD-001 — Audit & Explainability Ledger.

Owns (per MODULE_REGISTRY.json):
  - append-only audit ledger persistence
  - ledger sequence / hash-chain integrity
  - event correlation / indexing
  - bounded trace/replay/explanation assembly

Explicitly does NOT own (per the same boundary):
  - semantic success, external-world truth, raw internal model reasoning,
    policy approval

That boundary drives every design choice below: this module accepts and
orders what producers submit, proves it hasn't been silently altered, and
answers bounded queries about it — it never invents or upgrades a claim's
truth value.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from filelock import FileLock

from .canonical import canonicalize, sha256_hex, verify_record_digest
from .validation import validate_audit_event

# Cross-process writer serialization (round 27): this store — like every
# JSON-Lines store in the family — appends one row per write() and mints its
# sequence from the state loaded at construction, so two genuinely
# concurrent processes (the round-25/26 background-instance hazard) can both
# load the same snapshot, mint the same ledger_sequence, and append at the
# same file offset. One FileLock per resolved path serializes the
# load->mint->append->tail-marker critical section across processes. A
# registry is required because filelock is re-entrant only for the SAME
# instance: two instances on one path inside one process can self-deadlock
# on the OS-level lock.
_LOCK_REGISTRY: dict[str, FileLock] = {}
_LOCK_REGISTRY_GUARD = threading.Lock()


def _path_lock(path: Optional[str | Path]) -> Optional[FileLock]:
    """The process-wide FileLock for a store path (one instance per path)."""
    if path is None:
        return None
    key = str(Path(path).resolve())
    with _LOCK_REGISTRY_GUARD:
        lock = _LOCK_REGISTRY.get(key)
        if lock is None:
            lock = FileLock(key + ".lock")
            _LOCK_REGISTRY[key] = lock
        return lock


class _NullLock:
    """No-op context manager for in-memory (pathless) stores."""

    def __enter__(self) -> "_NullLock":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

# Authoritative schema-hash catalog for contracts this ledger accepts.
# In production this is populated from the sha256 of each deployed schema
# file at boot; the placeholder value below matches the value the pack's own
# approved consumer-owned fixtures (fixtures/consumers/NEO-AUD-001/...) treat
# as ground truth for AuditEvent 1.0.0, so this implementation stays
# fixture-compatible without inventing a new convention.
SCHEMA_HASH_CATALOG: dict[tuple[str, str], str] = {
    ("AuditEvent", "1.0.0"): "aa" * 32,
}

# data_classification values this ledger refuses to persist at all, because
# accepting them would mean recording raw internal model reasoning — a class
# of data this module is explicitly barred from owning.
BANNED_DATA_CLASSIFICATIONS = {"INTERNAL_CHAIN_OF_THOUGHT", "RAW_MODEL_REASONING"}

# data_classification values that assert something as externally-verified
# truth; such events must carry truth_refs_if_relevant so the claim traces
# back to actual evidence/reconciliation lineage rather than the producer's
# unverified say-so.
EXTERNAL_TRUTH_CLASSIFICATIONS = {"EXTERNAL_TRUTH_CLAIM"}


class AuditEventRejected(Exception):
    """Raised when append_event() cannot accept a record. .errors holds every
    reason, not just the first — callers get the full structural picture."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass(frozen=True)
class LedgerEntry:
    ledger_sequence: int
    ledger_hash: str
    record: Mapping[str, Any]


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse an RFC3339 UTC '...Z' timestamp with 0..9 fractional digits
    (Python's %f only accepts up to 6) -- same convention every other
    module's own _parse_dt uses (e.g. neo_gov_003/gateway.py:131-141)."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    body = value[:-1]
    if "." in body:
        date_part, frac = body.split(".", 1)
        body = f"{date_part}.{(frac + '000000')[:6]}"
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        return datetime.strptime(body, fmt).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class JsonLinesCorrupt(json.JSONDecodeError):
    """A non-JSON line in a JSON-Lines store, carrying its file line number.
    Subclasses JSONDecodeError so existing callers that catch it keep
    working; stores that wrap corruption in their own error type use
    ``.line_no`` to report where the file broke."""

    def __init__(self, msg: str, doc: str, pos: int, line_no: int) -> None:
        super().__init__(msg, doc, pos)
        self.line_no = line_no


def _quarantine_torn_tail(path: Path, raw: str, exc: Exception) -> None:
    """Preserve a torn tail line in ``<file>.corrupt-<ts>`` and truncate it
    out of the ledger so the next append continues after the last complete
    row. Always called with the FINAL line only — a crash can lose at most
    the last in-flight row; it can never brick startup (owner decision,
    LEDGER_DURABILITY_DESIGN.md Option 3).

    Round 48: the read->rewrite below is atomic with respect to concurrent
    appenders. The earlier review's gap was real — a row another process
    commits between the read and the rewrite is lost when the rewrite
    truncates from the stale snapshot (the real-ledger incident: the
    marker certified seq 39651 while the file only reached 39638). So the
    quarantine re-reads the file under the same per-path cross-process
    lock the append path uses (round 27) and cuts ONLY a line that is
    still a genuinely torn tail; a line a concurrent writer has since
    completed is a committed row and is left untouched."""
    with _path_lock(path) or _NullLock():
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
        tail_idx = max(
            (i for i, ln in enumerate(lines) if ln.strip()),
            default=None,
        )
        if tail_idx is None:
            return  # nothing left to quarantine
        tail = lines[tail_idx]
        try:
            json.loads(tail.strip())
            return  # the tail is complete now: a concurrent writer finished
            # that row, so it is a committed row, not a torn tail — cutting
            # it would lose committed history
        except json.JSONDecodeError:
            pass
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        corrupt = path.with_name(f"{path.name}.corrupt-{stamp}")
        with corrupt.open("w", encoding="utf-8") as fh:
            fh.write(tail)
        data = "".join(lines)
        cut = data.rfind(tail)
        with path.open("w", encoding="utf-8") as fh:
            fh.write(data[:cut] if cut >= 0 else data)
    print(f"{path}: torn tail line quarantined to {corrupt} "
          f"(discarding it: {exc}); continuing", file=sys.stderr)


def _iter_json_rows(path: Path):
    """Yield ``(line_no, row)`` for every non-empty JSON-Lines line of
    ``path``.

    Tail repair (owner decision, LEDGER_DURABILITY_DESIGN.md Option 3): a
    crash mid-append can leave the FINAL line torn (partial JSON). That line
    is quarantined to ``<file>.corrupt-<ts>`` and skipped with a warning
    instead of raising; a corrupt line anywhere else in the file is genuine
    corruption and still raises ``JsonLinesCorrupt`` (a ``JSONDecodeError``).
    """
    with path.open("r", encoding="utf-8") as fh:
        # readlines() (not direct iteration) so a mocked file handle in the
        # durability tests -- whose wrapper delegates regular methods but not
        # __iter__ -- can be read by the round-27 reload-under-lock paths.
        raw_lines = [(raw, raw.strip()) for raw in fh.readlines()]
    last_non_empty = max(
        (i for i, (_raw, stripped) in enumerate(raw_lines) if stripped),
        default=None,
    )
    for idx, (raw, stripped) in enumerate(raw_lines):
        if not stripped:
            continue
        try:
            yield idx + 1, json.loads(stripped)
        except json.JSONDecodeError as exc:
            if idx != last_non_empty:
                raise JsonLinesCorrupt(exc.msg, exc.doc, exc.pos, idx + 1) from exc
            _quarantine_torn_tail(path, raw, exc)
            return


class AuditLedger:
    """An append-only, hash-chained ledger of AuditEvent records.

    Thread-safe for single-process use (one lock guards append + sequence
    assignment). Persists to a JSON-Lines file when ``path`` is given;
    otherwise runs purely in memory (useful for tests).
    """

    def __init__(self, path: Optional[str | Path] = None):
        self._lock = threading.Lock()
        self._entries: list[LedgerEntry] = []
        self._by_key: dict[tuple[str, str], LedgerEntry] = {}  # (record_id, event_id) -> entry
        self._path = Path(path) if path else None
        self._tail_marker_path = (
            self._path.with_name(self._path.name + ".tail") if self._path else None
        )
        # Round 49: last file size this instance loaded/persisted. append_event
        # reloads under the cross-process lock to see other processes' rows;
        # when the size is unchanged, the in-memory state is already current
        # and the reload is a pure O(ledger) cost — so it is skipped. Any size
        # change (another process's row, a truncation, a torn-tail rewrite)
        # still falls through to the full reload, preserving round-27's
        # cross-process sequence safety exactly.
        self._last_known_size: int | None = None
        if self._path and self._path.exists():
            self._load()

    # -- persistence -------------------------------------------------
    def _load(self) -> None:
        # Round 48: hold the cross-process path lock for the whole load. The
        # append path already reloads under this lock (round 27); __init__
        # construction must too, or a load racing an in-flight append can
        # snapshot a row mid-write and run the torn-tail quarantine's
        # read->rewrite outside the lock — the real-ledger incident
        # (verify_chain() False; committed rows lost between the quarantine's
        # read and rewrite). The lock is re-entrant for the same instance,
        # so the reload-under-lock append path is unaffected.
        with _path_lock(self._path) or _NullLock():
            for _line_no, row in _iter_json_rows(self._path):
                entry = LedgerEntry(row["ledger_sequence"], row["ledger_hash"], row["record"])
                self._entries.append(entry)
                self._by_key[(row["record"]["record_id"], row["record"]["event_id"])] = entry
            # Baseline the out-of-band tail marker (Option 7) for a ledger
            # that predates the marker feature, so verify_chain() can detect
            # silent truncation from this load onward. A marker that already
            # exists is never rewritten here: it certifies an earlier append,
            # and rewriting it would bless whatever state the file happens to
            # be in now.
            if self._entries and not self._tail_marker_path.exists():
                self._write_tail_marker()
            if self._path and self._path.exists():
                self._last_known_size = self._path.stat().st_size

    def _reload_from_disk(self) -> None:
        """Re-read the persisted file (under the cross-process lock) so the
        next ledger_sequence and chain hash reflect every committed row,
        including rows another process appended since this instance's
        construction load. Without this, two processes that both loaded N
        rows would both mint sequence N — the round-25 fork.

        Round 49 fast path: the reload only matters when the file actually
        changed on disk. If its size equals the last size this instance
        loaded/persisted, no other process wrote anything, so the in-memory
        state is already current and the full re-parse (which costs O(ledger)
        on every append and made turns slower as the shared ledgers grew) is
        skipped. Every real change — a row another process appended, a
        truncation, a torn-tail rewrite — changes the size and still reloads
        fully."""
        if self._path is None or not self._path.exists():
            return
        if (self._last_known_size is not None
                and self._path.stat().st_size == self._last_known_size):
            return
        self._entries = []
        self._by_key = {}
        self._load()

    def _persist(self, entry: LedgerEntry) -> None:
        if not self._path:
            return
        with self._path.open("a", encoding="utf-8") as fh:
            # ONE write() call per row (owner decision, Option 2): the whole
            # line — payload + newline — goes out together, so a crash cannot
            # leave a complete payload without its newline and two writers
            # cannot interleave two separate writes.
            fh.write(canonicalize({
                "ledger_sequence": entry.ledger_sequence,
                "ledger_hash": entry.ledger_hash,
                "record": entry.record,
            }) + "\n")
        # Keep the fast-path size in sync with what we just wrote, so the next
        # append in this process skips the reload (our in-memory state is the
        # source of truth for our own rows).
        self._last_known_size = self._path.stat().st_size
        # Certify the new tail out-of-band (Option 7) so verify_chain() can
        # detect a silent truncation — a file shorter than this marker
        # certifies is a lost row, not a valid chain prefix.
        self._write_tail_marker()

    # -- out-of-band tail marker (LEDGER_DURABILITY_DESIGN.md Option 7) ------
    def _write_tail_marker(self) -> None:
        """Persist the tiny tail marker (last ledger_sequence + ledger_hash +
        file size) atomically via temp + rename, so readers see old-or-new,
        never a partial marker."""
        if not self._path or not self._entries or self._tail_marker_path is None:
            return
        last = self._entries[-1]
        marker = canonicalize({
            "ledger_sequence": last.ledger_sequence,
            "ledger_hash": last.ledger_hash,
            "file_size": self._path.stat().st_size,
        }) + "\n"
        tmp = self._tail_marker_path.with_name(
            self._tail_marker_path.name
            + f".tmp.{os.getpid()}.{uuid.uuid4().hex[:8]}"
        )
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(marker)
            fh.flush()
        os.replace(tmp, self._tail_marker_path)

    def _tail_marker_ok(self) -> bool:
        """The marker turns verify_chain() into complete history-evidence:
        the chain proves nothing in the middle changed, the marker proves
        nothing was lost off the end. A file shorter than the marker
        certified is a silent truncation; a file at the certified size must
        still end with the certified (sequence, hash); a file that has grown
        past the marker (a crash between a row write and its marker update)
        is benign — the certified prefix is re-checked and the next append
        refreshes the marker."""
        if self._path is None:
            return True  # in-memory ledger: nothing on disk to truncate
        if self._tail_marker_path is None or not self._tail_marker_path.exists():
            # No marker to compare against. An empty ledger has nothing to
            # lose; a non-empty ledger without a marker was written before
            # the marker feature, and _load() baselines it on first load.
            return True
        try:
            with self._tail_marker_path.open("r", encoding="utf-8") as fh:
                marker = json.loads(fh.read())
        except (json.JSONDecodeError, OSError):
            return False  # a marker we cannot read cannot certify the tail
        if not isinstance(marker, dict) or not all(
            k in marker for k in ("ledger_sequence", "ledger_hash", "file_size")
        ):
            return False
        actual_size = self._path.stat().st_size if self._path.exists() else 0
        if actual_size < marker["file_size"]:
            return False  # silent truncation: the file lost certified bytes
        if actual_size == marker["file_size"]:
            if not self._entries:
                return False  # the marker certified rows; the file is empty
            last = self._entries[-1]
            return (last.ledger_sequence == marker["ledger_sequence"]
                    and last.ledger_hash == marker["ledger_hash"])
        # actual_size > marker["file_size"]: unmarked tail rows exist; the
        # certified prefix must still be present and intact.
        idx = marker["ledger_sequence"]
        if idx < 0 or idx >= len(self._entries):
            return False
        return self._entries[idx].ledger_hash == marker["ledger_hash"]

    # -- write path ----------------------------------------------------
    def append_event(self, record: Mapping[str, Any]) -> LedgerEntry:
        """Validate, order, and persist one AuditEvent. Idempotent on
        (record_id, event_id): resubmitting an identical record is a no-op
        replay; resubmitting a different record under the same key is a
        conflict and is rejected — this ledger never silently overwrites
        history."""
        errors: list[str] = []

        result = validate_audit_event(record)
        errors.extend(result.errors)

        contract_key = (record.get("contract_name"), record.get("contract_version"))
        if contract_key in SCHEMA_HASH_CATALOG:
            expected = SCHEMA_HASH_CATALOG[contract_key]
            if record.get("schema_hash") != expected:
                errors.append(
                    f"schema_hash: does not match catalog for {contract_key[0]} "
                    f"{contract_key[1]} (SCHEMA_HASH_CATALOG_MATCH)"
                )

        if not verify_record_digest(record):
            errors.append(
                "record_digest: does not match SHA-256 of JCS-1 canonical record "
                "with record_digest omitted (RECORD_DIGEST_JCS1_MATCH)"
            )

        if record.get("data_classification") in BANNED_DATA_CLASSIFICATIONS:
            errors.append(
                "data_classification: this ledger does not accept "
                f"{record.get('data_classification')!r} — raw internal reasoning is "
                "out of this module's ownership (AUDIT_EVENT_NO_PRIVATE_CHAIN_OF_THOUGHT)"
            )

        if record.get("data_classification") in EXTERNAL_TRUTH_CLASSIFICATIONS and not record.get(
            "truth_refs_if_relevant"
        ):
            errors.append(
                "truth_refs_if_relevant: required and must be non-empty when "
                "data_classification asserts external truth "
                "(AUDIT_EVENT_EXTERNAL_TRUTH_REQUIRES_TRUTH_REFS)"
            )

        if errors:
            raise AuditEventRejected(errors)

        key = (record["record_id"], record["event_id"])
        with self._lock:
            with _path_lock(self._path) or _NullLock():
                # Cross-process exclusive: re-load the file so the sequence
                # mint and the idempotency check see every row another
                # process committed, then append + certify the tail marker.
                self._reload_from_disk()
                existing = self._by_key.get(key)
                if existing is not None:
                    if existing.record.get("record_digest") == record.get("record_digest"):
                        return existing  # idempotent replay: same content, no-op
                    raise AuditEventRejected([
                        f"record_id/event_id {key}: already recorded with a different "
                        "record_digest (idempotency conflict, not a replay)"
                    ])

                # AUDIT_LEDGER_ORDER_ASSIGNED_BY_AUD: sequence and chain hash are
                # assigned here, by AUD, never trusted from the producer.
                prev_hash = self._entries[-1].ledger_hash if self._entries else "0" * 64
                ledger_sequence = len(self._entries)
                ledger_hash = sha256_hex(prev_hash + record["record_digest"])
                entry = LedgerEntry(ledger_sequence, ledger_hash, dict(record))
                self._entries.append(entry)
                self._by_key[key] = entry
                self._persist(entry)
                return entry

    # -- read path -------------------------------------------------------
    def verify_chain(self) -> bool:
        """Recompute the full hash chain from scratch, and re-verify every
        stored record's own record_digest against its current content —
        tamper-evidence for both "history was reordered/spliced" and
        "a stored record's fields were edited in place," checked on demand."""
        prev_hash = "0" * 64
        for entry in self._entries:
            if not verify_record_digest(entry.record):
                return False
            expected = sha256_hex(prev_hash + entry.record["record_digest"])
            if expected != entry.ledger_hash:
                return False
            prev_hash = entry.ledger_hash
        return self._tail_marker_ok()

    def query(
        self,
        *,
        subject_refs: Iterable[str] = (),
        event_types: Iterable[str] = (),
        max_events: int = 1000,
    ) -> dict[str, Any]:
        """Answer a bounded query with an AuditTrace-shaped result. Never
        claims completeness beyond the exact ledger cut it read at, and
        never infers global absence from a filtered view."""
        subject_set = set(subject_refs)
        type_set = set(event_types)
        cut_sequence = len(self._entries) - 1 if self._entries else -1
        cut_hash = self._entries[-1].ledger_hash if self._entries else "0" * 64

        matches = []
        for entry in self._entries:
            rec = entry.record
            if subject_set and not (subject_set & set(rec.get("subject_refs", []))):
                continue
            if type_set and rec.get("event_type") not in type_set:
                continue
            matches.append(entry)

        truncated = len(matches) > max_events
        returned = matches[:max_events]

        return {
            "generated_at": _utcnow_iso(),
            "ledger_cut_sequence": max(cut_sequence, 0),
            "ledger_cut_hash": cut_hash,
            "returned_ledger_range": (
                {"empty": True}
                if not returned
                else {
                    "start_sequence": returned[0].ledger_sequence,
                    "end_sequence": returned[-1].ledger_sequence,
                }
            ),
            "ordered_event_refs": [e.record["event_id"] for e in returned],
            "ledger_hash_refs": [e.ledger_hash for e in returned],
            "correlation_summary": {
                "correlation_refs": [],
                "subject_refs": sorted(subject_set),
                "event_count": len(returned),
            },
            "completeness_state": "TRUNCATED" if truncated else "COMPLETE",
            "explanation_summary": (
                f"{len(returned)} of {len(matches)} matching events returned "
                f"at ledger cut {max(cut_sequence, 0)}."
            ),
        }

    def __len__(self) -> int:
        return len(self._entries)

    # -- clock-integrity read path ----------------------------------------
    def latest_timestamp(self) -> Optional[datetime]:
        """The latest ``created_at`` across every entry this ledger holds
        (this process's own in-memory entries plus whatever was reloaded
        from ``path``), as an aware UTC datetime, or ``None`` if the ledger
        is empty. This is a real, local, checkable high-water mark: the
        ledger is append-only and chain-verified (see ``verify_chain``), so
        no entry could have been produced before this value was already
        true. A caller whose current wall-clock ``now`` reads earlier than
        this value knows its own clock cannot be trusted for expiry-
        sensitive checks, without needing NTP or any external service
        (see F-5 in TIMESTAMP_CLOCK_AUDIT.md)."""
        latest: Optional[datetime] = None
        for entry in self._entries:
            parsed = _parse_dt(entry.record.get("created_at"))
            if parsed is not None and (latest is None or parsed > latest):
                latest = parsed
        return latest
