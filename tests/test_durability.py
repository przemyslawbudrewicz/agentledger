"""
Durability reproduction tests for NEO-AUD-001's JSON-Lines persistence.

Each of the three owner-decided fixes from LEDGER_DURABILITY_DESIGN.md
(Options 2 + 3 + 7) is proven fail-first against the pre-fix code and
locked green after:

1. One-syscall row append (Option 2): appending one event is exactly one
   write() call — payload and newline go out together, so a crash cannot
   leave a complete payload without its newline and two writers cannot
   interleave two separate writes.
2. Load-time tail repair (Option 3): a torn FINAL line (a crash mid-append)
   is quarantined to <ledger>.corrupt-<ts> and skipped with a warning —
   the ledger still loads; a corrupt line in the middle of the file still
   hard-fails (that is genuine corruption, not a torn tail).
3. Out-of-band AUD-001 tail marker (Option 7): verify_chain() detects a
   silently truncated tail — the chain alone cannot, because a truncated
   file is a perfectly valid chain prefix — while a marker that is merely
   behind the file (a crash between a row write and its marker update) is
   benign and refreshes on the next append.

Run with:  python3 -m unittest discover -s tests -v
"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentledger import AuditLedger, compute_record_digest  # noqa: E402
from agentledger.ledger import _path_lock, _quarantine_torn_tail  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(*parts: str) -> dict:
    with (FIXTURES / Path(*parts)).open(encoding="utf-8") as fh:
        return json.load(fh)


def _event(n: int) -> dict:
    """A distinct valid AuditEvent (fresh ids + recomputed digest)."""
    record = copy.deepcopy(load("valid", "golden_minimal.json"))
    record["record_id"] = f"record_{n:08d}"
    record["event_id"] = f"event_{n:08d}"
    record["record_digest"] = compute_record_digest(record)
    return record


# -- shared instrumentation: count write() calls per file open ----------------
_REAL_PATH_OPEN = Path.open


class _CountingWrite:
    """Wraps a file object, counting write() calls (the fix-1 gate)."""

    def __init__(self, fh):
        self._fh = fh
        self.write_calls = 0

    def write(self, s):
        self.write_calls += 1
        return self._fh.write(s)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return self._fh.__exit__(*exc)

    def __getattr__(self, name):
        return getattr(self._fh, name)


def _counting_open():
    """Patch Path.open with a real function (so descriptor binding passes
    the path through) that wraps every returned file in a write counter.
    Only write-mode opens are tracked (read opens are excluded). Returns
    (writes, patcher)."""
    writes: list = []

    def counting_open(path, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        wrapped = _CountingWrite(_REAL_PATH_OPEN(path, *args, **kwargs))
        if mode in ("a", "ab", "w", "wb"):
            writes.append(wrapped)
        return wrapped

    return writes, mock.patch.object(Path, "open", counting_open)


class OneSyscallRowAppend(unittest.TestCase):
    def test_appending_an_event_is_a_single_write_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            writes, patcher = _counting_open()
            with patcher:
                ledger = AuditLedger(path=path)
                ledger.append_event(load("valid", "golden_full.json"))
            self.assertTrue(writes)
            self.assertTrue(
                all(w.write_calls == 1 for w in writes),
                "every row append must be a single write() call (payload + "
                "newline together), got "
                f"{[w.write_calls for w in writes]}",
            )


class LoadTimeTailRepair(unittest.TestCase):
    def test_torn_final_line_is_quarantined_and_reload_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(load("valid", "golden_full.json"))
            self.assertEqual(len(ledger), 1)

            # Simulate a crash mid-append: a partial JSON row with no newline.
            with path.open("ab") as fh:
                fh.write(b'{"ledger_sequence": 1, "ledger_hash": "')

            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                reloaded = AuditLedger(path=path)
            self.assertEqual(
                len(reloaded), 1,
                "the complete row must survive; only the torn tail is discarded")
            self.assertTrue(reloaded.verify_chain())

            quarantined = sorted(path.parent.glob(path.name + ".corrupt-*"))
            self.assertEqual(
                len(quarantined), 1,
                "the torn bytes must be preserved out-of-band, not lost")
            self.assertIn(b'"ledger_sequence"', quarantined[0].read_bytes())
            self.assertFalse(
                path.read_bytes().endswith(b'"ledger_hash": "'),
                "the ledger must no longer end with the torn bytes")
            self.assertIn("torn tail", err.getvalue())

    def test_corrupt_line_in_the_middle_still_hard_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(load("valid", "golden_full.json"))
            ledger.append_event(_event(2))
            rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            self.assertEqual(len(rows), 2)
            # Rebuild the file as [good, TORN, good]: a corrupt line with a
            # newline of its own, so it is NOT the final line.
            path.write_text(
                rows[0] + "\n" + '{"ledger_sequence": 9, "ledger_hash": "' + "\n" + rows[1] + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(json.JSONDecodeError):
                AuditLedger(path=path)


class QuarantineConcurrentWriterRace(unittest.TestCase):
    """Round 48: the real-ledger incident. The torn-tail quarantine's
    read->rewrite ran outside the cross-process path lock, so rows another
    process committed between the read and the rewrite were lost when the
    rewrite truncated from the stale snapshot (verify_chain() reported
    False — the tail marker certified seq 39651 while the file only
    reached 39638). The quarantine now re-reads under the lock and cuts
    ONLY a line that is still a genuinely torn tail — never a committed
    row."""

    def test_quarantine_cuts_only_a_genuinely_torn_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(_event(1))
            # Crash mid-append: a partial JSON row with no newline.
            torn = b'{"ledger_sequence": 1, "ledger_hash": "deadbeef'
            with path.open("ab") as fh:
                fh.write(torn)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                _quarantine_torn_tail(
                    path, torn.decode(), json.JSONDecodeError("torn", "", 0))
            quarantined = sorted(path.parent.glob(path.name + ".corrupt-*"))
            self.assertEqual(len(quarantined), 1,
                             "the genuinely torn tail is still quarantined")
            self.assertEqual(quarantined[0].read_bytes(), torn)
            self.assertFalse(path.read_bytes().endswith(torn),
                             "the torn bytes must be cut out of the ledger")
            reloaded = AuditLedger(path=path)
            self.assertEqual(len(reloaded), 1,
                             "the complete row must survive; only the torn "
                             "tail is discarded")
            self.assertTrue(reloaded.verify_chain())

    def test_quarantine_never_loses_a_row_a_concurrent_writer_committed(self):
        """The incident state: a torn line with rows another process
        committed AFTER it (the pre-fix quarantine's stale snapshot then
        rewrote the file from BEFORE those rows, silently dropping them).
        The fixed quarantine must not touch the file when its actual tail
        is a committed row."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(_event(1))
            ledger.append_event(_event(2))
            rows = [ln for ln in path.read_text(encoding="utf-8").splitlines()
                    if ln.strip()]
            # Rebuild as [row0, TORN, row1]: the torn line in the middle, a
            # complete committed row after it.
            torn = '{"ledger_sequence": 9, "ledger_hash": "deadbeef'
            path.write_text(
                rows[0] + "\n" + torn + "\n" + rows[1] + "\n",
                encoding="utf-8",
            )
            before = path.read_bytes()
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                _quarantine_torn_tail(
                    path, torn, json.JSONDecodeError("torn", "", 0))
            # The committed row must survive: no rewrite happened at all.
            self.assertEqual(
                path.read_bytes(), before,
                "a quarantine must never rewrite the file when its actual "
                "tail is a committed row (pre-fix this cut the file from "
                "the stale torn line and silently lost the committed row)")
            self.assertEqual(
                len(list(path.parent.glob(path.name + ".corrupt-*"))), 0,
                "no corruption file: nothing was quarantined")
            # And the remaining middle-line corruption is SURFACED, never
            # silently rewritten away.
            with self.assertRaises(json.JSONDecodeError):
                AuditLedger(path=path)

    def test_construction_load_takes_the_cross_process_lock(self):
        """A construction load must serialize against a concurrent writer
        (round 48): while another holder owns the path lock, a fresh
        AuditLedger(path) blocks instead of reading/quarantining mid-
        append."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            AuditLedger(path=path).append_event(_event(1))
            lock = _path_lock(path)
            done = threading.Event()
            errors: list = []

            def construct() -> None:
                try:
                    AuditLedger(path=path)
                except Exception as exc:  # pragma: no cover - failure path
                    errors.append(exc)
                finally:
                    done.set()

            worker = threading.Thread(target=construct)
            with lock:
                worker.start()
                self.assertFalse(
                    done.wait(0.3),
                    "a construction load must block on the path lock a "
                    "concurrent writer holds, not read mid-append")
            self.assertTrue(
                done.wait(3.0),
                "the load must complete once the lock is released")
            worker.join(3.0)
            self.assertEqual(errors, [])


class OutOfBandTailMarker(unittest.TestCase):
    def test_silent_tail_truncation_is_detected_by_verify_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(load("valid", "golden_full.json"))
            ledger.append_event(_event(2))
            ledger.append_event(_event(3))
            self.assertTrue(ledger.verify_chain())

            # Simulate silent tail loss: the last row never made it to disk.
            # A truncated file is still a perfectly valid chain prefix, so
            # pre-fix verify_chain() reports it clean — exactly the hole the
            # out-of-band tail marker closes.
            rows = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            path.write_text("\n".join(rows[:-1]) + "\n", encoding="utf-8")

            self.assertFalse(
                ledger.verify_chain(),
                "the still-open ledger must detect the loss against its marker")
            reloaded = AuditLedger(path=path)
            self.assertFalse(
                reloaded.verify_chain(),
                "a silently truncated ledger must not verify clean — the "
                "marker certifies the lost tail; pre-fix this returned True")

            marker = Path(str(path) + ".tail")
            self.assertTrue(marker.exists(), "the tail marker must be persisted")
            marker_obj = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(marker_obj["ledger_sequence"], 2)

    def test_marker_behind_the_file_is_benign(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(load("valid", "golden_full.json"))
            ledger.append_event(_event(2))

            # Simulate a crash between a row write and its marker update:
            # the row lands, the marker does not (an unmarked tail row).
            with mock.patch.object(ledger, "_write_tail_marker"):
                ledger.append_event(_event(3))

            self.assertTrue(
                ledger.verify_chain(),
                "a marker behind the file is a torn append, not a truncation "
                "— the certified prefix is intact and the next append "
                "refreshes the marker")
            reloaded = AuditLedger(path=path)
            self.assertTrue(reloaded.verify_chain())

            # The next append refreshes the marker; everything stays consistent.
            ledger.append_event(_event(4))
            self.assertTrue(ledger.verify_chain())


if __name__ == "__main__":
    unittest.main()
