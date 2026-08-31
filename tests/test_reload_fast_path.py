"""
Round-49 reload fast-path tests for NEO-AUD-001's AuditLedger.

append_event() re-reads the whole persisted file on every append (round 27's
cross-process sequence safety). That is O(ledger) per append and made every
turn slower as the shared ledgers grew. Round 49 adds a fast path: when the
file size is unchanged since this instance last loaded/persisted, the
in-memory state is already current and the re-parse is skipped. These tests
lock the fast path in: same-process appends must NOT re-read, while every
real change (another process's row, a truncation, a torn tail) must still be
seen through a full reload.

Run with:  python3 -m unittest discover -s tests -v
"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentledger import AuditLedger, compute_record_digest  # noqa: E402
from agentledger import ledger as ledger_mod  # noqa: E402

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


def _count_iter_json_rows():
    """Wrap ledger_mod._iter_json_rows with a call counter. Returns
    (counter, patcher); counter['calls'] increments per full re-read."""
    real = ledger_mod._iter_json_rows
    counter = {"calls": 0}

    def counting(path):
        counter["calls"] += 1
        return real(path)

    return counter, mock.patch.object(ledger_mod, "_iter_json_rows", counting)


class ReloadFastPathSkipsSameProcessAppends(unittest.TestCase):
    def test_second_and_later_appends_do_not_re_read_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            ledger.append_event(_event(1))
            counter, patcher = _count_iter_json_rows()
            with patcher:
                ledger.append_event(_event(2))
                ledger.append_event(_event(3))
                ledger.append_event(_event(4))
            # The fast path must hold: our own appends change only our own
            # in-memory state, so no full re-parse is needed.
            self.assertEqual(counter["calls"], 0,
                             "same-process appends must skip the full reload")
            self.assertEqual(len(ledger), 4)
            self.assertEqual(ledger._entries[-1].ledger_sequence, 3)

    def test_chain_stays_valid_after_fast_path_appends(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            for n in range(1, 6):
                ledger.append_event(_event(n))
            self.assertTrue(ledger.verify_chain(),
                            "chain must stay valid across fast-path appends")
            self.assertEqual(len(ledger), 5)


class ReloadFastPathStillSeesForeignWrites(unittest.TestCase):
    def test_foreign_row_still_triggers_full_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger_a = AuditLedger(path=path)
            ledger_a.append_event(_event(1))
            # A second process appends a row behind our back.
            ledger_b = AuditLedger(path=path)
            ledger_b.append_event(_event(2))
            counter, patcher = _count_iter_json_rows()
            with patcher:
                entry = ledger_a.append_event(_event(3))
            # The foreign row changed the file size -> full re-read required.
            self.assertEqual(counter["calls"], 1,
                             "a foreign row must still force a full reload")
            # And the re-read must actually see it: sequence continues from b.
            self.assertEqual(entry.ledger_sequence, 2,
                             "sequence must continue after the foreign row")
            self.assertEqual(len(ledger_a), 3)
            self.assertTrue(ledger_a.verify_chain())

    def test_idempotent_replay_of_foreign_row_is_still_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger_a = AuditLedger(path=path)
            ledger_a.append_event(_event(1))
            ledger_b = AuditLedger(path=path)
            replay = _event(2)
            ledger_b.append_event(replay)
            # a resubmits b's row: the reload sees it and returns the existing
            # entry instead of minting a duplicate.
            out = ledger_a.append_event(replay)
            self.assertEqual(out.ledger_sequence, 1)
            self.assertEqual(len(ledger_a), 2)


class ReloadFastPathStillHandlesTornTail(unittest.TestCase):
    def test_torn_tail_after_fast_path_appends_is_quarantined(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=path)
            for n in range(1, 4):
                ledger.append_event(_event(n))
            # Simulate a crash mid-append: partial JSON row with no newline.
            with path.open("ab") as fh:
                fh.write(b'{"ledger_sequence": 3, "ledger_hash": "')
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                # A fresh instance must still load (torn tail quarantined).
                reloaded = AuditLedger(path=path)
            self.assertEqual(len(reloaded), 3,
                             "the torn tail must be quarantined, not loaded")
            self.assertTrue(reloaded.verify_chain())
            # The load that quarantined the torn tail updated the fast-path
            # size bookkeeping to the post-rewrite size, so the next
            # same-process append correctly skips the re-parse (the in-memory
            # state is current) -- never a redundant full reload.
            counter, patcher = _count_iter_json_rows()
            with patcher:
                reloaded.append_event(_event(4))
            self.assertEqual(counter["calls"], 0)
            self.assertEqual(len(reloaded), 4)


if __name__ == "__main__":
    unittest.main()
