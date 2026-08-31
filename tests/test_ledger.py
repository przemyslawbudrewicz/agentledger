"""
Tests for NEO-AUD-001, run against the same golden/invalid consumer-owned
fixtures shipped in the R225 spec pack (fixtures/consumers/NEO-AUD-001/).
A copy of the ones this module can meaningfully check lives in
tests/fixtures/ so this package is runnable standalone.

Run with:  python3 -m unittest discover -s tests -v
"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agentledger import AuditLedger, AuditEventRejected  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(*parts: str) -> dict:
    with (FIXTURES / Path(*parts)).open() as fh:
        return json.load(fh)


class GoldenFixturesAreAccepted(unittest.TestCase):
    def test_golden_full_is_accepted(self):
        ledger = AuditLedger()
        entry = ledger.append_event(load("valid", "golden_full.json"))
        self.assertEqual(entry.ledger_sequence, 0)
        self.assertEqual(len(ledger), 1)

    def test_golden_minimal_is_accepted(self):
        ledger = AuditLedger()
        entry = ledger.append_event(load("valid", "golden_minimal.json"))
        self.assertEqual(len(ledger), 1)
        self.assertTrue(ledger.verify_chain())


class InvalidFixturesAreRejected(unittest.TestCase):
    def _assert_rejected(self, filename: str):
        ledger = AuditLedger()
        with self.assertRaises(AuditEventRejected):
            ledger.append_event(load("invalid", filename))
        self.assertEqual(len(ledger), 0, "a rejected record must never be persisted")

    def test_record_digest_mismatch_rejected(self):
        self._assert_rejected("record_digest_mismatch.json")

    def test_schema_hash_mismatch_rejected(self):
        self._assert_rejected("schema_hash_mismatch.json")

    def test_missing_required_field_rejected(self):
        self._assert_rejected("missing_required.json")

    def test_unsupported_version_rejected(self):
        self._assert_rejected("unsupported_version.json")

    def test_wrong_type_rejected(self):
        self._assert_rejected("wrong_type.json")

    def test_unknown_field_rejected(self):
        self._assert_rejected("unknown_field.json")

    def test_null_where_forbidden_rejected(self):
        self._assert_rejected("null_where_forbidden.json")


class HashChainIntegrity(unittest.TestCase):
    def test_sequence_and_chain_are_assigned_by_the_ledger_not_the_producer(self):
        ledger = AuditLedger()
        first = ledger.append_event(load("valid", "golden_full.json"))

        second_record = copy.deepcopy(load("valid", "golden_minimal.json"))
        second_record["record_id"] = "record_00000002"
        second_record["event_id"] = "event_00000002"
        from agentledger import compute_record_digest
        second_record["record_digest"] = compute_record_digest(second_record)
        second = ledger.append_event(second_record)

        self.assertEqual(second.ledger_sequence, first.ledger_sequence + 1)
        self.assertNotEqual(first.ledger_hash, second.ledger_hash)
        self.assertTrue(ledger.verify_chain())

    def test_tamper_is_detected(self):
        ledger = AuditLedger()
        ledger.append_event(load("valid", "golden_full.json"))
        # simulate tampering with stored history directly
        ledger._entries[0].record["event_type"] = "SOMETHING_ELSE"  # type: ignore[index]
        self.assertFalse(
            ledger.verify_chain(),
            "an in-place edit to a stored record must be detected by re-checking "
            "that record's own record_digest, not just the chain of hashes",
        )


class ClockHighWaterMark(unittest.TestCase):
    """latest_timestamp() -- the read-only query F-5's clock-suspect guard
    (see TIMESTAMP_CLOCK_AUDIT.md) is built on: a local, checkable
    high-water mark derived from this ledger's own append-only history,
    with no NTP or external service involved."""

    def test_empty_ledger_has_no_high_water_mark(self):
        self.assertIsNone(AuditLedger().latest_timestamp())

    def test_returns_the_max_created_at_not_the_last_appended(self):
        from agentledger import compute_record_digest

        ledger = AuditLedger()
        first = load("valid", "golden_full.json")  # created_at 2026-08-13T03:40:00Z
        ledger.append_event(first)

        # Appended second but stamped *earlier* -- the high-water mark must
        # still reflect the latest created_at seen, not append order.
        earlier = copy.deepcopy(load("valid", "golden_minimal.json"))
        earlier["record_id"] = "record_00000002"
        earlier["event_id"] = "event_00000002"
        earlier["created_at"] = "2020-01-01T00:00:00Z"
        earlier["record_digest"] = compute_record_digest(earlier)
        ledger.append_event(earlier)

        hwm = ledger.latest_timestamp()
        self.assertIsNotNone(hwm)
        self.assertEqual(hwm.isoformat(), "2026-08-13T03:40:00+00:00")

    def test_reload_from_disk_preserves_the_high_water_mark(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path=str(path))
            ledger.append_event(load("valid", "golden_full.json"))
            reloaded = AuditLedger(path=str(path))
            self.assertEqual(
                reloaded.latest_timestamp().isoformat(), "2026-08-13T03:40:00+00:00"
            )


class Idempotency(unittest.TestCase):
    def test_identical_resubmission_is_a_no_op_replay(self):
        ledger = AuditLedger()
        record = load("valid", "golden_full.json")
        first = ledger.append_event(record)
        second = ledger.append_event(record)  # exact resubmission
        self.assertEqual(first.ledger_sequence, second.ledger_sequence)
        self.assertEqual(len(ledger), 1)

    def test_conflicting_resubmission_is_rejected(self):
        ledger = AuditLedger()
        record = load("valid", "golden_full.json")
        ledger.append_event(record)

        conflicting = copy.deepcopy(record)
        conflicting["event_type"] = "DIFFERENT_EVENT_TYPE"
        from agentledger import compute_record_digest
        conflicting["record_digest"] = compute_record_digest(conflicting)

        with self.assertRaises(AuditEventRejected) as ctx:
            ledger.append_event(conflicting)
        self.assertIn("idempotency conflict", str(ctx.exception))
        self.assertEqual(len(ledger), 1, "the conflicting record must not be persisted")


class Querying(unittest.TestCase):
    def test_query_by_subject_ref_returns_bounded_trace(self):
        ledger = AuditLedger()
        ledger.append_event(load("valid", "golden_full.json"))  # subject_refs: ["task:1"]

        trace = ledger.query(subject_refs=["task:1"])
        self.assertEqual(trace["completeness_state"], "COMPLETE")
        self.assertEqual(trace["correlation_summary"]["event_count"], 1)
        self.assertEqual(trace["ledger_cut_sequence"], 0)

        empty_trace = ledger.query(subject_refs=["task:does-not-exist"])
        self.assertEqual(empty_trace["returned_ledger_range"], {"empty": True})
        self.assertEqual(
            empty_trace["completeness_state"],
            "COMPLETE",
            "no matches in a bounded view is not the same claim as global absence",
        )


class Persistence(unittest.TestCase):
    def test_ledger_reloads_from_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledger = AuditLedger(path)
            ledger.append_event(load("valid", "golden_full.json"))
            self.assertTrue(path.exists())

            reloaded = AuditLedger(path)
            self.assertEqual(len(reloaded), 1)
            self.assertTrue(reloaded.verify_chain())


class BoundaryEnforcement(unittest.TestCase):
    def test_internal_chain_of_thought_is_refused(self):
        ledger = AuditLedger()
        record = copy.deepcopy(load("valid", "golden_full.json"))
        record["data_classification"] = "INTERNAL_CHAIN_OF_THOUGHT"
        from agentledger import compute_record_digest
        record["record_digest"] = compute_record_digest(record)
        with self.assertRaises(AuditEventRejected) as ctx:
            ledger.append_event(record)
        self.assertIn("raw internal reasoning", str(ctx.exception))

    def test_external_truth_claim_requires_truth_refs(self):
        ledger = AuditLedger()
        record = copy.deepcopy(load("valid", "golden_full.json"))
        record["data_classification"] = "EXTERNAL_TRUTH_CLAIM"
        record["truth_refs_if_relevant"] = []
        from agentledger import compute_record_digest
        record["record_digest"] = compute_record_digest(record)
        with self.assertRaises(AuditEventRejected) as ctx:
            ledger.append_event(record)
        self.assertIn("truth_refs_if_relevant", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
