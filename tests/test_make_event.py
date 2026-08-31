"""make_event() must produce records the ledger and the validator both accept
on their own terms — the helper is a convenience, never a validation bypass."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from agentledger import (
    AuditEventRejected,
    AuditLedger,
    make_event,
    validate_audit_event,
    verify_record_digest,
)


def test_minimal_event_is_valid_and_self_consistent():
    ev = make_event("TOOL_CALL", "ACME-AGENT-001", summary="called the refunds API")
    assert validate_audit_event(ev).ok, validate_audit_event(ev).errors
    assert verify_record_digest(ev)


def test_event_appends_to_a_real_ledger(tmp_path):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    entry = ledger.append_event(
        make_event(
            "TOOL_CALL",
            "ACME-AGENT-001",
            summary="called the refunds API",
            subject_refs=["order:1234"],
        )
    )
    assert entry.ledger_sequence == 0
    assert ledger.verify_chain()


def test_two_events_chain_and_verify(tmp_path):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    ledger.append_event(make_event("TOOL_CALL", "ACME-AGENT-001", summary="one"))
    second = ledger.append_event(make_event("POLICY_DECISION", "ACME-GATE-001", summary="two"))
    assert second.ledger_sequence == 1
    assert ledger.verify_chain()


def test_identifiers_are_unique_per_call():
    a = make_event("TOOL_CALL", "ACME-AGENT-001", summary="x")
    b = make_event("TOOL_CALL", "ACME-AGENT-001", summary="x")
    assert a["record_id"] != b["record_id"]
    assert a["event_id"] != b["event_id"]


def test_producer_defaults_to_actor_and_can_be_overridden():
    ev = make_event("TOOL_CALL", "ACME-AGENT-001", summary="x")
    assert ev["producer_module_id"] == "ACME-AGENT-001"
    ev2 = make_event("TOOL_CALL", "ACME-AGENT-001", summary="x", producer="ACME-LOGGER-002")
    assert ev2["producer_module_id"] == "ACME-LOGGER-002"
    assert validate_audit_event(ev2).ok


def test_payload_ref_branch_is_accepted():
    ev = make_event("TOOL_CALL", "ACME-AGENT-001", payload_ref="s3://bucket/call-1.json")
    assert ev["payload_ref_or_summary"] == {"payload_ref": "s3://bucket/call-1.json"}
    assert validate_audit_event(ev).ok


def test_summary_and_payload_ref_are_mutually_exclusive():
    with pytest.raises(ValueError):
        make_event("TOOL_CALL", "ACME-AGENT-001")
    with pytest.raises(ValueError):
        make_event("TOOL_CALL", "ACME-AGENT-001", summary="x", payload_ref="y")


def test_external_truth_claim_still_needs_truth_refs(tmp_path):
    """The helper does not soften the ledger's own refusals."""
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    ev = make_event(
        "BALANCE_READ",
        "ACME-AGENT-001",
        summary="read the live balance",
        data_classification="EXTERNAL_TRUTH_CLAIM",
    )
    with pytest.raises(AuditEventRejected):
        ledger.append_event(ev)

    ok = make_event(
        "BALANCE_READ",
        "ACME-AGENT-001",
        summary="read the live balance",
        data_classification="EXTERNAL_TRUTH_CLAIM",
        truth_refs=["evidence:balance-2026-08-30"],
    )
    assert ledger.append_event(ok).ledger_sequence == 0


def test_banned_classification_still_refused(tmp_path):
    ledger = AuditLedger(path=tmp_path / "audit.jsonl")
    ev = make_event(
        "MODEL_THOUGHT",
        "ACME-AGENT-001",
        summary="the model's private reasoning",
        data_classification="INTERNAL_CHAIN_OF_THOUGHT",
    )
    with pytest.raises(AuditEventRejected):
        ledger.append_event(ev)


def test_non_vendor_prefixed_actor_is_rejected():
    ev = make_event("TOOL_CALL", "ACME-AGENT-001", summary="x")
    ev["actor_module"] = "not-an-id"
    assert not validate_audit_event(ev).ok
