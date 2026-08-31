"""Sixty-second demo: record three agent actions, prove the chain, then prove
that editing the file is detected. Run: python demo.py"""
import json
from pathlib import Path

from agentledger import AuditLedger, make_event

LEDGER_PATH = Path(__file__).parent / "demo_audit.jsonl"


def main() -> None:
    if LEDGER_PATH.exists():
        LEDGER_PATH.unlink()
    ledger = AuditLedger(path=LEDGER_PATH)

    ledger.append_event(make_event(
        "TOOL_CALL", "ACME-AGENT-001",
        summary="looked up order 1234",
        subject_refs=["order:1234"],
    ))
    ledger.append_event(make_event(
        "POLICY_DECISION", "ACME-GATE-001",
        summary="refund above the auto-approve limit: escalated to a human",
        subject_refs=["order:1234"],
    ))
    ledger.append_event(make_event(
        "HUMAN_APPROVAL", "ACME-CONSOLE-001",
        summary="refund approved by the on-call operator",
        subject_refs=["order:1234"],
        authority_refs=["operator:on-call"],
    ))

    print(f"{len(ledger)} events recorded at {LEDGER_PATH.name}")
    print("chain valid:", ledger.verify_chain())

    trace = ledger.query(subject_refs=["order:1234"])
    print("\neverything the ledger holds about order 1234:")
    print(json.dumps(trace, indent=2)[:600] + "\n...")

    # Now tamper: rewrite one stored summary the way someone covering their
    # tracks would, and reload.
    rows = LEDGER_PATH.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[1])
    row["record"]["payload_ref_or_summary"]["summary"] = "refund was within the limit"
    rows[1] = json.dumps(row)
    LEDGER_PATH.write_text("\n".join(rows) + "\n", encoding="utf-8")

    reopened = AuditLedger(path=LEDGER_PATH)
    print("\nafter editing one line by hand, chain valid:", reopened.verify_chain())


if __name__ == "__main__":
    main()
