# agentledger

A tamper-evident, hash-chained audit ledger for AI agent actions.

[Source](https://github.com/przemyslawbudrewicz/agentledger) ·
[PyPI](https://pypi.org/project/phb-agentledger/) ·
[Commercial licence](https://budrewicz.gumroad.com/l/PHB-AgentLedger)

When an AI system does something consequential — calls a tool, spends money,
escalates to a person, refuses a request — you need a record that still means
something six months later, when someone asks what happened and why. An
application log does not survive that question: anyone with file access can
edit it, and nothing in the file says whether they did.

`agentledger` writes each action as a validated, content-addressed record in a
SHA-256 hash chain. Editing any stored record, in any field, breaks the chain,
and `verify_chain()` says so.

## Install

```bash
pip install phb-agentledger
```

Installed as `phb-agentledger`, imported as `agentledger`. One runtime
dependency (`filelock`). Python 3.10+.

## Sixty seconds

```python
from agentledger import AuditLedger, make_event

ledger = AuditLedger(path="audit.jsonl")

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

ledger.verify_chain()                        # True
ledger.query(subject_refs=["order:1234"])    # an AuditTrace of both events
```

Run `python demo.py` to see the same thing end to end, including a hand-edit of
the stored file and the chain check catching it.

## What it guarantees

- **Order is assigned by the ledger, never by the caller.** Sequence numbers
  and chain hashes are computed on append. A producer cannot claim a position
  in history.
- **Every record carries its own digest**, SHA-256 over JCS-1 canonical JSON
  with the digest field omitted. A record that does not match its own content
  is rejected before it is stored.
- **Appends are idempotent** on `(record_id, event_id)`. Resubmitting the same
  record is a no-op; resubmitting different content under the same key is a
  rejected conflict, not a silent overwrite.
- **Queries never overclaim.** A result is explicitly scoped to a ledger cut,
  so "no matches in this view" is never returned as "this never happened".
- **Concurrent writers are safe.** The load → mint → append critical section
  is held under a cross-process file lock, and a torn tail from a killed
  process is quarantined rather than silently truncating history.
- **Two refusals are enforced in code, not documentation.** The ledger will
  not store records classified as raw internal model reasoning, and it rejects
  any event that asserts externally-verified truth without evidence lineage.

## What it deliberately does not do

- **It does not verify payloads it never saw.** `payload_digest` is your
  assertion about content held elsewhere; the ledger stores and chains it, but
  cannot confirm it.
- **It is not a signing system.** Records are tamper-*evident* against edits to
  the stored file. They are not signed, so a party who can rewrite the whole
  file, including recomputing the chain, is out of scope. Signing is the next
  layer, not this one.
- **It does not make you compliant with anything.** It gives you a defensible
  record. Whether that record satisfies a given regulation is a question for
  your counsel.
- **`SCHEMA_HASH_CATALOG` ships with a placeholder hash** for AuditEvent 1.0.0
  rather than the digest of the shipped schema file. Set it from your deployed
  schemas at boot if you want that check to be meaningful.

## Event shape

`make_event()` fills the 22-field envelope for you and computes both digests.
The fields you supply are the ones that carry meaning:

| Argument | Meaning |
|---|---|
| `event_type` | What happened, as a `SCREAMING_SNAKE` label you choose |
| `actor` | Who did it, as `VENDOR-COMPONENT-NNN` (e.g. `ACME-AGENT-001`) |
| `summary` *or* `payload_ref` | A short line, or a pointer to the payload held elsewhere |
| `subject_refs` | What it was about (`order:1234`, `user:42`) |
| `data_classification` | Sensitivity label; drives the refusals above |
| `truth_refs` | Evidence lineage, required for external-truth claims |

Hand-built dicts are still accepted — `make_event` is a convenience, not a
bypass. `validate_audit_event()` judges both the same way.

## Tests

```bash
pip install -e ".[dev]"
python -m pytest tests -q
```

43 tests, no network, under a second.

## Licence

Source-available. Free for personal, educational, and evaluation use;
commercial use requires a paid licence. See [LICENSE](LICENSE).
