# escalation-contract

A finding that requires a bound, owned response — not just a log line.

Issue 18 and Issue 22 of *Controlled Agency* both make the same argument
about frontier-lab embedded evaluators: a mechanism that only observes and
reports isn't a control, because nobody is required to act on what it
reports. This is that argument, turned into working code, applied one
level down — at the level of a single agent runtime rather than an entire
industry.

```python
from escalation_contract import EscalationContractStore

def revoke_the_credential(contract):
    my_auth_system.revoke(contract.subject_token, reason=contract.reason)

store = EscalationContractStore(on_expire=revoke_the_credential)

contract = store.open(
    agent_id="agent-42",
    reason="turning point flagged, trajectory escalating",
    window_seconds=900,       # 15 minutes to respond
    subject_token="jti-abc",  # what gets revoked if nobody does
)

# ... later, either:
store.acknowledge(contract.contract_id, acknowledged_by="oncall@example.com")
# ... or, if nobody calls acknowledge() before the deadline:
store.sweep_expired()  # -> calls revoke_the_credential(contract)
```

## The three states

**Pending** — a finding has been raised and is waiting for a named person
to answer for it. **Acknowledged** — someone did, and it's recorded who and
when. **Expired** — nobody did, and whatever consequence function the store
was built with actually ran.

There is no fourth state where the finding just sits, un-owned, forever.
That's the entire point.

## Wired to VerityFlux and Tessera, using components that already work

This isn't a new enforcement mechanism bolted onto a demo — it's new
orchestration wired to two already-working, already-tested pieces of ARTO:

- **VerityFlux**: `StatefulIntentTracker` accepts an optional
  `escalation_store` — when its own `trajectory_metrics`-based
  turning-point detector fires, it opens a contract. VerityFlux never
  imports this package directly — it's a duck-typed optional dependency,
  so VerityFlux stays decoupled from whatever the store is wired to
  enforce (consistent with ARTO's own separation of planes — the system
  that acts shouldn't be the sole system that validates it).
- **Tessera**: `tessera_adapter.make_tessera_revoking_store()` wires
  `on_expire` to Tessera's real `RevocationList.revoke()` — the same
  revocation list `Gatekeeper.validate_access()` already checks on every
  request (`DENY_REVOKED`). An expired contract doesn't just get logged;
  the credential it names stops working on the next real request,
  end-to-end, tested against Tessera's actual classes, not a mock.

## What this deliberately does not do

It doesn't decide *what* counts as escalation-worthy — that's VerityFlux's
job, upstream of this. It doesn't decide *how* a credential gets revoked —
that's whatever `on_expire` is wired to, Tessera or otherwise. It only
guarantees the middle part: a finding gets a deadline, a named
acknowledgment or a real consequence, and nothing in between.

The contract store here is in-memory and per-process — enough for a single
deployment, not built for surviving a restart. A persistent backend (Redis,
a table) is a drop-in replacement behind the same interface if a
deployment needs that; not built speculatively here.

MIT-licensed, zero hard dependencies (the Tessera adapter is the one
optional piece that imports Tessera, and only when you use it).
