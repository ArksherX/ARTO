# Delegation Scope Model — design (roadmap)

**Status:** design only. Not implemented. Target: after Black Hat Arsenal.
**Owner decision required before build:** confirm the scope taxonomy (below).

## Problem

Tessera delegation enforces two things today, correctly:

1. **Depth-bounding** — a delegation chain cannot exceed `MAX_DELEGATION_DEPTH`.
2. **Chain-level non-escalation** — each link's `scopes_granted` must be a subset
   of its parent's, so a delegated token can never widen authority beyond its
   parent (`gatekeeper.validate_access`, chain scope-subset check).

What is **not** enforced: the per-operation scope *within a single tool*. A
delegated token minted with `requested_scopes=["read"]` still carries the
parent's full `tool` claim, and the gatekeeper authorizes on tool-equality. So a
"read-only" delegated token can still perform a write through the same tool.

This is a **correctness/expressiveness gap, not a privilege escalation** — the
sub-agent must already hold the tool in `allowed_tools`, and chain widening is
blocked. But "scope narrowing" implies per-operation enforcement, so we should
either build it or scope the claim honestly (the latter is done — see
`SESSION_SUMMARY.md` enforcement-boundary note).

## Design principles (chosen to avoid regressions)

1. **Coarse, explicitly-declared scopes — never parsed.** Scopes are a small
   fixed set (`read` / `write` / `admin`) declared in the agent/tool registry.
   We do **not** infer an operation's required scope by parsing payloads (e.g.
   parsing SQL). Parsing is non-deterministic, evadable, and would break working
   demos with false denials. Explicit declaration matches how the rest of Tessera
   already works.
2. **Backward-compatible by construction.** A token with **no** `scopes` claim
   means "all operations for the tool" — today's behavior, unchanged. Enforcement
   only applies to tokens that carry a `scopes` claim (i.e. delegated tokens that
   opted in). Every existing token, test, and demo keeps passing.
3. **Opt-in flag, default off.** `TESSERA_ENFORCE_DELEGATION_SCOPES` (default
   `false`), following the existing hardening-flag pattern
   (`TESSERA_REQUIRE_REGISTRATION_AUTH`, `TESSERA_ENFORCE_TENANT_SCOPE`, …).
   Off = current behavior, guaranteed no regression. On = per-operation scope
   enforcement for scope-bearing tokens.

## Implementation sketch

1. **Scope taxonomy (decision needed):** confirm the set `{read, write, admin}`
   and the mapping from each registered tool's operations to a required scope.
   A tool declares, per operation (or per request field), which scope it needs —
   e.g. `query_sql` → the caller supplies the operation class, or the tool's
   manifest declares `read`/`write` sub-actions. Registry-declared, not parsed.
2. **Token:** add an optional `scopes` param to `TokenGenerator.generate_token`
   and emit it as a `scopes` JWT claim. `/tokens/delegate` passes
   `list(delegated.effective_scopes)`. (`get_effective_scopes` already reads
   `token.get("scopes", [])`, so the read path exists.)
3. **Gatekeeper:** when `TESSERA_ENFORCE_DELEGATION_SCOPES` is on **and** the
   token carries a `scopes` claim, resolve the requested operation's required
   scope and deny (`DENY_SCOPE_MISMATCH`) if it is not in the token's effective
   scopes. When the flag is off or no `scopes` claim is present, behave exactly
   as today.

## Anti-regression gate (required before merge)

- With the flag **off**: the full existing delegation suite passes unchanged —
  `test_e2e_scenarios.py` Scenario 3 (6/6) and `test_suite_complete.py`
  Section C (5/5), and the live delegation demo behaves identically.
- With the flag **on**: new tests prove a `read`-scoped delegated token is
  allowed a read operation and denied a write operation on the same tool, and a
  no-scopes token is unaffected.
- No change to the token crypto/signing path beyond adding the claim.

## Decision rule

Build this only if a delegation demo needs to show "read-only-subset-of-a-tool"
enforcement, **or** post-Arsenal as a clean, flagged feature. Until then, the
honest wording (chain-level non-escalation + depth-bounding) stands.
