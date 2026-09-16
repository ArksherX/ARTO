# arto-reachability

Two static checks for the same underlying question — "does this codebase
actually deliver the enforcement outcome it claims to?" — each catching a
different way the answer can be no.

## 1. Reachability: is this control ever called at all?

The CAGE-class finding: a control that's built, possibly even tested in
isolation, but never wired into the path that matters — CAGE's
`atomic_verify_and_commit()`, PyRIT's `replay_evaluate()`, AgentDojo's
trajectory-aware detector mode. Each was found by grepping for callers of a
named function and checking, by hand, whether any of them sit on a path a
real request actually takes. This automates that pass.

```bash
python -m arto_reachability.cli reachability path/to/codebase \
    --entry-points execute_trade_action,handle_request \
    --targets atomic_verify_and_commit,replay_evaluate
```

```
[UNREACHABLE] atomic_verify_and_commit
    defined at path/to/codebase/gateway/cbf.py:406 (ControlBarrierFunction.atomic_verify_and_commit)
[REACHABLE] handle_request
    defined at path/to/codebase/server.py:12 (handle_request)
    reached via: execute_trade_action
```

Resolution is by simple (unqualified) name — the same resolution a
`grep -rn "def foo"` / `grep -rn "foo("` pass gives you, not full
type-resolved dispatch. Sound call-graph construction for dynamic Python
(decorators, `getattr`, `importlib`, monkeypatching) needs whole-program
type inference a static AST pass can't provide — this automates the grep,
not a formal proof. A real finding still deserves the same manual
confirmation every finding in this research has gotten before being
reported. Test directories are excluded by default: a function only ever
called from its own test suite is exactly the gap this catches, not a
reason to call it reachable.

## 2. Threshold ladders: is a branch unreachable due to ordering?

The Lelu-class finding: a branch *inside* a function that IS called, where
a specific outcome can never fire because an earlier, looser check already
catches everything it needs. This is Lelu's actual bug —
`Escalate()` checked `threshold` before `threshold + 0.3`, making the deny
branch unreachable once the calibrator was fitted.

```bash
python -m arto_reachability.cli ladders path/to/codebase
```

```
escalate (path/to/codebase/escalator.py): the branch at line 5
(`calibrated >= 0.7` -> return 'ActionDeny') is unreachable -- the branch
at line 3 (`calibrated >= 0.4` -> return 'ActionReview') already catches
every value that would satisfy it.
```

**This is not general branch-reachability analysis** — that needs symbolic
execution over arbitrary conditions and runtime values, a much larger
undertaking (closer to a theorem prover than a static AST pass) that this
tool does not attempt. What's checkable without one is the narrow, common
case this targets: a sequence of comparisons of the *same* left-hand
expression against *constant* numeric thresholds, using the *same*
directional operator (`>=`/`>` or `<=`/`<`) — either as sequential
early-return `if`s or an `if/elif` chain. Under those constraints, "does an
earlier branch already cover everything a later one needs" is arithmetic
on the thresholds, not a general satisfiability problem — and severity-tier
/ escalation-ladder logic overwhelmingly is written in exactly this shape.
A non-constant threshold (a parameter, an attribute value), a compound
condition, or mixed variables/directions falls outside what this can check
and is silently skipped rather than guessed at.

MIT-licensed, zero dependencies (stdlib `ast` only).
