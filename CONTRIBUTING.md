# Contributing to ARTO

Thanks for being here. ARTO is open security tooling for agentic AI, and it gets
better mostly through people who hit a real problem and decide to fix it. You do
not need to be a maintainer or an expert to contribute — a new detector, a new
attack scenario, or a clearer doc all move it forward. This guide is the door.

## The three most valuable things you can add

### 1. A new VerityFlux detector
A pattern that catches an attack class VerityFlux misses today. The
"survive contact" robustness pass showed how much these matter.

- Reasoning-level detectors live in
  `verityflux-v2/cognitive_firewall/reasoning_interceptor.py` (see the
  `critical_intent_patterns` list — a high-precision class detector is the
  simplest kind to add).
- A *good* detector is **high precision**: it fires on a real malicious class and
  not on benign agent reasoning. Always add both a positive case (it blocks) and
  a benign case (it still allows) to
  `verityflux-v2/tests/unit/test_reasoning_interceptor_robustness.py`.

### 2. A new attack scenario
A reproducible attack that demonstrates a control (or exposes a gap). Look at
`quickstart/attack_crescendo.py` for the shape: a short script that drives an
agent and prints a clear PASS/BLOCK result.

### 3. A new framework / standards mapping
Map ARTO's controls to a framework practitioners are audited against (NIST AI RMF,
ISO/IEC 42001, EU AI Act, OWASP, a regional regulation). These are pure docs and
are genuinely high-leverage for adoption.

## Your first contribution

Look for issues labelled **`good first issue`** — they are small, well-scoped, and
finishable in an afternoon without needing to talk to anyone. Pick one, comment
that you're taking it, and go.

## The mechanical path

1. Fork, then create a feature branch.
2. Make your change. Keep it minimal and scoped to one thing.
3. Run the tests for what you touched:
   ```bash
   # fast unit tests (most changes)
   cd verityflux-v2 && python -m pytest tests/unit tests/test_blocking_policy.py -q
   # full suite (cross-service changes) — services must be running
   ./launch_suite.sh
   python test_suite_complete.py && python test_adversarial_efficacy.py
   ```
4. Open a PR with: the problem, the scope of the change, and test evidence
   (paste the passing output).

### What gets a PR merged fast
- It does one thing, with a clear title.
- It has a test that proves the behaviour (especially for detectors).
- For a detector, it shows it blocks the attack **and** does not false-positive
  on a benign example.

## What to expect from us
We aim to respond to your first PR or issue within **48 hours**. The first
contributor's experience decides whether there's a second, so we take it
seriously — if something is unclear, that's a bug in this guide; tell us.

## Security issues
Please do **not** open public issues for security vulnerabilities in ARTO itself.
Email the maintainer instead. (Attack scenarios *against the demo* are welcome as
normal contributions — those are the point.)

## License
By contributing, you agree your contributions are licensed under Apache-2.0.
