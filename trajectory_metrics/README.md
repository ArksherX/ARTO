# trajectory-metrics

A small, dependency-free primitive for detecting escalation across a
sequence of turns, rather than scoring each turn in isolation.

Most guardrails and red-team scoring tools evaluate one message at a time.
That's structurally blind to attacks that only become identifiable in
aggregate — a crescendo attack, a gradual goal hijack — where no single
turn crosses a policy boundary on its own. This library doesn't replace
your per-turn scorer; it wraps its output to answer a different question:
**is this trajectory getting worse, and if so, since when?**

```python
from trajectory_metrics import TrajectoryTracker

tracker = TrajectoryTracker(escalation_threshold=0.5, min_consecutive_increases=3)

for turn_score in per_turn_scores:  # from your own scorer/detector
    result = tracker.update(turn_score)
    if result.is_turning_point:
        print(f"Escalation flagged at turn {result.turn_index}")
```

## What it computes

- **`delta`** — Δ(t) = S(t) − S(t−1), the turn-over-turn change in score.
- **`consecutive_increases`** — the current run length of strictly
  increasing scores.
- **`is_turning_point`** — fires once, on the first turn where the score
  has been rising for `min_consecutive_increases` turns in a row *and*
  has crossed `escalation_threshold`.

## What it does not do

It does not score content — you bring your own per-turn scorer (a
classifier, an LLM judge, a keyword detector). This library only tracks
the *sequence* of scores that scorer produces. No LLM calls, no network
access, no external dependencies — it's pure Python and safe to embed in
any pipeline that already produces a 0.0-1.0 per-turn score.

## Provenance

The core logic here generalizes the crescendo-detection approach already
running in [ARTO](https://github.com/ArksherX/ARTO)'s VerityFlux runtime
firewall (`StatefulIntentTracker`), extracted into a standalone form so
the same primitive can be reused as a detector/scorer in other
frameworks without depending on this repo.

MIT-licensed.
