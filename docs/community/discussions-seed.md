# GitHub Discussions — setup and seed posts

This is a checklist + copy-paste seed text. Do this **after** the quickstart and
the use case doc exist, so anyone who shows up curious finds a working tool.

## Setup
1. Repo → Settings → Features → enable **Discussions**.
2. Create the two threads below and **pin** both.
3. Commit to replying to every reply within **24 hours** for the first month. An
   unanswered thread reads as abandonment — worse than no thread. If traffic is
   near zero at first, that is fine; the responsiveness is the asset, not volume.

---

## Thread 1 (pin) — "What agentic AI security problem are you trying to solve?"

> I'm building ARTO — open-source security tooling for agentic AI (identity,
> runtime enforcement, tamper-evident audit). Before I build more, I want to hear
> what you're actually up against.
>
> If you're deploying or securing AI agents: **what's the security problem that's
> on your mind right now?** Multi-turn jailbreaks? Agents with too much standing
> access? MCP/tool supply chain? Proving to an auditor what an agent did? No wrong
> answers — even "we don't know where to start" is useful signal.
>
> I'll start with three I keep hearing:
> 1. *Multi-turn hijacks slip past per-request guards* — the attack accumulates
>    across a session ([quickstart shows this](../../QUICKSTART.md)).
> 2. *Agents share ambient, over-broad credentials* — no scoped, revocable
>    identity per agent.
> 3. *No admissible evidence trail* — when something goes wrong, you can't prove
>    what the agent did or that the logs weren't altered.
>
> What's yours?

*(Every reply is a potential use case doc and a potential contributor. When
someone names a problem ARTO doesn't yet solve well, that's your roadmap being
written by users — capture it.)*

---

## Thread 2 (pin) — "Show us your deployment — what are you running ARTO against?"

> If you've tried ARTO against an agent (yours or a test one), tell us:
> - what agent / framework you pointed it at,
> - what it caught (or missed),
> - anything that broke or was confusing.
>
> Screenshots and pasted output welcome. "It missed X" is just as valuable as "it
> caught Y" — both make the tools better, and the misses become good first issues.

---

## What success looks like
- Your own responsiveness (every reply answered < 24h), not reply volume.
- Within 60 days: 5+ practitioners describing a real problem.
- The leading indicator: someone describes a problem ARTO doesn't solve yet.
