# Outreach plan — the part that isn't a file

The four artifacts (quickstart, use case doc, Discussions, CONTRIBUTING) lower the
barrier to entry. They do not distribute themselves. This is the actual scarce
work: getting ~10 practitioners to run a tool and tell you what broke. None of it
produces a commit; all of it produces the signal ARTO is short on.

## The one goal
Within 90 days: **at least one organization outside Nigeria has run a tool against
a real agent environment and can describe a specific attack it caught or missed.**
Everything below is in service of that.

## Where the practitioners already are
Go to them; don't wait for them to find the repo.

- **OWASP** — the AI Exchange / Slack and the Agentic Security working groups. You
  already author there; share the quickstart and the use case doc as "here's a
  runnable demo of the Accumulation Problem," not as a pitch.
- **Your conference network** — DEF CON, Black Hat MEA, DevSecCon contacts. Warm
  intros beat cold posts 10:1.
- **Hacker News** — a "Show HN: VerityFlux — catch multi-turn agent hijacks
  per-request monitoring misses" once the quickstart is genuinely 10-minute clean.
- **r/netsec, r/MachineLearning (rarely), LLM-security Discords/Slacks.**
- **Security newsletters** — tldrsec and similar; the use case doc is the artifact
  to pitch.
- **LinkedIn** — short post per week: the architecture diagram, one scenario, one
  finding. You have the audience there already.

## The motion (repeatable)
1. Pick 10 named people who fit the practitioner profile.
2. Send each a short, specific message (template below) pointing at the
   **quickstart**, not the homepage.
3. Ask one question: "If you run it, what broke or what did it miss?"
4. Every reply → a GitHub issue or a use-case note. Every miss → a good first issue.
5. Fix the friction they hit *that day* (this is the only "building" allowed).

### Message template
> You're working on agentic AI security — I built an open-source runtime guard
> (VerityFlux) for multi-turn agent hijacks, the kind per-request monitoring
> misses. There's a 10-minute, no-API-key quickstart that shows it block a
> crescendo attack: <link>. If you run it, I'd love to know one thing — what broke,
> or what it missed against your own agent?

## What to measure (leading indicators)
- Quickstarts run by someone who isn't you (ask; or proxy via stars + issues).
- Issues filed from real attempts.
- Replies describing a real problem.
- The lagging one that matters: a documented external run.

## The honest calibration
Expect the first stretch to mostly teach you which **channels and messages fail**,
not to produce instant traction. That is a successful outcome if you run it as
experiments: a dead channel is data, a confusing message is data. Don't read early
silence as a verdict on whether the tools deserve to exist — read it as "wrong
door or wrong words, try the next." Sixty focused days of this beats sixty more
days of building.
