<!--
Security vulnerability? Do NOT open a PR. Report privately:
Security tab → Advisories → Report a vulnerability. See SECURITY.md.
-->

## What this changes
<!-- One or two sentences. PRs that do ONE thing get merged fastest. -->

## Why
<!-- The problem this solves. Link the issue if there is one: Fixes #123 -->

## Scope
<!-- Which component(s): Tessera / VerityFlux / Vestigia / shared / docs / console -->

## Test evidence
<!--
Paste the passing output — this is the single biggest thing that speeds up review.

  cd verityflux-v2 && python -m pytest tests/unit tests/test_blocking_policy.py -q

For cross-service changes (services must be running):

  ./launch_suite.sh
  python test_suite_complete.py && python test_adversarial_efficacy.py
-->

```
paste test output here
```

## For a new detector
<!-- Delete this section if not applicable. -->
- [ ] Positive case: it **blocks** the attack (test added)
- [ ] Benign case: it does **not** false-positive on legitimate agent reasoning (test added)

## Checklist
- [ ] Does one thing, with a clear title
- [ ] Tests added/updated for the behaviour changed
- [ ] No secrets, tokens, or real agent data in the diff or test output
- [ ] Docs updated if behaviour or configuration changed
- [ ] **Commits are signed off** (`git commit -s`) per the DCO — see `CONTRIBUTING.md`
- [ ] I understand ARTO is source-available under **BSL 1.1** (not an open-source
      licence) and that my contribution is licensed under those same terms
