# Security Policy

ARTO is security tooling for agentic AI. We take the security of the project, and
of the people who run it, seriously.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Instead, report it privately:
- Use GitHub's **"Report a vulnerability"** (Security tab → Advisories → Report),
  or
- Email the maintainer (see the profile at https://github.com/ArksherX).

Please include: a description, affected component/version, reproduction steps, and
impact. We aim to acknowledge within **48 hours** and to agree on a disclosure
timeline with you. We support coordinated disclosure and will credit reporters who
want it.

## Scope

In scope:
- Tessera (identity/authorization), VerityFlux (runtime enforcement/scanning),
  Vestigia (audit) — auth logic, token/JWT handling, the audit hash-chain, key
  management, detector bypasses, and injection in the APIs.

Out of scope:
- Findings that require a misconfigured deployment that ignores the hardening
  guidance (e.g. running with demo credentials in production).
- The bundled demo environments, which are intentionally permissive for local use.

## Secrets and configuration (operator guidance)

ARTO ships **no real secrets**. Before any non-local use:
- Set `TESSERA_SECRET_KEY`, `TESSERA_ADMIN_KEY`, `VERITYFLUX_API_KEY`,
  `VERITYFLUX_MCP_TOOL_SECRET`, `VESTIGIA_API_KEY`, and `VESTIGIA_SECRET_SALT`
  to strong, unique values via your secret store. The values visible in
  `launch_suite.sh` are **local-dev demo defaults only** and must be replaced.
- The local signing key is generated at launch if unset; provide your own for a
  stable key across restarts.
- Never commit a real `.env`; it is gitignored.
- See `ops/hardening_playbook.md` and `ops/production_env_checklist.md`.

## What is intentionally not in this repo

Offensive red-team payload libraries and automated attack tooling are **not**
open-sourced. Please do not request them; security research collaborations can be
arranged privately through the contact above.
