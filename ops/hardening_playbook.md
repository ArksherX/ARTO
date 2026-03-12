# ML-Redteam Suite — Hardening & Deployment Playbook

**Last updated:** 2026-02-10

## Goals
- Keep standalone behavior unchanged.
- Provide a clear path to production-grade deployments.

---

## 1) Secrets & Rotation
- **Use per-service secrets** (Tessera, Vestigia, VerityFlux) and rotate quarterly or after any incident.
- Store secrets in a vault (e.g., HashiCorp Vault, AWS Secrets Manager), never in plaintext.
- Rotate:
  - Tessera: `TESSERA_SECRET_KEY`, JWT/DPoP keys
  - Vestigia: `VESTIGIA_API_KEY`, `VESTIGIA_SECRET_SALT`, DB credentials
  - VerityFlux: API keys/JWT secrets

Reference env list: `ops/secrets_env.md`

Rotation procedure (safe, low risk):
1. Add new secret in vault.
2. Roll service with new secret while old remains accepted.
3. Switch verification to new secret.
4. Revoke old secret after a fixed window.

---

## 2) Multi-Node HA (Minimum)
- **Tessera:** 2 API nodes + Redis (HA) + LB with health checks.
- **Vestigia:** 2 API nodes + Postgres primary/replica + object storage for backups.
- **VerityFlux:** 2 API nodes + shared database (if used) + LB.

Recommended:
- Kubernetes or Docker Swarm with rolling updates.
- Health endpoints required for LB checks.

---

## 3) Logging & Metrics Unification
- Standardize logs: JSON logs with `service`, `trace_id`, `tenant_id`.
- Use a shared log shipper (Fluent Bit / Vector) to centralize logs.
- Metrics:
  - Prometheus scrape for all APIs
  - Dashboards in Grafana

---

## 4) Backup & DR
- Vestigia DB backups daily + integrity verification.
- Store backups encrypted offsite (S3/GCS + KMS).
- Quarterly restore drills.

---

## 5) Security Baselines
- Enable TLS everywhere.
- Disable unauth endpoints in prod (where possible).
- Use WAF rules for API endpoints.
- Restrict admin endpoints by IP or VPN.

Local TLS helper:
```
./ops/gen_local_tls.sh
```

---

## 6) Operational Checklists
- Pre-deploy: dependencies pinned, secrets in vault, ports verified.
- Deploy: rolling restart, verify health endpoints.
- Post-deploy: run integration smoke test + reliability checks.
