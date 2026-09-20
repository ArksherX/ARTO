# Production Environment Checklist

Use this before any production launch.

## Required Secrets

Set all of these explicitly. Do not rely on launcher defaults.

```bash
export MODE=prod
export SUITE_STRICT_MODE=true

export TESSERA_SECRET_KEY='<64+ byte secret>'
export TESSERA_ADMIN_KEY='tessera-admin-<strong-random-value>'
export TESSERA_TENANT_SCOPED_REGISTRY=true
export TESSERA_ENFORCE_TENANT_SCOPE=true

export VERITYFLUX_API_KEY='vf_admin_<strong-random-value>'
export VERITYFLUX_ALLOWED_ORIGINS='https://console.example.com'
export VERITYFLUX_MCP_TOOL_SECRET='<strong-random-value>'
export VERITYFLUX_MANIFEST_KEY='<strong-random-value>'
export VERITYFLUX_TENANT_SCOPED_STORAGE=true
export VERITYFLUX_TENANT_DATA_ROOT='verityflux-v2/data/tenants'

export VESTIGIA_SECRET_SALT='<strong-random-value>'
export VESTIGIA_API_KEY='<strong-random-value>'
export VESTIGIA_TENANT_SCOPED_STORAGE=true
```

## Recommended Runtime Settings

```bash
export MLRT_INTEGRATION_ENABLED=true
export MLRT_VESTIGIA_INGEST_URL='http://localhost:8002/events'
export MLRT_VESTIGIA_API_KEY="$VESTIGIA_API_KEY"

export TESSERA_REQUIRE_DPOP=true
export TESSERA_REQUIRE_MEMORY_BINDING=true
export TESSERA_REQUIRE_ACTION_SIGNATURE=true

# Close unauthenticated agent registration / token issuance (see Notes).
export TESSERA_REQUIRE_REGISTRATION_AUTH=true

# Refuse to serve the evidence API if no API key is set, rather than allow-all.
export VESTIGIA_FAIL_CLOSED=true
```

## Optional But Common

```bash
export VERITYFLUX_OVERSIGHT_PROVIDER='openai'
export VERITYFLUX_OVERSIGHT_MODEL='gpt-4o'
export VERITYFLUX_OVERSIGHT_API_KEY='<provider-key>'

export VERITYFLUX_SCORER_PROVIDER='openai'
export VERITYFLUX_SCORER_MODEL='gpt-4o-mini'
export VERITYFLUX_SCORER_API_KEY='<provider-key>'

export VERITYFLUX_JWT_SECRET='<strong-random-value>'
export VERITYFLUX_JWT_ISSUER='verityflux'
export VERITYFLUX_JWT_AUDIENCE='verityflux-api'

```

## TLS

Pick exactly one of the two models below. Do not configure both.

### Kubernetes (recommended): terminate at the ingress

This is what the shipped manifests do —
`tessera/kubernetes/ingress.yaml`, `vestigia/kubernetes/ingress.yaml`,
and `verityflux-v2/deploy/k8s/08-ingress.yaml` each declare a `tls:` block,
`ssl-redirect: "true"`, and a cert-manager `cluster-issuer`.

Do **not** set the `*_TLS_CERTFILE` / `*_TLS_KEYFILE` variables in this model.
cert-manager issues and renews certificates with no pod restarts, which matters
here because the services read those variables once at startup and have no
hot-reload path — in-app certs would make every renewal a restart.

Checklist:
- [ ] Replace the `*.example.com` hostnames in all three ingress manifests.
- [ ] Confirm the `cert-manager.io/cluster-issuer` name matches an issuer
      installed in your cluster.
- [ ] Verify `ssl-redirect` is active: a plain HTTP request should 308 to HTTPS.
- [ ] Note that ingress→pod traffic is plaintext inside the cluster. If your
      compliance regime requires in-cluster encryption, use a service mesh with
      mTLS, or the standalone model below.

### Standalone / non-Kubernetes: terminate in the application

Use this only when there is no ingress or reverse proxy in front of the
services.

```bash
export TESSERA_TLS_CERTFILE='/path/to/cert.pem'
export TESSERA_TLS_KEYFILE='/path/to/key.pem'
export VESTIGIA_TLS_CERTFILE='/path/to/cert.pem'
export VESTIGIA_TLS_KEYFILE='/path/to/key.pem'
export VERITYFLUX_TLS_CERTFILE='/path/to/cert.pem'
export VERITYFLUX_TLS_KEYFILE='/path/to/key.pem'
```

Checklist:
- [ ] Certificates are readable by the service user.
- [ ] A renewal procedure exists, and it restarts the services — these values
      are read at startup only.
- [ ] Nothing else is already terminating TLS in front of these processes.

## Validation Sequence

```bash
python3 preflight_check.py
python3 reliability_check.py
python3 test_suite_complete.py
python3 test_adversarial_efficacy.py
python3 test_e2e_scenarios.py
```

For strict preflight:

```bash
SUITE_STRICT_MODE=true python3 preflight_check.py
```

## Current Strict Preconditions

Strict preflight now checks:

- `TESSERA_SECRET_KEY`
- `TESSERA_ADMIN_KEY`
- `VERITYFLUX_API_KEY`
- `VERITYFLUX_ALLOWED_ORIGINS`
- `VERITYFLUX_MCP_TOOL_SECRET`
- `VERITYFLUX_MANIFEST_KEY`
- `VERITYFLUX_JWT_SECRET` — setting it is what activates JWT validation
- `VESTIGIA_SECRET_SALT`
- `VESTIGIA_PLATFORM_ADMIN_KEY` when `VESTIGIA_MULTI_TENANT=true`

## Notes

- `launch_suite.sh` remains local-friendly when `SUITE_STRICT_MODE` is not enabled.
- In strict production mode, the launcher and service startup paths fail closed on missing critical secrets.
- In strict production mode, VerityFlux only accepts explicitly configured API keys and no longer accepts wildcard CORS origins.
- VerityFlux API keys are now persisted with hashed verification and revocation metadata. The admin env key still exists as a bootstrap path.
- VerityFlux bearer-token auth validates real JWTs whenever `VERITYFLUX_JWT_SECRET` is configured. (There is no `VERITYFLUX_ENABLE_JWT` flag — no code reads one; the secret's presence is the switch.)
- `VERITYFLUX_TENANT_SCOPED_STORAGE=true` stores scans, skill assessments, approvals, and API keys under tenant-specific directories rather than shared flat files.
- `TESSERA_TENANT_SCOPED_REGISTRY=true` stores agent registry records under tenant-specific directories while preserving a unified in-memory view.
- `TESSERA_ENFORCE_TENANT_SCOPE=true` requires tenant-scoped agent queries on Tessera admin/listing surfaces so tenant data is not returned globally by default.
- `VESTIGIA_TENANT_SCOPED_STORAGE=true` stores access-audit and risk-history file data under tenant-specific directories when multi-tenant mode is enabled.
- `TESSERA_REQUIRE_REGISTRATION_AUTH=true` requires the admin bearer key for `/agents/register` and `/tokens/request`. Without it, those endpoints are open and anyone who can reach the API can self-register a broadly-scoped agent and mint valid tokens — bypassing scoped authority. Enable in any environment where the Tessera API is network-reachable. Default off so local/demo self-registration keeps working.
- `VESTIGIA_FAIL_CLOSED=true` makes the evidence API return `503` when `VESTIGIA_API_KEY` is unset, instead of allowing all requests ("development mode"). Enable it so a deploy that forgets to set the key cannot silently run the audit/evidence API wide open. Always set `VESTIGIA_API_KEY` as well.
- Vestigia's Merkle witness is on by default and detects in-place tampering and full-ledger rewrites; for rewrite-resistance against an attacker with write access to the data volume, configure an off-box external anchor rather than relying on the local witness file alone.
