# Production Environment Checklist

Use this before any production launch.

## Required Secrets

Set all of these explicitly. Do not rely on launcher defaults.

```bash
export MODE=prod
export SUITE_STRICT_MODE=true

export TESSERA_SECRET_KEY='<64+ byte secret>'
export TESSERA_ADMIN_KEY='tessera-admin-<strong-random-value>'

export VERITYFLUX_API_KEY='vf_admin_<strong-random-value>'
export VERITYFLUX_MCP_TOOL_SECRET='<strong-random-value>'
export VERITYFLUX_MANIFEST_KEY='<strong-random-value>'

export VESTIGIA_SECRET_SALT='<strong-random-value>'
export VESTIGIA_API_KEY='<strong-random-value>'
```

## Recommended Runtime Settings

```bash
export MLRT_INTEGRATION_ENABLED=true
export MLRT_VESTIGIA_INGEST_URL='http://localhost:8002/events'
export MLRT_VESTIGIA_API_KEY="$VESTIGIA_API_KEY"

export TESSERA_REQUIRE_DPOP=true
export TESSERA_REQUIRE_MEMORY_BINDING=true
export TESSERA_REQUIRE_ACTION_SIGNATURE=true
```

## Optional But Common

```bash
export VERITYFLUX_OVERSIGHT_PROVIDER='openai'
export VERITYFLUX_OVERSIGHT_MODEL='gpt-4o'
export VERITYFLUX_OVERSIGHT_API_KEY='<provider-key>'

export VERITYFLUX_SCORER_PROVIDER='openai'
export VERITYFLUX_SCORER_MODEL='gpt-4o-mini'
export VERITYFLUX_SCORER_API_KEY='<provider-key>'

export TESSERA_TLS_CERTFILE='/path/to/cert.pem'
export TESSERA_TLS_KEYFILE='/path/to/key.pem'
export VESTIGIA_TLS_CERTFILE='/path/to/cert.pem'
export VESTIGIA_TLS_KEYFILE='/path/to/key.pem'
export VERITYFLUX_TLS_CERTFILE='/path/to/cert.pem'
export VERITYFLUX_TLS_KEYFILE='/path/to/key.pem'
```

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
- `VERITYFLUX_MCP_TOOL_SECRET`
- `VERITYFLUX_MANIFEST_KEY`
- `VESTIGIA_SECRET_SALT`

## Notes

- `launch_suite.sh` remains local-friendly when `SUITE_STRICT_MODE` is not enabled.
- In strict production mode, the launcher and service startup paths fail closed on missing critical secrets.
- VerityFlux API authentication is still prefix-based (`vf_admin_...`, `vf_...`). That is acceptable for the current stack, but if you want a stronger production posture, the next step is replacing prefix-based API-key acceptance with a real key registry or signed token validation.
