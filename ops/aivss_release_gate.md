# AIVSS Release Gate (Checklist)

Purpose: convert AIVSS scores into explicit release decisions.

## Thresholds (per AIVSS v0.8)
- **Critical (9.0–10.0)** → **FAIL** (release blocked)
- **High (7.0–8.9)** → **REQUIRE APPROVAL** (security + governance sign‑off)
- **Medium/Low (0.1–6.9)** → **PASS**

## Required Artifacts
1. AIVSS report JSON (Appendix A schema).
2. SBOM evidence for supply chain category.

## Commands
Generate SBOM:
```bash
python3 ops/generate_sbom.py
```

Generate AIVSS report:
```bash
python3 ops/aivss_report.py --sbom-path <path-to-sbom.json>
```

Evaluate release gate:
```bash
python3 ops/aivss_release_gate.py <path-to-aivss-report.json>
```

Exit codes:
- `0` = PASS
- `1` = FAIL
- `2` = REQUIRE_APPROVAL
