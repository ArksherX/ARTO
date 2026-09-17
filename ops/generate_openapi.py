#!/usr/bin/env python3
"""
Generate OpenAPI specs for each service into docs/openapi/.

Why this exists: an audit of all 138 registered routes found that only 7 were
documented anywhere, and 3 of those 7 pointed at endpoints that did not exist
(wrong path, wrong version, or a capability the service never had). Hand-written
endpoint documentation drifts silently. A generated, committed spec turns
"is the documentation accurate?" into a diff.

Usage:
    python ops/generate_openapi.py            # write specs
    python ops/generate_openapi.py --check    # fail if specs are stale (CI)

--check is the CI mode: it regenerates in memory and compares against what is
committed, exiting non-zero if they differ. That makes an un-regenerated spec a
build failure rather than something discovered months later.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "docs" / "openapi"

# (service name, directory to import from, module path, app attribute)
SERVICES = [
    ("verityflux", REPO_ROOT / "verityflux-v2", "api.v2.main", "app"),
    ("tessera", REPO_ROOT / "tessera", "api_server", "app"),
    ("vestigia", REPO_ROOT / "vestigia", "api_server", "app"),
]

# Importing these modules executes service startup code, which reads config from
# the environment. Set deterministic placeholders so generation does not depend
# on the developer's local environment or produce environment-specific output.
GENERATION_ENV = {
    "TESSERA_SECRET_KEY": "a" * 64,
    "VERITYFLUX_API_KEY": "openapi-generation-placeholder",
    "VESTIGIA_API_KEY": "openapi-generation-placeholder",
    "MLRT_INTEGRATION_ENABLED": "false",
}


# Run inside a subprocess, one per service. The services cannot be imported
# into a single process: Tessera and Vestigia both define a top-level
# `api_server` module, and VerityFlux and Vestigia both define a top-level
# `core` package. Whichever imports first wins the sys.modules entry, which
# silently produced a "vestigia" spec full of Tessera's routes. Process
# isolation is the only clean way to give each service its own import state.
_WORKER = """
import json, os, sys
service_dir, module_path, attr = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, service_dir)
os.chdir(service_dir)
import importlib
module = importlib.import_module(module_path)
app = getattr(module, attr)
sys.stdout.write("---OPENAPI-BEGIN---")
sys.stdout.write(json.dumps(app.openapi()))
"""


def generate_spec(service_dir: Path, module_path: str, attr: str) -> dict:
    """Generate one service's spec in an isolated subprocess."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-c", _WORKER, str(service_dir), module_path, attr],
        capture_output=True,
        text=True,
        timeout=180,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode != 0:
        tail = (result.stderr or "").strip().splitlines()
        raise RuntimeError(tail[-1] if tail else f"exit code {result.returncode}")

    # Services print banner output on import, so the JSON is delimited rather
    # than assumed to be the whole of stdout.
    marker = "---OPENAPI-BEGIN---"
    if marker not in result.stdout:
        raise RuntimeError("worker produced no spec output")
    return json.loads(result.stdout.split(marker, 1)[1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if committed specs differ from freshly generated ones.",
    )
    args = parser.parse_args()

    for key, value in GENERATION_ENV.items():
        os.environ.setdefault(key, value)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    stale: list[str] = []
    failed: list[str] = []

    for name, service_dir, module_path, attr in SERVICES:
        target = OUTPUT_DIR / f"{name}.json"
        try:
            spec = generate_spec(service_dir, module_path, attr)
        except Exception as exc:  # noqa: BLE001 - report and continue to other services
            print(f"  ERROR  {name}: could not generate spec ({type(exc).__name__}: {exc})")
            failed.append(name)
            continue

        rendered = json.dumps(spec, indent=2, sort_keys=True) + "\n"
        route_count = len(spec.get("paths", {}))

        if args.check:
            if not target.exists():
                print(f"  STALE  {name}: {target.relative_to(REPO_ROOT)} does not exist")
                stale.append(name)
            elif target.read_text(encoding="utf-8") != rendered:
                print(f"  STALE  {name}: {target.relative_to(REPO_ROOT)} is out of date")
                stale.append(name)
            else:
                print(f"  ok     {name}: {route_count} paths, spec current")
        else:
            target.write_text(rendered, encoding="utf-8")
            print(f"  wrote  {target.relative_to(REPO_ROOT)}  ({route_count} paths)")

    if failed:
        print(f"\nFailed to generate: {', '.join(failed)}")
        return 2
    if stale:
        print(
            f"\n{len(stale)} spec(s) out of date: {', '.join(stale)}\n"
            "Run: python ops/generate_openapi.py"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
