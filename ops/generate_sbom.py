#!/usr/bin/env python3
"""
Generate a lightweight SBOM from local requirements files.
Outputs a JSON file suitable for evidence in AIVSS supply chain reporting.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Dict, List, Tuple


REQUIREMENT_FILES = [
    "tessera/requirements.txt",
    "vestigia/requirements.txt",
    "verityflux-v2/requirements.txt",
    "verityflux-v2/requirements_enterprise.txt",
]


def _parse_requirement(line: str) -> Tuple[str, str]:
    cleaned = line.strip()
    if not cleaned or cleaned.startswith("#"):
        return "", ""
    for sep in ("==", ">=", "<=", "~=", ">", "<"):
        if sep in cleaned:
            name, version = cleaned.split(sep, 1)
            return name.strip(), f"{sep}{version.strip()}"
    return cleaned, ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SBOM from requirements files.")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    components: List[Dict[str, str]] = []
    for rel_path in REQUIREMENT_FILES:
        path = Path(rel_path)
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                name, version = _parse_requirement(line)
                if not name:
                    continue
                components.append(
                    {
                        "name": name,
                        "version": version or "unversioned",
                        "source_file": rel_path,
                        "type": "pypi",
                    }
                )

    output_path = Path(args.output) if args.output else Path("ops/evidence") / f"sbom_{dt.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": dt.datetime.utcnow().isoformat() + "Z",
        "component_count": len(components),
        "components": components,
    }
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    print(f"SBOM written: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
