#!/usr/bin/env python3
"""
Evaluate an AIVSS report against release gate thresholds.
Exit codes:
  0 = PASS
  1 = FAIL (critical findings)
  2 = REQUIRE_APPROVAL (high findings)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AIVSS report for release gating.")
    parser.add_argument("report", help="Path to AIVSS report JSON")
    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        print(f"Report not found: {report_path}")
        return 1

    with report_path.open("r", encoding="utf-8") as handle:
        report = json.load(handle)

    vulnerabilities = report.get("vulnerabilities", [])
    max_score = 0.0
    critical = []
    high = []
    for vuln in vulnerabilities:
        scores = vuln.get("scores", {})
        aivss = float(scores.get("aivss", 0.0))
        severity = scores.get("severity", "")
        max_score = max(max_score, aivss)
        if severity == "Critical" or aivss >= 9.0:
            critical.append(vuln.get("owasp_category", vuln.get("id", "unknown")))
        elif severity == "High" or aivss >= 7.0:
            high.append(vuln.get("owasp_category", vuln.get("id", "unknown")))

    print(f"Max AIVSS score: {max_score:.1f}")
    if critical:
        print("Gate: FAIL (Critical findings)")
        print("Critical categories:", ", ".join(sorted(set(critical))))
        return 1
    if high:
        print("Gate: REQUIRE_APPROVAL (High findings)")
        print("High categories:", ", ".join(sorted(set(high))))
        return 2

    print("Gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
