"""
Command-line entry point.

Two independent checks, matched to two different classes of finding:

    # CAGE-class: a function nobody calls from a real entry point
    python -m arto_reachability.cli reachability SOURCE_DIR \\
        --entry-points main,handle_request \\
        --targets atomic_verify_and_commit,replay_evaluate

    # Lelu-class: a branch that's unreachable due to threshold ordering
    python -m arto_reachability.cli ladders SOURCE_DIR
"""

from __future__ import annotations

import argparse
import sys

from .callgraph import build_call_graph
from .scanner import check_reachability, format_report
from .threshold_ladder import find_threshold_ladder_bugs


def _run_reachability(args) -> int:
    graph = build_call_graph(args.source_dir)
    entry_points = [e.strip() for e in args.entry_points.split(",") if e.strip()]
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]

    findings = check_reachability(graph, entry_points, targets)
    print(format_report(findings))

    return 1 if any(not f.reachable for f in findings) else 0


def _run_ladders(args) -> int:
    findings = find_threshold_ladder_bugs(args.source_dir)
    if not findings:
        print("No threshold-ladder subsumption found.")
        return 0
    for f in findings:
        print(f.explain())
    return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Static checks for 'the enforcement outcome you expect isn't actually reachable.'"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    reach = sub.add_parser(
        "reachability",
        help="CAGE-class: is this named function ever called from a real entry point?",
    )
    reach.add_argument("source_dir", help="Root directory of the codebase to scan")
    reach.add_argument(
        "--entry-points",
        required=True,
        help="Comma-separated simple names of real execution entry points",
    )
    reach.add_argument(
        "--targets",
        required=True,
        help="Comma-separated simple names of safety-critical functions to check",
    )

    ladders = sub.add_parser(
        "ladders",
        help="Lelu-class: does an earlier threshold branch make a later one unreachable?",
    )
    ladders.add_argument("source_dir", help="Root directory of the codebase to scan")

    args = parser.parse_args(argv)

    if args.command == "reachability":
        return _run_reachability(args)
    return _run_ladders(args)


if __name__ == "__main__":
    sys.exit(main())
