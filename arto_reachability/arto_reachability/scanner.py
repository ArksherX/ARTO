"""
Reachability analysis: given a call graph, a set of entry points, and a set
of named safety-critical targets, report which targets are never reached.

This is the CAGE-class finding, automated: "a control exists in code but
the enforcing call path doesn't traverse it." It does not detect the
Lelu-class finding (a branch inside a function that IS called, but whose
specific outcome is unreachable due to condition ordering) — that requires
symbolic execution over branch conditions, not call-graph traversal, and is
explicitly out of scope for this tool.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Set

from .callgraph import CallGraph, FunctionDef


@dataclass
class ReachabilityFinding:
    """One safety-critical target that no traced entry point ever reaches."""

    target: str
    definitions: List[FunctionDef]  # every place this name is defined (file:line)
    reachable: bool
    reached_via: Set[str]  # entry points that DO reach it, if reachable


def _reachable_names(graph: CallGraph, entry_points: Iterable[str]) -> dict:
    """
    BFS from each entry point over the call graph's edges.

    Returns: {reachable_simple_name: set of entry points that reach it}
    """
    reached: dict = {}
    for entry in entry_points:
        seen: Set[str] = set()
        frontier = [entry]
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            seen.add(current)
            for callee in graph.callees_of(current):
                if callee not in seen:
                    frontier.append(callee)
        for name in seen:
            reached.setdefault(name, set()).add(entry)
    return reached


def check_reachability(
    graph: CallGraph,
    entry_points: Iterable[str],
    safety_critical_targets: Iterable[str],
) -> List[ReachabilityFinding]:
    """
    For each named safety-critical target, determine whether it's reachable
    from any of the given entry points.

    Args:
        graph: a CallGraph from build_call_graph().
        entry_points: simple names of functions where real execution
            begins (e.g. an HTTP handler, a CLI's main(), a request
            dispatcher) — the same starting points you'd pick by hand
            when tracing "what does the production path actually call."
        safety_critical_targets: simple names of functions that are
            supposed to be on some enforcement path — the things you'd
            grep for callers of.

    Returns:
        One ReachabilityFinding per target, in the order given. A target
        whose name doesn't appear anywhere in the codebase is reported as
        unreachable with an empty definitions list — that's itself worth
        surfacing (the name may be misspelled, or genuinely doesn't exist).
    """
    reached = _reachable_names(graph, entry_points)
    findings: List[ReachabilityFinding] = []

    for target in safety_critical_targets:
        defs = [d for d in graph.definitions.values() if d.name == target]
        reached_via = reached.get(target, set())
        # A same-named call reaching outside the scanned source (e.g. a
        # third-party library function) is not evidence that a specific
        # target definition is wired in -- only claim reachable when we
        # actually found the definition being asked about.
        reachable = bool(reached_via) and bool(defs)
        findings.append(
            ReachabilityFinding(
                target=target,
                definitions=defs,
                reachable=reachable,
                reached_via=reached_via,
            )
        )

    return findings


def format_report(findings: Iterable[ReachabilityFinding]) -> str:
    """Render findings as a plain-text report, unreachable targets first."""
    findings = sorted(findings, key=lambda f: f.reachable)  # unreachable (False) sorts first
    lines = []
    for f in findings:
        if not f.definitions:
            # No definition found in the scanned tree at all. A name that
            # also happens to be "reached" here means something calls a
            # same-named function defined outside the scanned source (e.g.
            # an external dependency) -- that's not evidence the target
            # you meant is wired in, so don't report it as REACHABLE.
            lines.append(f"[NOT FOUND] {f.target}")
            lines.append("    no definition in scanned source — check spelling / scope")
            if f.reached_via:
                lines.append(
                    f"    note: a same-named call exists (via {', '.join(sorted(f.reached_via))}), "
                    "but its definition is outside the scanned source — verify separately"
                )
            continue

        status = "REACHABLE" if f.reachable else "UNREACHABLE"
        lines.append(f"[{status}] {f.target}")
        for d in f.definitions:
            lines.append(f"    defined at {d.file}:{d.lineno} ({d.qualname})")
        if f.reachable:
            lines.append(f"    reached via: {', '.join(sorted(f.reached_via))}")
    return "\n".join(lines)


__all__ = ["ReachabilityFinding", "check_reachability", "format_report"]
