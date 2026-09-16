"""
A best-effort, AST-based call graph builder for Python source trees.

This automates the manual step behind every "control that's never called"
finding produced in this research so far (CAGE's atomic_verify_and_commit,
PyRIT's replay-check gap, AgentDojo and garak's missing trajectory
detectors): grep for callers of a named function, and read whether any of
them sit on a path actually reached from a real entry point.

Resolution is by simple (unqualified) name, the same way that manual grep
was — not fully-qualified, type-resolved dispatch. This is a deliberate,
documented limitation, not an oversight: sound call-graph construction for
dynamic Python (decorators, getattr, importlib, monkeypatching) requires
whole-program type inference that a static AST pass cannot give you. Name
resolution catches everything a `grep -rn "def foo"` / `grep -rn "foo("`
pass would have caught, and nothing more or less. Treat this tool as an
automation of that manual step, not a soundness proof.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, Set


@dataclass
class FunctionDef:
    """One function or method definition found in the source tree."""

    name: str
    qualname: str  # "ClassName.method_name" or just "function_name"
    file: str
    lineno: int


@dataclass
class CallGraph:
    """
    edges: simple function/method name -> set of simple names called
        anywhere in that function's body (including nested functions).
    definitions: every FunctionDef found, keyed by qualname, so a finding
        can be reported with a real file:line rather than just a name.
    """

    edges: Dict[str, Set[str]] = field(default_factory=dict)
    definitions: Dict[str, FunctionDef] = field(default_factory=dict)

    def callees_of(self, name: str) -> Set[str]:
        return self.edges.get(name, set())


class _CallCollector(ast.NodeVisitor):
    """Collects simple names of everything called within a function body."""

    def __init__(self) -> None:
        self.called: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name):
            self.called.add(func.id)
        elif isinstance(func, ast.Attribute):
            # obj.method(...) -> record "method"; this is the same
            # resolution a plain `grep "\.method_name("` pass gives you.
            self.called.add(func.attr)
        self.generic_visit(node)


def _iter_function_defs(
    tree: ast.Module, file: str
) -> Iterable[tuple[str, str, ast.AST]]:
    """Yield (simple_name, qualname, node) for every function/method def."""

    class _Walker(ast.NodeVisitor):
        def __init__(self) -> None:
            self.class_stack: list[str] = []
            self.found: list[tuple[str, str, ast.AST]] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.class_stack.append(node.name)
            self.generic_visit(node)
            self.class_stack.pop()

        def _visit_func(self, node) -> None:
            simple = node.name
            qual = ".".join(self.class_stack + [simple]) if self.class_stack else simple
            self.found.append((simple, qual, node))
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_func(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_func(node)

    walker = _Walker()
    walker.visit(tree)
    return walker.found


def build_call_graph(source_dir: str, exclude_dirs: Iterable[str] = ("tests", "test", "__pycache__")) -> CallGraph:
    """
    Parse every .py file under source_dir and build a best-effort call graph.

    Args:
        source_dir: root directory to scan, recursively.
        exclude_dirs: directory names to skip entirely (default excludes
            test directories, since a function only "called" from its own
            test is exactly the CAGE-class gap this tool exists to catch —
            counting test-only callers as reachability would hide the
            finding, not surface it).

    Returns:
        CallGraph with one edge-set per function/method simple name, and
        every definition's real file:line for reporting.
    """
    graph = CallGraph()
    root = Path(source_dir)
    exclude = set(exclude_dirs)

    for py_file in root.rglob("*.py"):
        if exclude & set(p.name for p in py_file.parents):
            continue
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue  # best-effort: skip unparseable files rather than fail the whole scan

        for simple_name, qualname, node in _iter_function_defs(tree, str(py_file)):
            collector = _CallCollector()
            collector.visit(node)

            existing = graph.edges.get(simple_name, set())
            graph.edges[simple_name] = existing | collector.called

            graph.definitions[f"{py_file}:{qualname}"] = FunctionDef(
                name=simple_name,
                qualname=qualname,
                file=str(py_file),
                lineno=getattr(node, "lineno", 0),
            )

    return graph


__all__ = ["CallGraph", "FunctionDef", "build_call_graph"]
