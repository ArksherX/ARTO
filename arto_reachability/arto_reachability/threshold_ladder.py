"""
Threshold-ladder subsumption checker: the tractable slice of the Lelu-class
finding (an unreachable branch inside a live function), as opposed to the
reachability scanner's CAGE-class finding (a function nobody calls at all).

The Lelu bug's actual shape: two threshold comparisons against the same
score, evaluated as early returns in the wrong order.

    if calibrated >= threshold:        # catches everything >= threshold ...
        return ActionReview
    if calibrated >= threshold + 0.3:  # ... so this needs > threshold too,
        return ActionDeny              # which the first check already caught.

This is NOT general branch-reachability analysis, which needs symbolic
execution over arbitrary conditions and runtime values -- a much larger
undertaking this module does not attempt. What's checkable without a
theorem prover is the narrow, common case this module targets: a sequence
of comparisons of the *same* left-hand expression against *constant*
numeric thresholds, using the *same* directional operator. Under those
three constraints, "does an earlier branch already cover everything a
later branch needs" is pure arithmetic on the thresholds, not a general
satisfiability problem -- and severity-tier / escalation-ladder logic
(review/deny/block cascades) overwhelmingly is written in exactly this
constrained shape, which is why this narrow check is worth having despite
not solving the general problem.

Two call shapes are covered, because real code splits between both styles:
  1. Sequential early-return ifs: `if cond: return X` statements as
     siblings, each with no else, each body ending in return.
  2. if/elif chains: `if cond: return X  elif cond2: return Y  ...`

Both have the same reachability semantics (a later branch is only ever
reached if every earlier condition was false), so the same subsumption
check applies to both once the ladder of conditions is extracted.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# Only these two directions are supported. Both are common in severity-tier
# code ("at least this bad" / "at most this good"); mixing directions within
# one ladder, or using == / !=, is out of scope -- flagged, not silently
# mishandled (see _extract_ladder's early-exit on a shape it can't read).
_ASCENDING = {ast.GtE: ">=", ast.Gt: ">"}
_DESCENDING = {ast.LtE: "<=", ast.Lt: "<"}


@dataclass
class LadderStep:
    lineno: int
    lhs_repr: str
    op: str
    threshold: float
    return_repr: str


@dataclass
class SubsumptionFinding:
    """An earlier branch makes a later branch unreachable."""

    function_qualname: str
    file: str
    earlier: LadderStep
    later: LadderStep

    def explain(self) -> str:
        return (
            f"{self.function_qualname} ({self.file}): the branch at line "
            f"{self.later.lineno} (`{self.later.lhs_repr} {self.later.op} "
            f"{self.later.threshold}` -> {self.later.return_repr}) is "
            f"unreachable -- the branch at line {self.earlier.lineno} "
            f"(`{self.earlier.lhs_repr} {self.earlier.op} "
            f"{self.earlier.threshold}` -> {self.earlier.return_repr}) "
            f"already catches every value that would satisfy it."
        )


def _lhs_key(node: ast.expr) -> Optional[str]:
    """A syntactic identity string for the comparison's left-hand side, so
    two comparisons can be checked for referring to 'the same' value.
    Only Name and simple Attribute chains are supported (`x`, `self.x`,
    `obj.attr.attr`) -- anything else (a call, a subscript, a binop) is
    treated as unresolvable, matching this module's stated scope."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _lhs_key(node.value)
        return f"{base}.{node.attr}" if base is not None else None
    return None


def _extract_step(node: ast.If) -> Optional[Tuple[LadderStep, str]]:
    """
    If node.test is `<lhs> <op> <constant>` with a supported op, and
    node.body's last statement is a return, produce a LadderStep and a
    'direction' tag ("asc" or "desc"). Otherwise None -- this if isn't part
    of a checkable ladder (compound condition, non-constant threshold,
    non-return body, etc.), and the whole ladder starting here is skipped
    rather than guessed at.
    """
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return None

    op = test.ops[0]
    direction = None
    op_symbol = None
    if type(op) in _ASCENDING:
        direction, op_symbol = "asc", _ASCENDING[type(op)]
    elif type(op) in _DESCENDING:
        direction, op_symbol = "desc", _DESCENDING[type(op)]
    else:
        return None

    lhs_key = _lhs_key(test.left)
    if lhs_key is None:
        return None

    threshold_node = test.comparators[0]
    if not isinstance(threshold_node, ast.Constant) or not isinstance(
        threshold_node.value, (int, float)
    ):
        return None

    if not node.body or not isinstance(node.body[-1], (ast.Return, ast.Raise)):
        return None  # doesn't end in return/raise -- early-return semantics don't hold

    return_repr = ast.unparse(node.body[-1]) if hasattr(ast, "unparse") else "<return>"

    step = LadderStep(
        lineno=node.lineno,
        lhs_repr=lhs_key,
        op=op_symbol,
        threshold=float(threshold_node.value),
        return_repr=return_repr,
    )
    return step, direction


def _walk_ladders(body: List[ast.stmt]):
    """
    Yield candidate ladders: lists of (LadderStep, direction, lhs_key) from
    consecutive if-statements at the same block level -- either sibling
    early-return ifs, or a single if/elif/elif chain (represented in the
    AST as nested If nodes in `orelse`).
    """
    i = 0
    while i < len(body):
        stmt = body[i]
        if isinstance(stmt, ast.If):
            ladder = []
            extracted = _extract_step(stmt)
            if extracted:
                ladder.append(extracted)

                # Case 2: if/elif chain -- walk down node.orelse as long as
                # it's exactly one more If (that's what elif compiles to).
                cursor = stmt
                while (
                    len(cursor.orelse) == 1
                    and isinstance(cursor.orelse[0], ast.If)
                ):
                    cursor = cursor.orelse[0]
                    step = _extract_step(cursor)
                    if step is None:
                        break
                    ladder.append(step)

                if len(ladder) >= 2:
                    yield ladder

                # Case 1: sibling early-return ifs. Only meaningful if this
                # `if` had no elif/else of its own (orelse is empty) and its
                # body ends in return -- otherwise control never reaches the
                # next sibling unconditionally the way this check assumes.
                if not stmt.orelse and stmt.body and isinstance(stmt.body[-1], (ast.Return, ast.Raise)):
                    sibling_ladder = [extracted]
                    j = i + 1
                    while j < len(body) and isinstance(body[j], ast.If) and not body[j].orelse:
                        step = _extract_step(body[j])
                        if step is None:
                            break
                        sibling_ladder.append(step)
                        if not (body[j].body and isinstance(body[j].body[-1], (ast.Return, ast.Raise))):
                            break
                        j += 1
                    if len(sibling_ladder) >= 2:
                        yield sibling_ladder

            # Recurse into nested blocks regardless (a ladder can live inside
            # an outer if/for/etc.)
            yield from _walk_ladders(stmt.body)
            yield from _walk_ladders(stmt.orelse)
        i += 1

    # Generic recursion into any nested statement blocks not already covered
    # above (function/class defs, loops, with-blocks, try-blocks).
    for stmt in body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield from _walk_ladders(stmt.body)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith)):
            yield from _walk_ladders(stmt.body)
        elif isinstance(stmt, ast.Try):
            yield from _walk_ladders(stmt.body)
            for handler in stmt.handlers:
                yield from _walk_ladders(handler.body)


def _check_ladder(ladder, same_lhs_required: bool = True) -> List[Tuple[LadderStep, LadderStep]]:
    """Given a ladder of (step, direction) pairs in evaluated order, return
    (earlier, later) pairs where earlier subsumes later."""
    findings = []
    for idx in range(len(ladder) - 1):
        step_a, dir_a = ladder[idx]
        for jdx in range(idx + 1, len(ladder)):
            step_b, dir_b = ladder[jdx]
            if dir_a != dir_b or step_a.lhs_repr != step_b.lhs_repr:
                continue  # different variable or mixed direction -- not comparable
            if dir_a == "asc" and step_b.threshold >= step_a.threshold:
                # reaching step_b requires having failed step_a (value < step_a.threshold),
                # but step_b needs value >= step_b.threshold >= step_a.threshold -- contradiction.
                findings.append((step_a, step_b))
            elif dir_a == "desc" and step_b.threshold <= step_a.threshold:
                findings.append((step_a, step_b))
    return findings


def find_threshold_ladder_bugs(source_dir: str) -> List[SubsumptionFinding]:
    """
    Scan every .py file under source_dir for the Lelu-class pattern: a
    sequence of same-variable, constant-threshold, same-direction
    comparisons where an earlier branch subsumes a later one.
    """
    findings: List[SubsumptionFinding] = []
    root = Path(source_dir)

    for py_file in root.rglob("*.py"):
        if "__pycache__" in py_file.parts:
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError):
            continue

        class _FuncWalker(ast.NodeVisitor):
            def __init__(self):
                self.class_stack: List[str] = []

            def visit_ClassDef(self, node):
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()

            def _visit(self, node):
                qualname = ".".join(self.class_stack + [node.name]) if self.class_stack else node.name
                for ladder in _walk_ladders(node.body):
                    for earlier, later in _check_ladder(ladder):
                        findings.append(
                            SubsumptionFinding(
                                function_qualname=qualname,
                                file=str(py_file),
                                earlier=earlier,
                                later=later,
                            )
                        )
                self.generic_visit(node)

            def visit_FunctionDef(self, node):
                self._visit(node)

            def visit_AsyncFunctionDef(self, node):
                self._visit(node)

        _FuncWalker().visit(tree)

    # An if/elif chain of length N is walked both as a whole and, on
    # recursion, as each of its own tails (elif-chain-from-the-second-branch,
    # etc.) -- so the same (earlier, later) pair can legitimately surface
    # more than once. Dedupe on the pair of line numbers within a function
    # rather than complicating the traversal to visit each node once.
    seen = set()
    deduped: List[SubsumptionFinding] = []
    for f in findings:
        key = (f.file, f.function_qualname, f.earlier.lineno, f.later.lineno)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


__all__ = ["LadderStep", "SubsumptionFinding", "find_threshold_ladder_bugs"]
