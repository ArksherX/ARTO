import textwrap

import pytest

from arto_reachability import build_call_graph, check_reachability, format_report


def _write(tmp_path, filename, content):
    path = tmp_path / filename
    path.write_text(textwrap.dedent(content))
    return path


def test_simple_reachable_target(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        def helper():
            return 1

        def main():
            return helper()
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["helper"])
    assert findings[0].reachable is True
    assert "main" in findings[0].reached_via


def test_unreachable_target_zero_callers(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        def unused_safety_check():
            return True

        def main():
            return 42
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["unused_safety_check"])
    assert findings[0].reachable is False
    assert len(findings[0].definitions) == 1
    assert findings[0].definitions[0].lineno > 0


def test_target_not_found_anywhere(tmp_path):
    _write(tmp_path, "app.py", "def main():\n    pass\n")
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["does_not_exist"])
    assert findings[0].reachable is False
    assert findings[0].definitions == []


def test_same_named_call_to_undefined_target_is_not_reachable(tmp_path):
    """A call to a name whose definition lives outside the scanned source
    (e.g. a third-party/external package) must not be reported as
    'reachable' for a target with no known definition -- that would claim
    reachability for a function we never actually found."""
    _write(
        tmp_path,
        "app.py",
        """
        def main():
            return update()  # 'update' is not defined anywhere in this tree
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["update"])
    assert findings[0].reachable is False
    assert findings[0].definitions == []


def test_transitive_reachability(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        def deep_check():
            return True

        def middle():
            return deep_check()

        def main():
            return middle()
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["deep_check"])
    assert findings[0].reachable is True


def test_method_call_resolution(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        class Gate:
            def verify(self):
                return True

        def main():
            g = Gate()
            return g.verify()
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(graph, entry_points=["main"], safety_critical_targets=["verify"])
    assert findings[0].reachable is True


def test_test_only_caller_does_not_count_as_reachable(tmp_path):
    """A function called only from its own test suite is exactly the
    CAGE-class gap this tool exists to surface -- test-only callers must
    not be treated as reachability."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    _write(
        tmp_path,
        "src/app.py",
        """
        def atomic_verify_and_commit():
            return True

        def execute_trade_action():
            return "unrelated split check-then-write path"

        def main():
            return execute_trade_action()
        """,
    )
    _write(
        tmp_path,
        "tests/test_app.py",
        """
        from src.app import atomic_verify_and_commit

        def test_it():
            assert atomic_verify_and_commit() is True
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(
        graph, entry_points=["main"], safety_critical_targets=["atomic_verify_and_commit"]
    )
    assert findings[0].reachable is False


def test_format_report_lists_unreachable_first(tmp_path):
    _write(
        tmp_path,
        "app.py",
        """
        def reachable_fn():
            return True

        def unreachable_fn():
            return True

        def main():
            return reachable_fn()
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(
        graph, entry_points=["main"], safety_critical_targets=["reachable_fn", "unreachable_fn"]
    )
    report = format_report(findings)
    # unreachable_fn must appear before reachable_fn in the rendered report
    assert report.index("UNREACHABLE] unreachable_fn") < report.index("REACHABLE] reachable_fn")


# --- Regression case modeled on the actual CAGE-SEC-002 finding shape ---
#
# atomic_verify_and_commit() was real, well-built, and had zero callers on
# the production execute_trade_action path -- the live path went through a
# separate split verify_action()/update_state() pair instead. This test
# reproduces that exact shape as a fixture to confirm the tool would have
# flagged it.
def test_cage_sec_002_shape_is_caught(tmp_path):
    _write(
        tmp_path,
        "cbf.py",
        """
        class ControlBarrierFunction:
            def atomic_verify_and_commit(self, action, payload):
                # Lua-atomic check+commit -- never called by execute_trade_action below.
                return (True, "COMMITTED")

            def verify_action(self, action, payload):
                return True

            def update_state(self, cost):
                return None
        """,
    )
    _write(
        tmp_path,
        "mcp_tool_server.py",
        """
        from cbf import ControlBarrierFunction

        def execute_trade_action(action, payload):
            cbf = ControlBarrierFunction()
            if cbf.verify_action(action, payload):
                cbf.update_state(payload.get("amount"))
            return True
        """,
    )
    graph = build_call_graph(str(tmp_path))
    findings = check_reachability(
        graph,
        entry_points=["execute_trade_action"],
        safety_critical_targets=["atomic_verify_and_commit", "verify_action", "update_state"],
    )
    by_name = {f.target: f for f in findings}
    assert by_name["atomic_verify_and_commit"].reachable is False
    assert by_name["verify_action"].reachable is True
    assert by_name["update_state"].reachable is True
