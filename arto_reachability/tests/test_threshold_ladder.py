import textwrap

from arto_reachability import find_threshold_ladder_bugs


def _write(tmp_path, filename, content):
    path = tmp_path / filename
    path.write_text(textwrap.dedent(content))
    return path


# --- The actual Lelu bug, reproduced verbatim in shape ---
#
# escalator.go's Escalate(): checks threshold before threshold+0.3, so the
# deny branch is unreachable once the calibrator is fitted. Reproduced here
# in Python with the identical logic shape (sequential early-return ifs).
def test_lelu_escalate_shape_is_caught(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(calibrated, threshold):
            if calibrated >= threshold:
                return "ActionReview"
            if calibrated >= threshold + 0.3:
                return "ActionDeny"
            return "ActionAllow"
        """,
    )
    # Note: `threshold + 0.3` is not a constant the checker can evaluate
    # (it's a runtime parameter, not a literal) -- this variant is out of
    # scope for constant-threshold subsumption and won't be flagged. The
    # literal-constant version below is the shape this checker actually
    # covers; this test documents the boundary rather than asserting a
    # false positive.
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []


def test_lelu_shape_with_literal_thresholds_is_caught(tmp_path):
    """Same bug shape, but with literal numeric thresholds -- the case this
    checker is actually built for."""
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(calibrated):
            if calibrated >= 0.4:
                return "ActionReview"
            if calibrated >= 0.7:
                return "ActionDeny"
            return "ActionAllow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.function_qualname == "escalate"
    assert f.earlier.threshold == 0.4
    assert f.later.threshold == 0.7
    assert f.later.lineno == 5


def test_correctly_ordered_ladder_is_not_flagged(tmp_path):
    """The fix: check the higher threshold first. No subsumption possible."""
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(calibrated):
            if calibrated >= 0.7:
                return "ActionDeny"
            if calibrated >= 0.4:
                return "ActionReview"
            return "ActionAllow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []


def test_elif_chain_variant_is_caught(tmp_path):
    """The same bug, written as if/elif instead of sequential early returns
    -- equally common in real code, and structurally identical: reaching
    the elif still requires failing the earlier condition."""
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score):
            if score >= 0.4:
                return "review"
            elif score >= 0.7:
                return "deny"
            else:
                return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].earlier.threshold == 0.4
    assert findings[0].later.threshold == 0.7


def test_three_tier_elif_ladder_flags_only_the_subsumed_pair(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score):
            if score >= 0.9:
                return "critical"
            elif score >= 0.3:
                return "review"
            elif score >= 0.6:
                return "deny"
            else:
                return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    # 0.3 (second) subsumes 0.6 (third); 0.9 (first) doesn't subsume either
    # since both later thresholds (0.3, 0.6) are lower than 0.9, so those
    # branches ARE still reachable for values below 0.9.
    pairs = {(f.earlier.threshold, f.later.threshold) for f in findings}
    assert pairs == {(0.3, 0.6)}


def test_no_duplicate_findings_for_same_pair(tmp_path):
    """Regression: the elif-chain traversal recurses into its own tail,
    which could otherwise report the same subsumed pair twice."""
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score):
            if score >= 0.2:
                return "a"
            elif score >= 0.5:
                return "b"
            elif score >= 0.8:
                return "c"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    keys = [(f.earlier.lineno, f.later.lineno) for f in findings]
    assert len(keys) == len(set(keys))


def test_different_variables_are_not_compared(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score, other_score):
            if score >= 0.4:
                return "review"
            if other_score >= 0.7:
                return "deny"
            return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []


def test_mixed_directions_are_not_compared(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score):
            if score >= 0.4:
                return "review"
            if score <= 0.1:
                return "safe"
            return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []


def test_descending_direction_ladder_is_caught(tmp_path):
    """The mirror-image bug: checking a loose 'at most this good' bound
    before a tighter one makes the tighter one unreachable."""
    _write(
        tmp_path,
        "healthcheck.py",
        """
        def classify(latency_ms):
            if latency_ms <= 500:
                return "acceptable"
            if latency_ms <= 100:
                return "excellent"
            return "slow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].earlier.threshold == 500
    assert findings[0].later.threshold == 100


def test_attribute_lhs_is_supported(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        class Escalator:
            def escalate(self, calibrated):
                if self.confidence >= 0.4:
                    return "review"
                if self.confidence >= 0.7:
                    return "deny"
                return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].function_qualname == "Escalator.escalate"
    assert findings[0].earlier.lhs_repr == "self.confidence"


def test_non_constant_threshold_is_not_flagged(tmp_path):
    """A threshold that isn't a literal (e.g. a parameter or attribute)
    can't be compared arithmetically without value-flow analysis -- out of
    scope, so this must not be silently mis-flagged."""
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score, threshold):
            if score >= threshold:
                return "review"
            if score >= threshold:
                return "deny"
            return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []


def test_ladder_inside_nested_block_is_found(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def handle(score, enabled):
            if enabled:
                if score >= 0.4:
                    return "review"
                if score >= 0.7:
                    return "deny"
            return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert len(findings) == 1


def test_single_if_is_not_a_ladder(tmp_path):
    _write(
        tmp_path,
        "escalator.py",
        """
        def escalate(score):
            if score >= 0.4:
                return "review"
            return "allow"
        """,
    )
    findings = find_threshold_ladder_bugs(str(tmp_path))
    assert findings == []
