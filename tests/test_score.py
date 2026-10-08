"""Score math, grades, gate logic."""

from pathlib import Path

from sentinel.engine import ScanResult
from sentinel.models import Finding, Severity
from sentinel.score import counts, gate_threshold, score, should_fail


def _findings(*severities: Severity) -> list[Finding]:
    out = []
    for sev in severities:
        out.append(Finding(rule_id="X", title="t", severity=sev, message="m",
                           path="a.py", line=1, evidence="e", fix="f", cwe="",
                           confidence="high", scanner="code"))
    return out


class TestScore:
    def test_empty_is_100_a(self):
        assert score([]) == (100, "A")

    def test_single_critical(self):
        assert score(_findings(Severity.CRITICAL)) == (75, "C")  # 100-25, band C

    def test_single_high(self):
        assert score(_findings(Severity.HIGH)) == (90, "A")

    def test_clamped_at_zero(self):
        many = _findings(*([Severity.CRITICAL] * 20 + [Severity.HIGH] * 30))
        assert score(many) == (0, "F")

    def test_band_b(self):
        # 100 - 4*3 medium = 88 -> B
        assert score(_findings(*([Severity.MEDIUM] * 4)))[1] == "B"

    def test_band_d(self):
        # 100 - 4*10 high = 60 -> D
        assert score(_findings(*([Severity.HIGH] * 4)))[1] == "D"

    def test_band_f(self):
        # 100 - 6*10 = 40 -> F
        assert score(_findings(*([Severity.HIGH] * 6)))[1] == "F"

    def test_info_never_deducts(self):
        assert score(_findings(*([Severity.INFO] * 50))) == (100, "A")

    def test_weights_ordering(self):
        assert (counts(_findings(Severity.CRITICAL, Severity.HIGH,
                                 Severity.MEDIUM, Severity.LOW, Severity.INFO))
                == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1, "INFO": 1})


class TestGateThreshold:
    def test_never_maps_to_none(self):
        for name in ("never", "off", "none", "NEVER"):
            assert gate_threshold(name) is None

    def test_severities(self):
        assert gate_threshold("critical") is Severity.CRITICAL
        assert gate_threshold("high") is Severity.HIGH
        assert gate_threshold("medium") is Severity.MEDIUM
        assert gate_threshold("low") is Severity.LOW


class TestShouldFail:
    def test_below_threshold_passes(self):
        fs = _findings(Severity.MEDIUM)
        assert should_fail(fs, "high") is False

    def test_at_threshold_fails(self):
        assert should_fail(_findings(Severity.MEDIUM), "medium") is True

    def test_high_fails_default_gate(self):
        assert should_fail(_findings(Severity.HIGH), "high") is True

    def test_never_always_passes(self):
        assert should_fail(_findings(Severity.CRITICAL), "never") is False

    def test_critical_does_not_fail_high_gate(self):
        # fail_on=critical means ONLY criticals gate
        assert should_fail(_findings(Severity.HIGH), "critical") is False
        assert should_fail(_findings(Severity.CRITICAL), "critical") is True


class TestExitFindings:
    def test_info_notes_excluded_from_gate(self):
        result = ScanResult(root=Path("."),
                            findings=_findings(Severity.INFO, Severity.LOW))
        assert [f.severity for f in result.exit_findings] == [Severity.LOW]

    def test_info_only_never_fails_any_gate(self):
        result = ScanResult(root=Path("."), findings=_findings(Severity.INFO))
        assert should_fail(result.exit_findings, "critical") is False
        assert should_fail(result.exit_findings, "high") is False
        assert should_fail(result.exit_findings, "low") is False
