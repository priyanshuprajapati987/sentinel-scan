"""Score (0-100) and letter grade from findings."""

from __future__ import annotations

from collections import Counter

from .models import SEVERITY_WEIGHT, Finding, Severity


def score(findings: list[Finding]) -> tuple[int, str]:
    """Return (score, grade).

    * 100 minus weighted deductions (critical 25 / high 10 / medium 3 / low 1).
    * Score clamped to 0.
    * Grade bands: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 50, F < 50.
    * Any CRITICAL caps the grade at D — one leaked prod key is never an "A".
    """
    deductions = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    s = max(0, 100 - deductions)
    if s >= 90:
        grade = "A"
    elif s >= 80:
        grade = "B"
    elif s >= 70:
        grade = "C"
    elif s >= 50:
        grade = "D"
    else:
        grade = "F"
    if any(f.severity is Severity.CRITICAL for f in findings) and grade in ("A", "B"):
        grade = "D"
    return s, grade


def counts(findings: list[Finding]) -> dict[str, int]:
    c: Counter[str] = Counter(f.severity.name for f in findings)
    return {name: c.get(name, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}


def gate_threshold(fail_on: str) -> Severity | None:
    """Map --fail-on to the minimum severity that fails the build.

    ``never``/``off`` → None (always exit 0 for findings).
    """
    if fail_on.lower() in {"never", "off", "none"}:
        return None
    return Severity.parse(fail_on)


def should_fail(findings: list[Finding], fail_on: str) -> bool:
    threshold = gate_threshold(fail_on)
    if threshold is None:
        return False
    return any(f.severity >= threshold for f in findings)
