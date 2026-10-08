"""Findings and severity model shared by every scanner module."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered severity — IntEnum so severities compare and sort directly."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name

    @classmethod
    def parse(cls, value: str | int) -> "Severity":
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[str(value).upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc


# Deduction model: criticals hurt the score far more than lows.
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass(slots=True)
class Finding:
    """One security finding.

    ``evidence`` is stored ALREADY REDACTED for secret findings — reports
    must never echo a live credential back to the terminal or CI log.
    """

    rule_id: str
    title: str
    severity: Severity
    message: str
    path: str
    line: int = 0
    evidence: str = ""
    fix: str = ""
    cwe: str = ""
    confidence: str = "high"  # high | medium | low
    scanner: str = ""  # secrets | code | git | deps
    meta: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        """Dedupe key — same rule hitting the same line is one finding."""
        return (self.rule_id, self.path, self.line, self.message[:80])

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.name,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "fix": self.fix,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "scanner": self.scanner,
        }
