"""User-defined rules from ``[[custom_rules]]`` in sentinel.toml.

Same line-oriented contract as the built-in code rules: one finding per
matching line, evidence truncated, scanner tagged ``custom`` so reports can
tell team rules apart from built-ins.
"""

from __future__ import annotations

from ..config import CustomRule
from ..models import Finding
from .code import _ext_of  # shared extension classifier (Dockerfile/.env aware)


def scan_text(path: str, text: str, rules: list[CustomRule]) -> list[Finding]:
    """Run every custom rule that applies to this file's extension."""
    if not rules:
        return []
    ext = _ext_of(path)
    findings: list[Finding] = []
    lines = text.splitlines()
    for rule in rules:
        if rule.extensions is not None and ext not in rule.extensions:
            continue
        for lineno, line in enumerate(lines, 1):
            if not rule.regex.search(line):
                continue
            findings.append(Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                message=rule.message or f"{rule.title}: {line.strip()[:120]}",
                path=path,
                line=lineno,
                evidence=line.strip()[:160],
                fix=rule.fix,
                cwe=rule.cwe,
                confidence=rule.confidence,
                scanner="custom",
            ))
    return findings


def all_rules(rules: list[CustomRule]) -> list[tuple[str, str, object]]:
    """Catalog entries for ``sentinel rules``: (id, title, severity)."""
    return [(r.id, r.title, r.severity) for r in rules]
