"""Report diffing — fail CI only on findings that are NEW since a baseline.

``sentinel diff old.sarif new.sarif`` matches findings by the stable
``partialFingerprints`` id emitted in SARIF (and derivable from JSON
reports), so a finding that merely moved to another line is "unchanged",
not new+removed. Typical ratchet workflow::

    sentinel scan . -f sarif -o new.sarif
    sentinel diff baseline.sarif new.sarif --fail-on high
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, Severity


@dataclass(slots=True)
class DiffReport:
    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    unchanged: int = 0

    @property
    def new_at_or_above(self) -> list[Finding]:
        """Added findings with an unknown-or-real severity (all of them —
        kept as a helper so callers can filter by a threshold themselves)."""
        return list(self.added)


def _stable_id(rule_id: str, path: str, anchor: str) -> str:
    raw = f"{rule_id}|{path.replace(chr(92), '/')}|{anchor}".encode("utf-8")
    return hashlib.sha1(raw, usedforsecurity=False).hexdigest()[:12]


def _finding_from_sarif_result(item: dict) -> tuple[str, Finding] | None:
    try:
        rule_id = str(item["ruleId"])
        locs = item.get("locations") or [{}]
        phys = (locs[0].get("physicalLocation") or {}) if locs else {}
        path = (phys.get("artifactLocation") or {}).get("uri", "")
        line = int((phys.get("region") or {}).get("startLine", 0))
    except (KeyError, TypeError, ValueError):
        return None
    level = str(item.get("level", "warning")).lower()
    props = item.get("properties") or {}
    try:
        severity = Severity.parse(str(props.get("severity", "")))
    except ValueError:
        severity = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
                    "note": Severity.LOW}.get(level, Severity.MEDIUM)
    message = str((item.get("message") or {}).get("text", ""))
    fp = ((item.get("partialFingerprints") or {}).get("sentinelStable/v1")
          or _stable_id(rule_id, path, message[:120]))
    finding = Finding(
        rule_id=rule_id, title=str(props.get("title", rule_id)),
        severity=severity, message=message, path=path, line=line,
        scanner="sarif",
    )
    return fp, finding


def _finding_from_json(item: dict) -> tuple[str, Finding] | None:
    if not isinstance(item, dict) or "rule_id" not in item:
        return None
    try:
        severity = Severity.parse(str(item.get("severity", "medium")))
    except ValueError:
        severity = Severity.MEDIUM
    path = str(item.get("path", ""))
    evidence = str(item.get("evidence", ""))
    anchor = evidence.strip()[:120] if evidence.strip() else str(item.get("title", ""))
    fp = str(item.get("stable_id") or "") or _stable_id(str(item["rule_id"]), path, anchor)
    finding = Finding(
        rule_id=str(item["rule_id"]), title=str(item.get("title", "")),
        severity=severity, message=str(item.get("message", "")),
        path=path, line=int(item.get("line", 0) or 0),
        evidence=evidence, scanner="json",
    )
    return fp, finding


def load_report_findings(path: Path) -> dict[str, Finding]:
    """Load one SARIF 2.1.0 or sentinel JSON report → {stable_id: Finding}.

    Raises ``ValueError`` on unreadable / unrecognised files.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a sentinel/SARIF report")

    by_id: dict[str, Finding] = {}
    if "runs" in data:  # SARIF
        for run in data.get("runs") or []:
            for item in run.get("results") or []:
                parsed = _finding_from_sarif_result(item)
                if parsed:
                    by_id[parsed[0]] = parsed[1]
        return by_id
    if "findings" in data:  # sentinel JSON
        for item in data.get("findings") or []:
            parsed = _finding_from_json(item)
            if parsed:
                by_id[parsed[0]] = parsed[1]
        return by_id
    raise ValueError(f"{path}: unrecognised report format (need SARIF or sentinel JSON)")


def diff_reports(old: dict[str, Finding], new: dict[str, Finding]) -> DiffReport:
    added = [new[k] for k in new if k not in old]
    removed = [old[k] for k in old if k not in new]
    unchanged = sum(1 for k in new if k in old)
    added.sort(key=lambda f: (-int(f.severity), f.path, f.line))
    removed.sort(key=lambda f: (-int(f.severity), f.path, f.line))
    return DiffReport(added=added, removed=removed, unchanged=unchanged)


def render_diff(diff: DiffReport) -> str:
    lines: list[str] = []
    lines.append("")
    lines.append(f"  SENTINEL DIFF — {len(diff.added)} new · "
                 f"{len(diff.removed)} resolved · {diff.unchanged} unchanged")
    lines.append("")
    if diff.added:
        lines.append("  NEW FINDINGS")
        for f in diff.added:
            loc = f"{f.path}" + (f":{f.line}" if f.line else "")
            lines.append(f"    {f.severity.name:<8} {f.rule_id} {f.title} @ {loc}")
        lines.append("")
    if diff.removed:
        lines.append("  RESOLVED (present in old, gone in new)")
        for f in diff.removed[:20]:
            loc = f"{f.path}" + (f":{f.line}" if f.line else "")
            lines.append(f"    {f.severity.name:<8} {f.rule_id} @ {loc}")
        if len(diff.removed) > 20:
            lines.append(f"    … and {len(diff.removed) - 20} more")
        lines.append("")
    if not diff.added and not diff.removed:
        lines.append("  ✓ no changes")
        lines.append("")
    return "\n".join(lines)
