"""Report diffing — fail CI only on findings that are NEW since a baseline.

``sentinel diff old.sarif new.sarif`` matches findings by the stable
``partialFingerprints`` id emitted in SARIF (and derivable from JSON
reports), so a finding that merely moved to another line is "unchanged",
not new+removed. Duplicate stable ids keep their multiplicity — a second
occurrence of the same finding counts as NEW, never silently collapsed.
Typical ratchet workflow::

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

    def new_at_or_above(self, min_severity: Severity) -> list[Finding]:
        """Added findings with severity >= ``min_severity``."""
        return [f for f in self.added if f.severity >= min_severity]


def _stable_id(rule_id: str, path: str, anchor: str) -> str:
    raw = f"{rule_id}|{path.replace(chr(92), '/')}|{anchor}".encode("utf-8")
    return hashlib.sha1(raw, usedforsecurity=False).hexdigest()[:12]


def _finding_from_sarif_result(item: dict) -> tuple[str, Finding] | None:
    if not isinstance(item, dict):
        return None
    try:
        rule_id = str(item["ruleId"])
        locs = item.get("locations") or [{}]
        phys = (locs[0].get("physicalLocation") or {}) if locs else {}
        path = str((phys.get("artifactLocation") or {}).get("uri", ""))
        # startLine: null / missing → 0 (file-level), do not drop the finding
        line = int((phys.get("region") or {}).get("startLine") or 0)
        level = str(item.get("level", "warning")).lower()
        props = item.get("properties")
        if not isinstance(props, dict):
            props = {}
        try:
            severity = Severity.parse(str(props.get("severity", "")).strip())
        except ValueError:
            severity = {"error": Severity.HIGH, "warning": Severity.MEDIUM,
                        "note": Severity.LOW}.get(level, Severity.MEDIUM)
        # message may be a plain string instead of {"text": ...}
        msg = item.get("message")
        message = str((msg.get("text", "") if isinstance(msg, dict) else msg) or "")
        finding = Finding(
            rule_id=rule_id, title=str(props.get("title", rule_id)),
            severity=severity, message=message, path=path, line=line,
            scanner="sarif",
        )
        fps = item.get("partialFingerprints")
        fp = fps.get("sentinelStable/v1") if isinstance(fps, dict) else None
        # fallback id = same computation as Finding.stable_fingerprint so
        # JSON and SARIF parsers agree for the same finding (fix #8)
        return (str(fp) if fp else finding.stable_fingerprint()), finding
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def _finding_from_json(item: dict) -> tuple[str, Finding] | None:
    if not isinstance(item, dict) or "rule_id" not in item:
        return None
    try:
        severity = Severity.parse(str(item.get("severity", "medium")).strip())
    except ValueError:
        severity = Severity.MEDIUM  # unknown severity defaults to MEDIUM
    try:
        path = str(item.get("path", ""))
        evidence = str(item.get("evidence", ""))
        finding = Finding(
            rule_id=str(item["rule_id"]), title=str(item.get("title", "")),
            severity=severity, message=str(item.get("message", "")),
            path=path, line=int(item.get("line", 0) or 0),
            evidence=evidence, scanner="json",
        )
        # prefer the report's embedded stable id; fallback matches
        # Finding.stable_fingerprint (same as the SARIF parser)
        return (str(item.get("stable_id") or "")
                or finding.stable_fingerprint()), finding
    except (KeyError, TypeError, ValueError, AttributeError):
        return None


def load_report_findings(path: Path) -> dict[str, list[Finding]]:
    """Load one SARIF 2.1.0 or sentinel JSON report → {stable_id: [Finding]}.

    Findings sharing a stable id are kept as a list (multiplicity
    preserved) so a genuinely new duplicate is never collapsed into
    "unchanged". Raises ``ValueError`` on unreadable / unrecognised files
    AND when raw findings exist but none are parseable (fail-closed, not
    fail-open "0 new").
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path}: not a sentinel/SARIF report")

    by_id: dict[str, list[Finding]] = {}
    if "runs" in data:  # SARIF
        raw_count = 0
        for run in data.get("runs") or []:
            if not isinstance(run, dict):
                continue
            for item in run.get("results") or []:
                raw_count += 1
                parsed = _finding_from_sarif_result(item)
                if parsed:
                    by_id.setdefault(parsed[0], []).append(parsed[1])
        if raw_count and not by_id:
            raise ValueError(
                f"{path}: {raw_count} findings but none parseable")
        return by_id
    if "findings" in data:  # sentinel JSON
        raw = data.get("findings") or []
        for item in raw:
            parsed = _finding_from_json(item)
            if parsed:
                by_id.setdefault(parsed[0], []).append(parsed[1])
        if raw and not by_id:
            raise ValueError(
                f"{path}: {len(raw)} findings but none parseable")
        return by_id
    raise ValueError(f"{path}: unrecognised report format (need SARIF or sentinel JSON)")


def _as_list(value: Finding | list[Finding]) -> list[Finding]:
    """Normalize a by-id bucket — accepts legacy single-Finding values."""
    if isinstance(value, Finding):
        return [value]
    return list(value)


def diff_reports(old: dict[str, Finding | list[Finding]],
                 new: dict[str, Finding | list[Finding]]) -> DiffReport:
    """Compare two {stable_id: Finding(s)} maps, multiplicity-aware.

    Within each stable id: findings are first paired by exact
    :meth:`Finding.key` (rule+path+line+message); leftovers are then
    paired positionally so a finding that merely moved lines stays
    "unchanged" (line-shift tolerance). Unpaired leftovers are
    added/removed; unchanged counts all matched pairs.
    """
    added: list[Finding] = []
    removed: list[Finding] = []
    unchanged = 0
    for key in set(old) | set(new):
        old_list = _as_list(old[key]) if key in old else []
        new_list = _as_list(new[key]) if key in new else []
        # pair exact-key matches within the same stable id
        old_by_key: dict[tuple, list[Finding]] = {}
        for f in old_list:
            old_by_key.setdefault(f.key(), []).append(f)
        leftover_new: list[Finding] = []
        for f in new_list:
            bucket = old_by_key.get(f.key())
            if bucket:
                bucket.pop()
                unchanged += 1
            else:
                leftover_new.append(f)
        leftover_old = [f for b in old_by_key.values() for f in b]
        # line-shift tolerance: pair remaining same-stable-id findings
        pairs = min(len(leftover_old), len(leftover_new))
        unchanged += pairs
        added.extend(leftover_new[pairs:])
        removed.extend(leftover_old[pairs:])
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
