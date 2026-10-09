"""Report rendering: console, JSON, Markdown, HTML, SARIF 2.1.0."""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import __version__
from .models import Finding, Severity
from .score import counts, score

_SEV_COLOR = {
    Severity.CRITICAL: "\033[1;97;41m",  # bold white on red
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[1;33m",
    Severity.LOW: "\033[1;36m",
    Severity.INFO: "\033[1;90m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_COLOR_ENABLED = False


def _enable_color() -> None:
    global _COLOR_ENABLED
    if os.environ.get("NO_COLOR"):
        _COLOR_ENABLED = False
        return
    if os.environ.get("FORCE_COLOR"):
        _COLOR_ENABLED = True
        return
    _COLOR_ENABLED = sys.stdout.isatty()
    if _COLOR_ENABLED and os.name == "nt":  # enable VT processing on Windows
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(kernel32.GetStdHandle(-11), ctypes.byref(mode)):
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), mode.value | 0x0004)
        except Exception:
            _COLOR_ENABLED = False


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _COLOR_ENABLED else text


def render_console(result, show_evidence: bool = True) -> str:
    _enable_color()
    lines: list[str] = []
    s, grade = score(result.findings)
    c = counts(result.findings)

    lines.append("")
    lines.append(_c(f"  SENTINEL SCAN — {result.root}", _BOLD))
    lines.append(_c(f"  files: {result.files_scanned} scanned, {result.files_skipped} skipped"
                    + (f" · suppressed: {result.suppressed}" if result.suppressed else ""), _DIM))
    lines.append("")

    grade_color = {"A": "\033[1;32m", "B": "\033[1;32m", "C": "\033[1;33m",
                   "D": "\033[1;31m", "F": "\033[1;31m"}.get(grade, "")
    lines.append(f"  SCORE  {_c(str(s) + '/100', _BOLD)}   GRADE  {_c(' ' + grade + ' ', grade_color)}   "
                 + "  ".join(
                     _c(f"{name} {c[name]}", _SEV_COLOR[Severity.parse(name)])
                     for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if c[name]
                 ))
    lines.append("")

    if not result.findings:
        lines.append(_c("  ✓ no findings", "\033[1;32m"))
        lines.append("")
        return "\n".join(lines)

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)

    for path in sorted(by_file):
        lines.append(_c(f"  {path}", _BOLD))
        for f in by_file[path]:
            loc = f":{f.line}" if f.line else ""
            sev = _c(f"{f.severity.name:<8}", _SEV_COLOR[f.severity])
            lines.append(f"    {sev} {_c(f.rule_id, _DIM)} {f.title}"
                         f"{loc and ' @' + str(f.line) or ''}"
                         f" {_c('[' + f.fingerprint() + ']', _DIM)}")
            if show_evidence and f.evidence:
                lines.append(_c(f"            {f.evidence}", _DIM))
            if f.fix:
                lines.append(_c(f"            fix: {f.fix}", _DIM))
        lines.append("")

    for note in result.notes:
        lines.append(_c(f"  note: {note}", _DIM))
    lines.append(_c(f"  {len(result.findings)} finding(s) · sentinel v{__version__}", _DIM))
    lines.append("")
    return "\n".join(lines)


def render_json(result) -> str:
    s, grade = score(result.findings)
    payload = {
        "tool": {"name": "sentinel", "version": __version__},
        "root": str(result.root),
        "score": s,
        "grade": grade,
        "counts": counts(result.findings),
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "suppressed": result.suppressed,
        "notes": result.notes,
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(result) -> str:
    s, grade = score(result.findings)
    c = counts(result.findings)
    lines = [
        "# Sentinel security report",
        "",
        f"**Root:** `{result.root}`  ",
        f"**Score:** {s}/100 · **Grade:** {grade} · **Files:** {result.files_scanned}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {name} | {c[name]} |")
    lines.append("")

    if not result.findings:
        lines.append("No findings. ✅")
        return "\n".join(lines) + "\n"

    lines += ["| Sev | Rule | Location | Issue | Fix |", "|---|---|---|---|---|"]
    for f in result.findings:
        loc = f"`{f.path}" + (f":{f.line}`" if f.line else "`")
        title = f.title.replace("|", "\\|")
        fix = (f.fix or "").replace("|", "\\|")
        lines.append(f"| {f.severity.name} | `{f.rule_id}` | {loc} | {title} | {fix} |")

    if result.notes:
        lines += ["", "## Notes", ""] + [f"- {n}" for n in result.notes]
    return "\n".join(lines) + "\n"


def render_html(result) -> str:
    s, grade = score(result.findings)
    c = counts(result.findings)
    grade_color = {"A": "#22c55e", "B": "#22c55e", "C": "#eab308", "D": "#ef4444", "F": "#ef4444"}[grade]
    rows = []
    for f in result.findings:
        sev_color = {
            "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
            "LOW": "#38bdf8", "INFO": "#94a3b8",
        }[f.severity.name]
        ev = f"<code>{_html(f.evidence)}</code>" if f.evidence else ""
        fix = f"<div class='fix'>↳ {_html(f.fix)}</div>" if f.fix else ""
        loc = f"{_html(f.path)}" + (f":{f.line}" if f.line else "")
        rows.append(
            f"<tr><td><span class='sev' style='background:{sev_color}'>{f.severity.name}</span></td>"
            f"<td class='rid'>{_html(f.rule_id)}</td><td><div class='loc'>{loc}</div>"
            f"<div class='title'>{_html(f.title)}</div>{ev}{fix}</td></tr>"
        )
    notes = "".join(f"<li>{_html(n)}</li>" for n in result.notes)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel report — grade {grade}</title>
<style>
 body{{background:#0b1120;color:#e2e8f0;font:14px/1.5 ui-monospace,Consolas,monospace;margin:0;padding:32px}}
 h1{{font-size:18px;letter-spacing:.12em;text-transform:uppercase;color:#94a3b8}}
 .card{{background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:20px;margin-bottom:20px}}
 .big{{font-size:56px;font-weight:700;color:{grade_color}}}
 .counts span{{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;margin-right:8px;background:#1e293b}}
 table{{width:100%;border-collapse:collapse}} td{{padding:8px;vertical-align:top;border-bottom:1px solid #1e293b}}
 .sev{{color:#0b1120;border-radius:6px;padding:2px 8px;font-size:11px;font-weight:700}}
 .rid{{color:#64748b;white-space:nowrap}} .loc{{color:#38bdf8}} .title{{color:#f1f5f9}}
 .fix{{color:#94a3b8;font-size:12px;margin-top:3px}} code{{color:#fbbf24;font-size:12px}}
 ul{{color:#94a3b8;font-size:12px}} .foot{{color:#475569;font-size:11px;margin-top:16px}}
</style></head><body>
<h1>Sentinel security report</h1>
<div class="card">
  <div class="big">{s}<span style="font-size:20px;color:#64748b">/100 · grade {grade}</span></div>
  <div class="counts" style="margin-top:10px">
    <span>CRITICAL {c['CRITICAL']}</span><span>HIGH {c['HIGH']}</span>
    <span>MEDIUM {c['MEDIUM']}</span><span>LOW {c['LOW']}</span>
    <span>files {result.files_scanned}</span>
  </div>
</div>
<div class="card"><table>{''.join(rows) or '<tr><td>No findings 🎉</td></tr>'}</table>
{'<ul>' + notes + '</ul>' if notes else ''}
<div class="foot">sentinel v{__version__} · {_html(str(result.root))}</div>
</div></body></html>"""


def _html(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# SARIF rule metadata is built from the findings themselves so unknown rules
# still render in GitHub's code-scanning UI.
def render_sarif(result) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message or f.title},
                "help": {"text": f.fix or f.title},
                "properties": {"security-severity": _security_severity(f)},
            }
        level = {
            Severity.CRITICAL: "error", Severity.HIGH: "error",
            Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
        }[f.severity]
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.path.replace("\\", "/")},
            }
        }
        if f.line:
            loc["physicalLocation"]["region"] = {"startLine": f.line}
        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message or f.title},
            "locations": [loc],
            "properties": {"severity": f.severity.name, "cwe": f.cwe,
                           "confidence": f.confidence},
        })

    payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sentinel",
                    "version": __version__,
                    "informationUri": "https://github.com/priyanshuprajapati987/sentinel-scan",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _security_severity(f: Finding) -> str:
    """GitHub security-severity is a CVSS-like string (0.0-10.0)."""
    return {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0",
            Severity.MEDIUM: "5.0", Severity.LOW: "2.0", Severity.INFO: "0.0"}[f.severity]


RENDERERS = {
    "console": render_console,
    "json": render_json,
    "md": render_markdown,
    "markdown": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
}


def write_report(fmt: str, result, output: str | None, quiet: bool = False) -> None:
    """Render ``fmt`` to stdout (console) or a file path.

    ``quiet`` suppresses only the human status chatter — files still get written.
    """
    text = RENDERERS[fmt](result)
    if not output or fmt == "console":
        if not quiet:
            print(text)
        return
    out = Path(output)
    if out.is_dir() or str(output).endswith(("/", "\\")):
        names = {"json": "report.json", "md": "report.md", "markdown": "report.md",
                 "html": "report.html", "sarif": "report.sarif"}
        out = out / names.get(fmt, f"report.{fmt}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8")
    if not quiet:
        print(f"report written: {out}")
