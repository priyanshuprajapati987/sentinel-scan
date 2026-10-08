"""Dependency auditing — pin hygiene locally, CVEs via pip-audit/npm when present.

Offline-first: every external tool is optional. If ``pip-audit`` / ``npm``
are missing or the network is down, the scan degrades to pin-hygiene checks
and records a note instead of failing.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from ..models import Finding, Severity

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[.*?\])?\s*(.*?)\s*$")
_SPECIFIER = re.compile(r"(===|==|>=|<=|~=|!=|>|<)")

_EXTERNAL_TIMEOUT = 60


def _note(text: str) -> Finding:
    return Finding(
        rule_id="DEPS-SKIP", title="Dependency audit skipped", severity=Severity.INFO,
        message=text, path="-", line=0, fix="Install pip-audit / npm for CVE coverage.",
        cwe="", confidence="high", scanner="deps",
    )


def scan_pin_hygiene(root: Path) -> list[Finding]:
    """Unpinned requirements and unpinned package.json ranges (SEC060)."""
    findings: list[Finding] = []

    for req in sorted(root.glob("requirements*.txt")):
        rel = req.relative_to(root).as_posix() if req.is_relative_to(root) else req.name
        try:
            lines = req.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-r", "--", "-e", ".")):
                continue
            m = _REQ_LINE.match(line)
            if not m:
                continue
            spec = m.group(2) or ""
            if not _SPECIFIER.search(spec):
                findings.append(Finding(
                    rule_id="SEC060", title="Unpinned dependency", severity=Severity.LOW,
                    message=f"'{m.group(1)}' has no version constraint — builds are not reproducible "
                    "and a compromised release would be pulled automatically.",
                    path=rel, line=i, evidence=line[:120],
                    fix=f"Pin it: {m.group(1)}==<tested-version>",
                    cwe="CWE-1104", confidence="medium", scanner="deps",
                ))

    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for section in ("dependencies", "devDependencies"):
            for name, ver in (data.get(section) or {}).items():
                v = str(ver)
                if v.startswith(("file:", "link:", "workspace:", "git+", "http")):
                    continue
                if not re.search(r"\d", v) or v in {"*", "latest", "x", "next"}:
                    findings.append(Finding(
                        rule_id="SEC060", title="Unpinned dependency", severity=Severity.LOW,
                        message=f"{section}.{name} = '{v}' — floating range pulls any future release.",
                        path="package.json", line=0, evidence=f"{name}: {v}",
                        fix=f"Pin {name} to an exact version (or at least a ~ range).",
                        cwe="CWE-1104", confidence="medium", scanner="deps",
                    ))
    return findings


def _run(cmd: list[str], cwd: Path, timeout: int = _EXTERNAL_TIMEOUT) -> str | None:
    """Run an optional external tool; None = unavailable/failed (never raises)."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):  # pip-audit/npm audit exit 1 = vulns found
        return None
    return proc.stdout.decode("utf-8", errors="replace")


def _severity_from_cvss(score: float | None, severity: str | None) -> Severity:
    if severity:
        try:
            return Severity.parse(severity)
        except ValueError:
            pass
    if score is None:
        return Severity.HIGH
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def scan_cves(root: Path) -> list[Finding]:
    """pip-audit (requirements/pyproject) + npm audit (lockfile), if available."""
    findings: list[Finding] = []
    ran_any = False

    # --- pip-audit -----------------------------------------------------
    req = None
    for cand in ("requirements.txt", "requirements-prod.txt"):
        if (root / cand).exists():
            req = root / cand
            break
    if req is not None or (root / "pyproject.toml").exists():
        cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
        cmd += ["-r", req.name] if req else ["--format", "json"]
        if not req:
            cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
        out = _run(cmd, root)
        if out:
            ran_any = True
            try:
                payload = json.loads(out)
            except json.JSONDecodeError:
                payload = []
            for vuln in payload if isinstance(payload, list) else []:
                vid = vuln.get("id", "UNKNOWN")
                for dep in vuln.get("dependencies", []) or []:
                    fixes = vuln.get("fix_versions") or []
                    findings.append(Finding(
                        rule_id="SEC061", title="Known vulnerable dependency (pip-audit)",
                        severity=_severity_from_cvss(None, None),
                        message=f"{dep.get('name', '?')} {dep.get('version', '?')} — {vid} "
                        f"{('(fix: ' + ', '.join(fixes) + ')') if fixes else ''}".strip(),
                        path=req.name if req else "pyproject.toml",
                        line=0, evidence=vid,
                        fix=f"Upgrade {dep.get('name', '')} to {'/'.join(fixes) or 'a patched release'}.",
                        cwe="CWE-1395", confidence="high", scanner="deps",
                    ))

    # --- npm audit -----------------------------------------------------
    if (root / "package-lock.json").exists() or (root / "npm-shrinkwrap.json").exists():
        out = _run(["npm", "audit", "--json"], root)
        if out:
            ran_any = True
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                data = {}
            vulns = (data.get("vulnerabilities") or {})
            for name, info in vulns.items():
                sev_raw = str(info.get("severity", "high")).upper()
                try:
                    sev = Severity.parse(sev_raw)
                except ValueError:
                    sev = Severity.HIGH
                via = info.get("via") or []
                title = ""
                for v in via:
                    if isinstance(v, dict):
                        title = v.get("title", "")
                        url = v.get("url", "")
                        break
                else:
                    url = ""
                findings.append(Finding(
                    rule_id="SEC062", title="Known vulnerable dependency (npm audit)",
                    severity=sev, message=f"{name} — {title or 'advisory'} {url}".strip(),
                    path="package-lock.json", line=0, evidence=name,
                    fix="Run `npm audit fix` or upgrade the affected package.",
                    cwe="CWE-1395", confidence="high", scanner="deps",
                ))

    if not ran_any:
        findings.append(_note(
            "No CVE data: pip-audit/npm unavailable or offline — ran pin-hygiene checks only. "
            "`pip install pip-audit` for Python CVE coverage."))
    return findings


def scan(root: Path, cves: bool = True) -> list[Finding]:
    findings = scan_pin_hygiene(Path(root))
    if cves:
        findings.extend(scan_cves(Path(root)))
    return findings
