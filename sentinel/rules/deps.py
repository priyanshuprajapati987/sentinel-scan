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
_URL_REQ_PREFIXES = ("git+", "http://", "https://", "hg+", "svn+")

_EXTERNAL_TIMEOUT = 60

# Tool-reported severity labels → Severity. npm emits info/low/moderate/high/
# critical; pip-audit emits HIGH/MODERATE/... — anything unmapped (incl.
# "unknown" and missing) deliberately lands on MEDIUM, not a guessed HIGH.
_SEVERITY_LABELS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.MEDIUM,
}


def _note(text: str) -> Finding:
    return Finding(
        rule_id="DEPS-SKIP", title="Dependency audit skipped", severity=Severity.INFO,
        message=text, path="-", line=0, fix="Install pip-audit / npm for CVE coverage.",
        cwe="", confidence="high", scanner="deps",
    )


def scan_pin_hygiene(root: Path) -> list[Finding]:
    """Unpinned requirements and unpinned package.json ranges (SEC060)."""
    findings: list[Finding] = []

    for req in sorted({*root.glob("requirements*.txt"), *root.glob("requirements/*.txt")}):
        rel = req.relative_to(root).as_posix() if req.is_relative_to(root) else req.name
        try:
            lines = req.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith(("#", "-r", "--", "-e", ".")):
                continue
            if line.startswith(_URL_REQ_PREFIXES):
                continue  # VCS/URL requirement — no package name to pin
            m = _REQ_LINE.match(line)
            if not m:
                continue
            spec = m.group(2) or ""
            if ";" in spec:
                # env marker: `pkg; python_version<"3.12"` — the marker's `<`
                # must not be mistaken for a version specifier.
                spec = spec.split(";", 1)[0].strip()
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
        if not isinstance(data, dict):
            # an array/string top-level JSON must not crash the whole scan
            findings.append(_note(
                "package.json is not a JSON object — skipped npm pin-hygiene "
                "section (not reported as clean)."))
            data = {}
        for section in ("dependencies", "devDependencies"):
            sec = data.get(section)
            if not isinstance(sec, dict):
                continue
            for name, ver in sec.items():
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

    # --- Ruby Gemfile -------------------------------------------------------
    gemfile = root / "Gemfile"
    if gemfile.exists():
        try:
            glines = gemfile.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            glines = []
        _gem = re.compile(r"^\s*gem\s+['\"]([^'\"]+)['\"](.*)$")
        _kwarg = re.compile(r"^(\w+|:\w+)\s*(?::|=>)")
        for i, raw in enumerate(glines, 1):
            line = raw.split("#", 1)[0].rstrip()
            m = _gem.match(line)
            if not m:
                continue
            rest = (m.group(2) or "").strip().lstrip(",").strip()
            # Only a positional argument carries the version constraint;
            # `require: false` / `github: '...'` kwargs do NOT pin anything
            # (the old digit/comma regex let kwarg-only lines pass as pinned).
            has_version = False
            for seg in rest.split(","):
                seg = seg.strip()
                if not seg or _kwarg.match(seg):
                    continue  # keyword option — not a version constraint
                has_version = True
                break
            if not has_version:
                findings.append(Finding(
                    rule_id="SEC060", title="Unpinned dependency", severity=Severity.LOW,
                    message=f"gem '{m.group(1)}' has no version constraint — "
                    "Bundler may pull any future release.",
                    path="Gemfile", line=i, evidence=line[:120],
                    fix=f"Pin it: gem '{m.group(1)}', '~> <tested-version>'",
                    cwe="CWE-1104", confidence="medium", scanner="deps",
                ))

    # --- PHP composer.json --------------------------------------------------
    composer = root / "composer.json"
    if composer.exists():
        try:
            cdata = json.loads(composer.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            cdata = {}
        if not isinstance(cdata, dict):
            findings.append(_note(
                "composer.json is not a JSON object — skipped Composer pin-hygiene "
                "section (not reported as clean)."))
            cdata = {}
        for section in ("require", "require-dev"):
            sec = cdata.get(section)
            if not isinstance(sec, dict):
                continue
            for name, ver in sec.items():
                if name.startswith(("php", "ext-")):
                    continue  # platform requirements, not packagist deps
                v = str(ver).strip()
                if not re.search(r"\d", v) or v in {"*", "@dev", "dev-master", "dev-main"}:
                    findings.append(Finding(
                        rule_id="SEC060", title="Unpinned dependency", severity=Severity.LOW,
                        message=f"composer {section}.{name} = '{v}' — floating constraint "
                        "pulls any future release (or an arbitrary dev branch).",
                        path="composer.json", line=0, evidence=f"{name}: {v}",
                        fix=f"Pin {name} to an exact version or a bounded range (^1.2).",
                        cwe="CWE-1104", confidence="medium", scanner="deps",
                    ))

    # --- Java Maven pom.xml (dynamic versions) ------------------------------
    pom = root / "pom.xml"
    if pom.exists():
        try:
            plines = pom.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            plines = []
        _dyn = re.compile(r"<version>\s*(LATEST|RELEASE|latest|release)\s*</version>", re.I)
        for i, raw in enumerate(plines, 1):
            m = _dyn.search(raw)
            if m:
                findings.append(Finding(
                    rule_id="SEC060", title="Unpinned dependency", severity=Severity.LOW,
                    message=f"Maven <version>{m.group(1)}</version> resolves the newest "
                    "release at build time — builds are not reproducible and a "
                    "compromised release would be pulled automatically.",
                    path="pom.xml", line=i, evidence=raw.strip()[:120],
                    fix="Replace LATEST/RELEASE with an exact version (or a locked BOM).",
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


def _severity_from_label(label) -> Severity | None:
    """Map a tool-reported severity string (npm/pip-audit) or None."""
    if label is None:
        return None
    return _SEVERITY_LABELS.get(str(label).strip().lower())


def _cvss_score(raw) -> float | None:
    """Pull a numeric CVSS base score out of pip-audit's cvss field
    (number or {"base_score"/"score": n}); None when absent/unknown."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, dict):
        for key in ("base_score", "score"):
            val = raw.get(key)
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return float(val)
    return None


def _shape_failed(payload) -> bool:
    """True when npm audit output is NOT the shape this parser understands:
    an object carrying a ``vulnerabilities`` dict. Anything else (garbage,
    a bare list, pip-audit's shapes) must surface as a note, not as "0 vulns".
    (pip-audit shapes are normalized inline in scan_cves — modern dict vs
    legacy list.)"""
    return not (isinstance(payload, dict) and isinstance(payload.get("vulnerabilities"), dict))


def scan_cves(root: Path) -> list[Finding]:
    """pip-audit (requirements/pyproject) + npm audit (lockfile), if available."""
    findings: list[Finding] = []
    ran_any = False
    parse_failed = False  # tool produced output we could NOT parse -> note, never "0 vulns"

    # --- pip-audit -----------------------------------------------------
    # every requirements*.txt (incl. requirements/*.txt subdirs); pyproject
    # falls back to `pip-audit <path>` (project mode — audits the DECLARED
    # dependencies). A bare `pip-audit` (no target) audits the ambient
    # environment instead: unrelated machine packages reported against this
    # repo's pyproject, results nondeterministic across machines/CI.
    reqs = sorted({*root.glob("requirements*.txt"), *root.glob("requirements/*.txt")})
    targets = list(reqs) if reqs else (
        [root / "pyproject.toml"] if (root / "pyproject.toml").exists() else [])
    for tgt in targets:
        rel = tgt.relative_to(root).as_posix()
        cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"]
        if tgt.suffix == ".txt":
            cmd += ["-r", rel]
        else:
            cmd += ["."]  # project_path: cwd=root, declared deps from pyproject
        out = _run(cmd, root)
        if not out:
            continue
        try:
            payload = json.loads(out)
        except json.JSONDecodeError:
            payload = None
        # pip-audit ships TWO real JSON shapes:
        #   modern: {"dependencies": [{"name","version","vulns":[...]}], "fixes":[]}
        #   legacy: [{"id", "dependencies":[...], "fix_versions":[...]}]
        # (modern is what current pip-audit emits — the old list-only check
        #  read it as malformed and dropped every real CVE as "coverage unknown")
        # Anything else (e.g. npm's {"vulnerabilities": ...}) = shape failure:
        # a visible note, NEVER "0 vulnerabilities".
        triples: list[tuple[str, str, dict]] = []
        if isinstance(payload, dict) and isinstance(payload.get("dependencies"), list):
            for dep in payload["dependencies"]:
                if not isinstance(dep, dict):
                    continue
                vulns = dep.get("vulns")
                if not isinstance(vulns, list):
                    continue
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        triples.append(
                            (str(dep.get("name", "?")), str(dep.get("version", "?")), vuln))
            ran_any = True
        elif isinstance(payload, list) and all(isinstance(v, dict) for v in payload):
            for vuln in payload:
                for dep in vuln.get("dependencies") or []:
                    if isinstance(dep, dict):
                        triples.append(
                            (str(dep.get("name", "?")), str(dep.get("version", "?")), vuln))
            ran_any = True
        else:
            findings.append(_note(
                f"pip-audit output for {rel} is not the expected JSON — CVE coverage "
                "unknown (NOT reported as 'no vulnerabilities')."))
            parse_failed = True
            continue
        for name, version, vuln in triples:
            vid = vuln.get("id", "UNKNOWN")
            sev = _severity_from_label(vuln.get("severity"))
            if sev is None:
                sev = _severity_from_cvss(_cvss_score(vuln.get("cvss")), None)
            fixes = vuln.get("fix_versions") or []
            findings.append(Finding(
                rule_id="SEC061", title="Known vulnerable dependency (pip-audit)",
                severity=sev,
                message=f"{name} {version} — {vid} "
                f"{('(fix: ' + ', '.join(str(x) for x in fixes) + ')') if fixes else ''}".strip(),
                path=rel,
                line=0, evidence=vid,
                fix=f"Upgrade {name} to {'/'.join(str(x) for x in fixes) or 'a patched release'}.",
                cwe="CWE-1395", confidence="high", scanner="deps",
            ))

    # --- npm audit -----------------------------------------------------
    if (root / "package-lock.json").exists() or (root / "npm-shrinkwrap.json").exists():
        out = _run(["npm", "audit", "--json"], root)
        if out:
            try:
                data = json.loads(out)
            except json.JSONDecodeError:
                data = None
            if _shape_failed(data):
                findings.append(_note(
                    "npm audit output is not the expected JSON — CVE coverage "
                    "unknown (NOT reported as 'no vulnerabilities')."))
                parse_failed = True
            else:
                ran_any = True
                for name, info in data["vulnerabilities"].items():
                    if not isinstance(info, dict):
                        continue
                    sev = _severity_from_label(info.get("severity"))
                    if sev is None:
                        sev = Severity.MEDIUM  # careful: INFO == 0 is falsy — no `or` here
                    via = info.get("via") or []
                    title = ""
                    url = ""
                    for v in via:
                        if isinstance(v, dict):
                            title = v.get("title", "")
                            url = v.get("url", "")
                            break
                    findings.append(Finding(
                        rule_id="SEC062", title="Known vulnerable dependency (npm audit)",
                        severity=sev, message=f"{name} — {title or 'advisory'} {url}".strip(),
                        path="package-lock.json", line=0, evidence=name,
                        fix="Run `npm audit fix` or upgrade the affected package.",
                        cwe="CWE-1395", confidence="high", scanner="deps",
                    ))

    if not ran_any and not parse_failed:
        findings.append(_note(
            "No CVE data: pip-audit/npm unavailable or offline — ran pin-hygiene checks only. "
            "`pip install pip-audit` for Python CVE coverage."))
    return findings


def scan(root: Path, cves: bool = True) -> list[Finding]:
    findings = scan_pin_hygiene(Path(root))
    if cves:
        findings.extend(scan_cves(Path(root)))
    return findings
