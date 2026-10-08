"""Scan orchestration: discovery → rule modules → suppress → dedupe."""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config, Suppression, load_config
from .models import Finding
from .rules import code, deps, gitcheck, secrets

# Extensions we run the line scanners on (secrets has its own wider set).
_LINE_SCAN_EXTS = secrets.SECRET_EXTENSIONS | code.ALL


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    notes: list[str] = field(default_factory=list)
    suppressed: int = 0
    config: Config | None = None

    @property
    def exit_findings(self) -> list[Finding]:
        """Findings that count for gating (INFO notes are excluded)."""
        from .models import Severity

        return [f for f in self.findings if f.severity > Severity.INFO]


def _is_excluded(rel: str, patterns: list[str]) -> bool:
    rel_posix = rel.replace("\\", "/")
    for pat in patterns:
        pat = pat.rstrip("/")
        if not pat:
            continue
        if pat.endswith("/"):
            if rel_posix.startswith(pat) or f"/{pat}" in rel_posix:
                return True
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix.rsplit("/", 1)[-1], pat):
            return True
        if pat in rel_posix.split("/"):
            return True
    return False


def discover(root: Path, cfg: Config, extra_excludes: list[str] | None = None,
             only_files: list[str] | None = None) -> tuple[list[Path], int]:
    """Return (files_to_scan, skipped_count)."""
    root = Path(root)
    patterns = list(cfg.excludes) + list(extra_excludes or [])
    files: list[Path] = []
    skipped = 0

    if only_files is not None:
        for rel in only_files:
            p = root / rel
            if not p.is_file():
                continue
            if _is_excluded(rel, patterns):
                skipped += 1
                continue
            files.append(p)
        return files, skipped

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if _is_excluded(rel, patterns):
            skipped += 1
            continue
        if path.suffix.lower() not in _LINE_SCAN_EXTS and path.name not in {
            "Dockerfile", "Makefile", "Jenkinsfile",
        } and not path.name.startswith(".env"):
            continue
        try:
            if path.stat().st_size > cfg.max_file_bytes:
                skipped += 1
                continue
        except OSError:
            skipped += 1
            continue
        files.append(path)
    return files, skipped


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _staged_files(root: Path) -> list[str] | None:
    try:
        proc = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=str(root), capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [ln for ln in proc.stdout.decode("utf-8", errors="replace").splitlines() if ln.strip()]


def _expiry_active(sup: Suppression) -> bool:
    """True when a dated suppression is still valid (or undated)."""
    if not sup.expires:
        return True
    try:
        expires = _dt.date.fromisoformat(sup.expires)
    except ValueError:
        return True
    return _dt.date.today() <= expires


def _suppressed_by(findings: list[Finding], sups: list[Suppression]) -> int:
    removed = 0
    for sup in sups:
        if not _expiry_active(sup):
            continue
        keep: list[Finding] = []
        for f in findings:
            rule_ok = sup.rule_id in ("*", f.rule_id)
            path_ok = (not sup.path) or bool(
                fnmatch.fnmatch(f.path.replace("\\", "/"), sup.path)
                or sup.path in f.path.replace("\\", "/")
            )
            if rule_ok and path_ok:
                removed += 1
            else:
                keep.append(f)
        findings[:] = keep
    return removed


def load_baseline(path: Path) -> set[tuple]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    keys = set()
    for item in data.get("findings", []) if isinstance(data, dict) else (data or []):
        try:
            keys.add((item["rule_id"], item["path"], int(item.get("line", 0)), str(item.get("message", ""))[:80]))
        except (KeyError, TypeError, ValueError):
            continue
    return keys


def write_baseline(path: Path, findings: list[Finding], root: Path) -> None:
    payload = {
        "version": 1,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "findings": [
            {"rule_id": f.rule_id, "path": f.path, "line": f.line, "message": f.message[:80]}
            for f in findings
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def scan(
    root: str | Path,
    config: Config | None = None,
    config_path: str | None = None,
    extra_excludes: list[str] | None = None,
    staged: bool = False,
    run_git: bool = True,
    run_deps: bool = True,
    history: bool | None = None,
    only_files: list[str] | None = None,
    baseline: Path | None = None,
) -> ScanResult:
    """Run the full sweep against ``root``."""
    root = Path(root).resolve()
    cfg = config if config is not None else load_config(root, config_path)
    result = ScanResult(root=root, config=cfg)
    result.notes.extend(cfg.notes)

    if staged:
        staged_list = _staged_files(root)
        if staged_list is None:
            result.notes.append("staged: `git diff --cached` failed — falling back to full scan")
        else:
            only_files = staged_list
            result.notes.append(f"staged: scanning {len(staged_list)} staged file(s)")

    files, skipped = discover(root, cfg, extra_excludes, only_files)
    result.files_skipped = skipped

    allow = [a.lower() for a in cfg.allow_secrets]
    for path in files:
        text = _read_text(path)
        if text is None:
            result.files_skipped += 1
            continue
        rel = path.relative_to(root).as_posix()
        result.files_scanned += 1
        hits = secrets.scan_text(rel, text, allow=allow)
        if path.suffix.lower() != ".lock":
            hits += code.scan_text(rel, text)
        if allow:
            hits = [h for h in hits if not any(a in h.evidence.lower() or a in h.message.lower() for a in allow)]
        result.findings.extend(hits)

    if run_git:
        do_history = cfg.history if history is None else history
        patterns = list(cfg.excludes) + list(extra_excludes or [])
        result.findings.extend(gitcheck.scan(
            root, history=do_history, max_commits=cfg.history_commits,
            exclude=lambda rel: _is_excluded(rel, patterns), allow=allow))
    if run_deps:
        result.findings.extend(deps.scan(root, cves=cfg.deps_cves))

    # dedupe
    seen: set[tuple] = set()
    deduped: list[Finding] = []
    for f in sorted(result.findings, key=lambda f: (-int(f.severity), f.path, f.line)):
        k = f.key()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(f)
    result.findings = deduped

    result.suppressed += _suppressed_by(result.findings, cfg.suppressions)

    if baseline is not None:
        base_keys = load_baseline(baseline)
        if base_keys:
            before = len(result.findings)
            result.findings = [f for f in result.findings if f.key() not in base_keys]
            result.notes.append(f"baseline: {before - len(result.findings)} known finding(s) ignored")

    return result
