"""Scan orchestration: discovery → rule modules → suppress → dedupe."""

from __future__ import annotations

import datetime as _dt
import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config, Suppression, load_config
from .models import Finding
from .rules import code, container, custom, deps, gitcheck, secrets

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


def _glob_to_regex(pat: str) -> str:
    """Translate a glob to a regex body.

    ``**/`` matches any-depth prefix (``(?:.*/)?``), ``**`` crosses ``/``,
    while plain ``*``/``?`` never do (glob semantics, not fnmatch).
    """
    out: list[str] = []
    i, n = 0, len(pat)
    while i < n:
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif pat[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pat[i]))
            i += 1
    return "".join(out)


_GLOB_CHARS = re.compile(r"[*?]")


def _is_excluded(rel: str, patterns: list[str]) -> bool:
    """True when ``rel`` (posix-style, scan-root-relative) matches a pattern.

    Directory patterns (trailing ``/``) match the directory itself *or*
    anything under it, at any depth (``**/`` patterns may also anchor);
    a leading ``/`` anchors the pattern to the scan root (gitignore-style).
    Matching is case-insensitive on Windows for every branch.
    """
    rel_posix = rel.replace("\\", "/")
    ignore_case = os.name == "nt"
    flags = re.IGNORECASE if ignore_case else 0
    fold = str.casefold if ignore_case else (lambda s: s)
    rel_cmp = fold(rel_posix)
    segs = rel_posix.split("/")
    segs_cmp = [fold(s) for s in segs]

    for pat in patterns:
        if not pat:
            continue
        dir_only = pat.endswith("/")
        body = pat.rstrip("/")
        if not body:
            continue
        anchored = body.startswith("/")
        body = body.lstrip("/")
        if not body:
            continue
        body_cmp = fold(body)
        if rel_cmp == body_cmp:  # exact file path or the directory itself
            return True
        rx = re.compile(_glob_to_regex(body), flags)
        if dir_only:
            if rel_cmp.startswith(body_cmp + "/"):
                return True
            for k in range(1, len(segs_cmp) + 1):
                # prefix of the file path matches the directory pattern
                if rx.fullmatch("/".join(segs[:k])):
                    return True
                # segment anywhere in the path (skipped when anchored)
                if not anchored and rx.fullmatch(segs[k - 1]):
                    return True
        elif rx.fullmatch(rel_posix) or (not anchored and rx.fullmatch(segs[-1])):
            return True
        # bare (glob-free) tokens still match any path component — the
        # historical `pat in rel.split("/")` behaviour, minus glob dead code
        if not anchored and not _GLOB_CHARS.search(body) and body_cmp in segs_cmp:
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
                # a listed entry that no longer exists is accounted, not silent
                skipped += 1
                continue
            if _is_excluded(rel, patterns):
                skipped += 1
                continue
            try:
                if p.stat().st_size > cfg.max_file_bytes:
                    skipped += 1
                    continue
            except OSError:
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
        lname = path.name.lower()
        is_dockerfile = lname == "dockerfile" or lname.startswith("dockerfile.")
        if path.suffix.lower() not in _LINE_SCAN_EXTS and not is_dockerfile \
                and path.name not in {"Makefile", "Jenkinsfile"} \
                and not path.name.startswith(".env"):
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
        # utf-8-sig strips a BOM so line 1 matches what editors show
        return path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None


def _staged_files(root: Path) -> list[str] | None:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=false", "diff", "--cached",
             "--name-only", "-z", "--diff-filter=ACMR"],
            cwd=str(root), capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    # -z gives NUL-separated raw paths (no quoting) → unicode-safe
    return [p for p in proc.stdout.decode("utf-8", errors="replace").split("\0") if p]


def _expiry_active(sup: Suppression) -> bool:
    """True when a dated suppression is still valid (or undated).

    A malformed ``expires`` date fails closed: the suppression does NOT
    apply, so the finding stays visible instead of being hidden forever.
    """
    if not sup.expires:
        return True
    try:
        expires = _dt.date.fromisoformat(sup.expires)
    except ValueError:
        return False
    return _dt.date.today() <= expires


# --- inline suppression comments --------------------------------------------
# `# sentinel-ignore SEC020`        — suppress that rule on the SAME line
# `# sentinel-ignore-next-line`     — suppress on the NEXT line (all rules)
# `// sentinel-ignore SEC014,SEC015` — comma list; bare keyword = all rules
_MARKER_RE = re.compile(
    r"\bsentinel-ignore(-next-line)?"
    r"(?:\s+([A-Za-z0-9_*,]+(?:\s*,\s*[A-Za-z0-9_*]+)*))?",
    re.IGNORECASE,
)
_RULE_ID_RE = re.compile(r"[A-Za-z]{2,10}\d{2,5}$")


def _parse_ignore_rules(fragment: str) -> set[str]:
    """Turn the marker's tail into a set of uppercase rule ids.

    ``{"*"}`` only when nothing (or an explicit ``*``) was given — that's
    the intended bare-marker behaviour. If the fragment DID contain tokens
    but none is a valid rule id (e.g. ``SEC020X``), return an empty set so
    the typo suppresses nothing instead of degrading to a wildcard.
    """
    tokens = [t for t in re.split(r"[,\s]+", fragment.strip()) if t]
    if not tokens or all(t == "*" for t in tokens):
        return {"*"}
    ids = {t.upper() for t in tokens if _RULE_ID_RE.fullmatch(t)}
    return ids  # empty when no token is a valid id → fail closed


def _in_comment(line: str, pos: int) -> bool:
    """Cheap check: does a comment start (``#`` or ``//``) precede ``pos``?

    Markers inside string literals / code must not suppress findings, so a
    marker only counts when it sits behind a comment character.
    """
    head = line[:pos]
    return "#" in head or "//" in head


def _inline_suppress(findings: list[Finding], text: str) -> int:
    """Drop findings cancelled by ``sentinel-ignore`` comments in ``text``.

    Returns the number suppressed. Markers apply per (line, rule) pair —
    `sentinel-ignore SEC020` on line N keeps other rules on line N live.
    A marker with no preceding comment start on its line is ignored.
    """
    same: dict[int, set[str]] = {}
    nxt: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in _MARKER_RE.finditer(line):
            if not _in_comment(line, m.start()):
                continue  # marker inside a string/expression, not a comment
            rules = _parse_ignore_rules(m.group(2) or "")
            bucket = nxt if m.group(1) else same
            bucket.setdefault(lineno + 1 if m.group(1) else lineno, set()).update(rules)
    if not same and not nxt:
        return 0
    removed = 0
    keep: list[Finding] = []
    for f in findings:
        rules = same.get(f.line, set()) | nxt.get(f.line, set())
        if "*" in rules or f.rule_id.upper() in rules:
            removed += 1
        else:
            keep.append(f)
    findings[:] = keep
    return removed


def _suppressed_by(findings: list[Finding], sups: list[Suppression]) -> int:
    removed = 0
    ignore_case = os.name == "nt"
    for sup in sups:
        if not _expiry_active(sup):
            continue
        keep: list[Finding] = []
        sup_path = sup.path.replace("\\", "/")
        sup_prefix = sup_path.rstrip("/") + "/" if sup_path else ""
        for f in findings:
            rule_ok = sup.rule_id in ("*", f.rule_id)
            if not sup_path:
                path_ok = True
            else:
                fp = f.path.replace("\\", "/")
                fp_cmp, sp_cmp, pre_cmp = (
                    (fp.casefold(), sup_path.casefold(), sup_prefix.casefold())
                    if ignore_case else (fp, sup_path, sup_prefix))
                # exact path, path under the suppressed dir, or glob —
                # NOT a bare substring ("api.py" must not hit "mockapi.py")
                path_ok = (fp_cmp == sp_cmp
                           or fp_cmp.startswith(pre_cmp)
                           or fnmatch.fnmatch(fp_cmp, sp_cmp))
            if rule_ok and path_ok:
                removed += 1
            else:
                keep.append(f)
        findings[:] = keep
    return removed


def _load_baseline(path: Path) -> tuple[set[tuple], str | None]:
    """Parse a baseline file.

    Returns ``(keys, error)``. Keys are 5-tuples
    ``(rule_id, path, line, message_trunc80, stable_id or "")`` — the 5th
    member keeps baselines valid across line shifts; legacy files without
    ``stable_id`` load with ``""`` (exact-line matching only). ``error`` is
    non-None only when the file exists but cannot be trusted.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8-sig")
    except OSError:
        return set(), "unreadable"
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return set(), "unreadable"
    if isinstance(data, dict):
        items = data.get("findings", [])
    elif isinstance(data, list):
        items = data
    else:
        items = None
    if not isinstance(items, list):
        return set(), "unreadable"
    keys: set[tuple] = set()
    for item in items:
        try:
            keys.add((item["rule_id"], item["path"], int(item.get("line", 0)),
                      str(item.get("message", ""))[:80],
                      str(item.get("stable_id", "") or "")))
        except (KeyError, TypeError, ValueError):
            continue
    if items and not keys:
        return set(), "no usable entries"
    return keys, None


def load_baseline(path: Path) -> set[tuple]:
    return _load_baseline(Path(path))[0]


def write_baseline(path: Path, findings: list[Finding], root: Path) -> None:
    payload = {
        "version": 1,
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "findings": [
            {"rule_id": f.rule_id, "path": f.path, "line": f.line,
             "message": f.message[:80], "stable_id": f.stable_fingerprint()}
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
        try:
            # resolve() first: only_files can carry ../ or absolute paths
            # that would otherwise read outside (or crash relative_to on) root
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            result.files_skipped += 1
            continue
        text = _read_text(path)
        if text is None:
            result.files_skipped += 1
            continue
        result.files_scanned += 1
        hits = secrets.scan_text(rel, text, allow=allow)
        if path.suffix.lower() != ".lock":
            hits += code.scan_text(rel, text)
            if cfg.custom_rules:
                hits += custom.scan_text(rel, text, cfg.custom_rules)
        if allow:
            # allow_secrets applies to secret evidence only — custom rules
            # and SAST hits are managed via [[suppressions]] / `sentinel allow`.
            hits = [
                h for h in hits
                if not (h.scanner == "secrets" and any(
                    a in h.evidence.lower() or a in h.message.lower() for a in allow))
            ]
        if cfg.inline_suppressions:
            result.suppressed += _inline_suppress(hits, text)
        result.findings.extend(hits)

    patterns = list(cfg.excludes) + list(extra_excludes or [])
    if run_git:
        do_history = cfg.history if history is None else history
        result.findings.extend(gitcheck.scan(
            root, history=do_history, max_commits=cfg.history_commits,
            exclude=lambda rel: _is_excluded(rel, patterns), allow=allow))
    if run_deps:
        result.findings.extend(deps.scan(root, cves=cfg.deps_cves))
    if only_files is None:  # repo-level checks make sense only on full scans
        result.findings.extend(container.scan_repo(
            root, exclude=lambda rel: _is_excluded(rel, patterns)))

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
        base_keys, bl_error = _load_baseline(baseline)
        if base_keys:
            # legacy entries match exact keys; entries carrying a stable id
            # survive line shifts (blank lines / refactors)
            legacy_keys = {(r, p, ln, m) for (r, p, ln, m, _sid) in base_keys}
            stable_ids = {sid for *_, sid in base_keys if sid}
            before = len(result.findings)
            result.findings = [
                f for f in result.findings
                if f.key() not in legacy_keys
                and f.stable_fingerprint() not in stable_ids
            ]
            result.notes.append(f"baseline: {before - len(result.findings)} known finding(s) ignored")
        elif bl_error:
            # fail closed: the baseline is NOT applied (findings stay visible)
            try:
                has_content = Path(baseline).is_file() and Path(baseline).stat().st_size > 0
            except OSError:
                has_content = False
            if has_content:
                result.notes.append(f"baseline: {baseline} unreadable — NOT applied")

    return result
