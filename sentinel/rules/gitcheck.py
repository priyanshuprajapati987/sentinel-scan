"""Git repository hygiene — tracked secrets, history, config, remotes.

Everything here runs through the ``git`` CLI with subprocess and a hard cap
on output size, so a huge repository can never wedge the scanner.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ..models import Finding, Severity
from . import secrets as secrets_mod

_MAX_HISTORY_PATCH_BYTES = 8_000_000  # 8 MB cap on `git log -p` output
_MAX_HISTORY_COMMITS = 500
_MAX_FILE_BYTES = 50 * 1024 * 1024  # SEC054: >50 MB blobs

_TRACKED_SECRET_NAMES = {
    ".env": ("SEC050", "Tracked .env file", Severity.CRITICAL,
             "Untrack it (git rm --cached), add to .gitignore, and rotate every credential it held."),
    ".env.local": ("SEC050", "Tracked .env.local file", Severity.CRITICAL,
                   "Untrack it, ignore it, rotate its credentials."),
    "credentials": ("SEC050", "Tracked credentials file", Severity.CRITICAL,
                    "Untrack it, ignore it, rotate its credentials."),
    "id_rsa": ("SEC051", "Tracked private SSH key", Severity.CRITICAL,
               "Untrack, purge history (git filter-repo), re-issue the keypair."),
    "id_ed25519": ("SEC051", "Tracked private SSH key", Severity.CRITICAL,
                   "Untrack, purge history, re-issue the keypair."),
}

_TRACKED_KEY_SUFFIXES = {
    ".pem": ("SEC051", "Tracked PEM key/certificate file", Severity.HIGH,
             "Verify it is a public cert; private keys must never be tracked."),
    ".p12": ("SEC051", "Tracked PKCS#12 keystore", Severity.CRITICAL,
             "Untrack the keystore and rotate the credential it contains."),
    ".pfx": ("SEC051", "Tracked PKCS#12 keystore", Severity.CRITICAL,
             "Untrack the keystore and rotate the credential it contains."),
    ".key": ("SEC051", "Tracked .key file", Severity.CRITICAL,
             "Untrack it, purge history, and rotate the key."),
}

_ENV_IGNORE_RE = re.compile(r"(^|/)\.env\*?$|\*+\.env\*?$", re.MULTILINE)
# `.env` exactly or `.env.<variant>` — deliberately NOT `.environment`/`.envrc`
_ENV_FILE_RE = re.compile(r"\.env(\..+)?")


def _git(root: Path, *args: str, timeout: int = 30) -> str | None:
    """Run a git command; stdout on success, None on ANY failure.

    None = git failed (missing binary, timeout, nonzero exit) and callers
    must treat it as "check SKIPPED", never as "ran and clean" — an empty
    string '' means the command ran successfully and produced no output.
    Never raises.
    """
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""


def is_git_repo(path: Path) -> bool:
    if not (Path(path) / ".git").exists():
        return False
    res = _git(path, "rev-parse", "--is-inside-work-tree")
    return bool(res and res.strip())


def _finding(rule_id, title, severity, message, fix, path, line=0, evidence="") -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity, message=message,
        path=path, line=line, evidence=evidence[:160], fix=fix,
        cwe="CWE-540" if rule_id == "SEC053" else "CWE-538",
        confidence="high", scanner="git",
    )


def _skip(cmd: str, check: str) -> Finding:
    """Visible 'git failed -> check skipped' signal (INFO — never gates).

    Non-catalog note id, same precedent as deps' DEPS-SKIP: honest reporting
    of a skipped check instead of silently reporting 'clean'.
    """
    return Finding(
        rule_id="GIT-SKIP", title="Git check skipped", severity=Severity.INFO,
        message=f"git: {cmd} failed — SKIPPING {check} (not clean)",
        path="-", line=0, fix="Verify the git CLI works in this repository, then re-run.",
        cwe="", confidence="high", scanner="git",
    )


def scan_hygiene(root: Path) -> list[Finding]:
    """Tracked-secret names, oversized blobs, remote credentials, ignore gaps."""
    findings: list[Finding] = []
    root = Path(root)

    # one `git ls-files -z` shared by checks 1, 2 and 4 (was two spawns)
    ls_out = _git(root, "ls-files", "-z")
    if ls_out is None:
        findings.append(_skip(
            "ls-files -z",
            "tracked-secret (SEC050/051), blob-size (SEC054) and env-coverage (SEC053) checks"))
        tracked: list[str] = []
    else:
        tracked = [r for r in ls_out.split("\0") if r]

    # 1) tracked files whose NAME alone is dangerous
    for rel in tracked:
        name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name in _TRACKED_SECRET_NAMES:
            rid, title, sev, fix = _TRACKED_SECRET_NAMES[name]
            findings.append(_finding(
                rid, title, sev,
                f"{rel} is tracked by git — anyone with repo access has these credentials.",
                fix, rel))
            continue
        if _ENV_FILE_RE.fullmatch(name):
            # .env.production / .env.staging / ... (exact .env/.env.local above)
            findings.append(_finding(
                "SEC050", f"Tracked {name} file", Severity.CRITICAL,
                f"{rel} is tracked by git — anyone with repo access has these credentials.",
                "Untrack it (git rm --cached), add to .gitignore, and rotate every credential it held.",
                rel))
            continue
        suffix = Path(name).suffix
        if suffix in _TRACKED_KEY_SUFFIXES:
            rid, title, sev, fix = _TRACKED_KEY_SUFFIXES[suffix]
            findings.append(_finding(rid, title, sev, f"{rel} is tracked by git.", fix, rel))

    # 2) oversized blobs (repo bloat + usually leaked artifacts)
    for rel in tracked:
        fp = root / rel
        try:
            if fp.is_file() and fp.stat().st_size > _MAX_FILE_BYTES:
                findings.append(_finding(
                    "SEC054", "Oversized file tracked in git", Severity.MEDIUM,
                    f"{rel} is {fp.stat().st_size // (1024 * 1024)} MB — git history will carry it forever.",
                    "Move large artifacts to releases/object storage and gitignore them.", rel))
        except OSError:
            continue

    # 3) credentialled remotes
    remotes = _git(root, "remote", "-v")
    if remotes is None:
        findings.append(_skip("remote -v", "credentialled-remote check (SEC052)"))
    else:
        for url in remotes.splitlines():
            # "origin\thttps://user@host/repo.git (fetch)" — credentialed remotes
            # place ":pass@" between user and host; written so this source line
            # never trips SEC013 itself.
            m = re.search(r"https?://([^\s:@/]+):([^\s@/]+)@", url)
            if m:
                # assembled from parts so this source line never matches SEC013 itself
                evidence = f"https://{m.group(1)}:" + secrets_mod.redact(m.group(2)) + "@…"
                findings.append(_finding(
                    "SEC052", "Remote URL embeds credentials", Severity.CRITICAL,
                    f"Remote '{url.split()[0]}' stores a username/password in .git/config.",
                    "Switch to a PAT-less remote (SSH or credential helper) and rotate the password.",
                    ".git/config", 0, evidence))

    # 4) env files tracked but .gitignore has no env-covering pattern
    env_like = [p for p in tracked if p.replace("\\", "/").rsplit("/", 1)[-1].startswith(".env")]
    if env_like:
        gitignore = root / ".gitignore"
        gi = (gitignore.read_text(encoding="utf-8", errors="replace")
              if gitignore.exists() else "")
        if not _ENV_IGNORE_RE.search(gi):
            findings.append(_finding(
                "SEC053", ".gitignore does not ignore .env files", Severity.LOW,
                f"{len(env_like)} env file(s) tracked and .gitignore has no env-covering "
                "pattern — future .env drops will be committed by accident.",
                "Add '.env*' to .gitignore (keep .env.example tracked).", ".gitignore"))
    return findings


def scan_history(root: Path, max_commits: int = _MAX_HISTORY_COMMITS,
                 exclude=None, allow: list[str] | None = None) -> list[Finding]:
    """Scan recent commit patches for secrets (SEC055).

    Output is capped at 8 MB so massive repos stay responsive; findings
    point at the commit that introduced the secret. ``exclude(rel_path)``
    applies the same path excludes as the working-tree scan — test fixtures
    and vendored code must not become history-only false positives.
    ``allow`` matches raw extracted values (see ``secrets.scan_text``).
    """
    root = Path(root)
    cap = min(max_commits, _MAX_HISTORY_COMMITS)
    patch = _git(root, "log", "-p", f"--max-count={cap}", "--all", "--no-merges",
                 "--format=commit %H %s", timeout=60)
    if patch is None:
        # git failed (incl. 0-commit repos where `git log` exits nonzero) —
        # a failed check must be VISIBLE, not silently reported as "clean".
        return [_skip(f"log -p --max-count={cap}", "git-history secret scan (SEC055)")]
    if not patch:
        return []
    if len(patch.encode("utf-8", errors="replace")) > _MAX_HISTORY_PATCH_BYTES:
        patch = patch.encode("utf-8", errors="replace")[:_MAX_HISTORY_PATCH_BYTES].decode("utf-8", errors="replace")

    findings: list[Finding] = []
    current_commit = "unknown"
    current_file: str | None = None
    current_old: str | None = None
    in_hunk = False
    seen: set[tuple] = set()
    for line in patch.splitlines():
        if line.startswith("commit "):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                current_commit = parts[1][:12]
            current_file = None
            current_old = None
            in_hunk = False
            continue
        if line.startswith("diff --git "):
            # new file section: without this reset in_hunk stays True from the
            # previous file's hunk, `+++ b/...` never re-parses and every later
            # file in the commit is scanned under the FIRST file's path —
            # exclude() then applies to the wrong file (fixture leaks).
            # (real content lines always start with +/- so this never matches them)
            in_hunk = False
            current_file = None
            current_old = None
            continue
        if not in_hunk:
            if line.startswith("@@"):
                in_hunk = True
                continue
            if line.startswith("--- "):
                # old path of the file this hunk touches ("--- a/path")
                src = line[4:].strip()
                current_old = None if src.startswith("/dev/null") else (
                    src[2:] if src.startswith("a/") else src)
                continue
            if line.startswith("+++ "):
                # "+++ b/path" marks the file every +/- line belongs to;
                # "+++ /dev/null" = deletion -> content belongs to the OLD path
                target = line[3:].strip()
                if target.startswith("/dev/null"):
                    current_file = current_old
                else:
                    current_file = target[2:] if target.startswith("b/") else target
                continue
        if not line or line[0] not in "+-":
            continue  # only added/removed content lines can carry a leak
        if current_file and exclude is not None and exclude(current_file):
            continue
        for rule in secrets_mod.SECRET_RULES:
            for match in rule.pattern.finditer(line):
                value = secrets_mod.extract_value(rule, line, match, allow)
                if not value:
                    continue
                key = (rule.rule_id, secrets_mod.redact(value))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    rule_id="SEC055",
                    title="Secret present in git history",
                    severity=Severity.CRITICAL,
                    message=f"{rule.title} found in commit {current_commit} — deleting the file "
                    "later does NOT remove it from history.",
                    path="<git-history>",
                    line=0,
                    evidence=f"{rule.rule_id}: {secrets_mod.redact(value)} @ {current_commit}",
                    fix="Rotate the credential, then purge history (git filter-repo / BFG).",
                    cwe="CWE-798",
                    confidence="high",
                    scanner="git",
                ))
    return findings


def scan(root: Path, history: bool = True, max_commits: int = _MAX_HISTORY_COMMITS,
         exclude=None, allow: list[str] | None = None) -> list[Finding]:
    root = Path(root)
    if not (root / ".git").exists():
        return []  # not a git repository — nothing to check (nothing failed either)
    probe = _git(root, "rev-parse", "--is-inside-work-tree")
    if probe is None:
        # .git exists but git itself fails — checks cannot run; say so instead
        # of returning [] which reads as "repo is clean".
        return [_skip("rev-parse --is-inside-work-tree", "all git hygiene/history checks")]
    if not probe.strip():
        return []  # git ran and confirmed: not a work tree
    findings = scan_hygiene(root)
    if history:
        findings.extend(scan_history(root, max_commits, exclude=exclude, allow=allow))
    return findings
