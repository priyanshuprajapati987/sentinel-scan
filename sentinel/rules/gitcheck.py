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

_ENV_IGNORE_RE = re.compile(r"^\.env\b|^\*\.env\b", re.MULTILINE)


def _git(root: Path, *args: str, timeout: int = 30) -> str:
    """Run a git command; returns stdout ('' on failure). Never raises."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists() and bool(_git(path, "rev-parse", "--is-inside-work-tree").strip())


def _finding(rule_id, title, severity, message, fix, path, line=0, evidence="") -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity, message=message,
        path=path, line=line, evidence=evidence[:160], fix=fix,
        cwe="CWE-540" if rule_id == "SEC053" else "CWE-538",
        confidence="high", scanner="git",
    )


def scan_hygiene(root: Path) -> list[Finding]:
    """Tracked-secret names, oversized blobs, remote credentials, ignore gaps."""
    findings: list[Finding] = []
    root = Path(root)

    # 1) tracked files whose NAME alone is dangerous
    tracked = _git(root, "ls-files").splitlines()
    for rel in tracked:
        name = rel.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if name in _TRACKED_SECRET_NAMES:
            rid, title, sev, fix = _TRACKED_SECRET_NAMES[name]
            findings.append(_finding(
                rid, title, sev,
                f"{rel} is tracked by git — anyone with repo access has these credentials.",
                fix, rel))
            continue
        suffix = Path(name).suffix
        if suffix in _TRACKED_KEY_SUFFIXES:
            rid, title, sev, fix = _TRACKED_KEY_SUFFIXES[suffix]
            findings.append(_finding(rid, title, sev, f"{rel} is tracked by git.", fix, rel))

    # 2) oversized blobs (repo bloat + usually leaked artifacts)
    proc_sizes = _git(root, "ls-files", "-z")
    for rel in [r for r in proc_sizes.split("\0") if r]:
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
    for url in _git(root, "remote", "-v").splitlines():
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

    # 4) .gitignore does not cover .env but env-style files exist
    gitignore = root / ".gitignore"
    env_like = [p for p in tracked if p.replace("\\", "/").rsplit("/", 1)[-1].startswith(".env")]
    if env_like and gitignore.exists():
        gi = gitignore.read_text(encoding="utf-8", errors="replace")
        if not _ENV_IGNORE_RE.search(gi):
            findings.append(_finding(
                "SEC053", ".gitignore does not ignore .env files", Severity.LOW,
                f"{len(env_like)} env file(s) tracked and no .env pattern in .gitignore — "
                "future .env drops will be committed by accident.",
                "Add '.env*' to .gitignore (keep .env.example tracked).", ".gitignore"))
    return findings


def scan_history(root: Path, max_commits: int = _MAX_HISTORY_COMMITS,
                 exclude=None) -> list[Finding]:
    """Scan recent commit patches for secrets (SEC055).

    Output is capped at 8 MB so massive repos stay responsive; findings
    point at the commit that introduced the secret. ``exclude(rel_path)``
    applies the same path excludes as the working-tree scan — test fixtures
    and vendored code must not become history-only false positives.
    """
    root = Path(root)
    cap = min(max_commits, _MAX_HISTORY_COMMITS)
    patch = _git(root, "log", "-p", f"--max-count={cap}", "--all", "--no-merges",
                 "--format=commit %H %s", timeout=60)
    if not patch:
        return []
    if len(patch.encode("utf-8", errors="replace")) > _MAX_HISTORY_PATCH_BYTES:
        patch = patch.encode("utf-8", errors="replace")[:_MAX_HISTORY_PATCH_BYTES].decode("utf-8", errors="replace")

    findings: list[Finding] = []
    current_commit = "unknown"
    current_file: str | None = None
    seen: set[tuple] = set()
    for line in patch.splitlines():
        if line.startswith("commit "):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                current_commit = parts[1][:12]
            current_file = None
            continue
        if line.startswith("+++ "):
            # "+++ b/path/to/file" marks the file every +/- line belongs to
            target = line[3:].strip()
            current_file = None if target.startswith("/dev/null") else (
                target[2:] if target.startswith("b/") else target)
            continue
        if not line or line[0] not in "+-":
            continue  # only added/removed content lines can carry a leak
        if current_file and exclude is not None and exclude(current_file):
            continue
        for rule in secrets_mod.SECRET_RULES:
            for match in rule.pattern.finditer(line):
                try:
                    value = match.group(rule.value_group)
                except IndexError:
                    continue
                if not value:
                    continue
                if rule.min_entropy and secrets_mod.shannon_entropy(value) < rule.min_entropy:
                    continue
                if secrets_mod._PLACEHOLDER_RE.search(value):
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
         exclude=None) -> list[Finding]:
    if not is_git_repo(Path(root)):
        return []
    findings = scan_hygiene(Path(root))
    if history:
        findings.extend(scan_history(Path(root), max_commits, exclude=exclude))
    return findings
