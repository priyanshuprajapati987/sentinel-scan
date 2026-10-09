"""Repo-level container hygiene (checks that span more than one file).

Only runs on full scans (not --staged / --changed-since) because the checks
look at the repository as a whole.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ..models import Finding, Severity


def scan_repo(root: Path,
              exclude: Callable[[str], bool] | None = None) -> list[Finding]:
    """SEC074 — Dockerfile(s) present but no .dockerignore at the repo root.

    Docker only reads ``.dockerignore`` from the build-context root, so the
    presence check is root-only; a Dockerfile anywhere counts.
    """
    root = Path(root)
    try:
        dockerfiles = [
            p for p in root.rglob("*")
            if p.is_file()
            and p.name.lower().startswith("dockerfile")
            and ".git" not in p.parts
            and not (exclude and exclude(p.relative_to(root).as_posix()))
        ]
    except OSError:
        return []
    if not dockerfiles or (root / ".dockerignore").exists():
        return []
    rel = dockerfiles[0].relative_to(root).as_posix()
    return [Finding(
        rule_id="SEC074",
        title="Dockerfile without .dockerignore",
        severity=Severity.LOW,
        message=f"{rel} present but no .dockerignore at the repo root — the "
                "build context may leak .git, secrets and junk into the image.",
        path=".dockerignore",
        line=0,
        evidence="",
        fix="Add a .dockerignore covering .git, .env*, secrets, node_modules, caches.",
        cwe="CWE-200",
        confidence="high",
        scanner="code",
    )]
