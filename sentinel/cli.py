"""Command-line interface.

Exit codes
----------
0  success (or findings below --fail-on threshold)
1  findings at/above the --fail-on threshold (CI gate)
2  usage / runtime error
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import __version__, engine, report, score
from .config import STARTER_TOML, load_config
from .models import Severity
from .rules import code as code_rules
from .rules import secrets as secrets_rules

HOOK_MARKER = "# sentinel pre-commit hook (managed by `sentinel install-hook`)"
_HOOK_BODY = f"""#!/bin/sh
{HOOK_MARKER}
# Refuse the commit when staged findings reach the configured severity
# (`fail_on` in sentinel.toml, default: high). Requires `sentinel` on PATH.
# History + dependency audits are CI jobs — the local hook stays fast/offline.
sentinel scan --staged --no-history --no-deps -q
exit $?
"""

_RULE_CATALOG_STATIC = [
    ("SEC050", "Secret-looking file tracked in git (tracked .env/credentials)", Severity.CRITICAL),
    ("SEC051", "Private key / keystore tracked in git", Severity.CRITICAL),
    ("SEC052", "Remote URL embeds credentials", Severity.CRITICAL),
    ("SEC053", ".gitignore does not cover .env files", Severity.LOW),
    ("SEC054", "Oversized file tracked in git", Severity.MEDIUM),
    ("SEC055", "Secret present in git history", Severity.CRITICAL),
    ("SEC060", "Unpinned dependency", Severity.LOW),
    ("SEC061", "Known vulnerable dependency (pip-audit)", Severity.HIGH),
    ("SEC062", "Known vulnerable dependency (npm audit)", Severity.HIGH),
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — full-sweep security scanner: secrets, code, "
                    "dependencies and git hygiene in one command.",
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="scan a repository")
    scan_p.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    scan_p.add_argument("-f", "--format", default="console",
                        choices=sorted(report.RENDERERS) + ["all"],
                        help="report format (default: console)")
    scan_p.add_argument("-o", "--output", default=None,
                        help="write report to file/dir (console prints to stdout)")
    scan_p.add_argument("--fail-on", default=None,
                        choices=["critical", "high", "medium", "low", "never"],
                        help="minimum severity that exits 1 (default: config / high)")
    scan_p.add_argument("--exclude", action="append", default=[],
                        help="extra exclude glob (repeatable)")
    scan_p.add_argument("--config", default=None, help="explicit config file")
    scan_p.add_argument("--staged", action="store_true",
                        help="scan only git-staged files (pre-commit mode)")
    scan_p.add_argument("--changed-since", default=None, metavar="REF",
                        help="scan only files changed since REF (git ref/sha) plus "
                             "uncommitted changes — PR/diff mode; history/deps still "
                             "cover the whole repo")
    scan_p.add_argument("--no-git", action="store_true", help="skip git hygiene/history checks")
    scan_p.add_argument("--no-deps", action="store_true", help="skip dependency audit")
    scan_p.add_argument("--no-history", action="store_true", help="skip git history secret scan")
    scan_p.add_argument("--history-commits", type=int, default=None,
                        help="max commits to history-scan (default 500)")
    scan_p.add_argument("--baseline", default=None,
                        help="baseline file of known findings to ignore")
    scan_p.add_argument("--update-baseline", action="store_true",
                        help="write current findings to the baseline file and exit 0")
    scan_p.add_argument("-q", "--quiet", action="store_true", help="suppress console output")

    sub.add_parser("rules", help="list the rule catalog")

    init_p = sub.add_parser("init", help="write a starter sentinel.toml")
    init_p.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    init_p.add_argument("--force", action="store_true", help="overwrite an existing config")

    hook_p = sub.add_parser("install-hook", help="install the pre-commit git hook")
    hook_p.add_argument("path", nargs="?", default=".", help="git repository root (default: .)")
    hook_p.add_argument("--force", action="store_true",
                        help="overwrite an existing hook not managed by sentinel")

    unhook_p = sub.add_parser("uninstall-hook", help="remove the sentinel pre-commit hook")
    unhook_p.add_argument("path", nargs="?", default=".", help="git repository root (default: .)")
    return parser


def _catalog() -> list[tuple[str, str, Severity]]:
    from .rules import gitcheck  # noqa: F401 - documents that ids are static

    catalog = [(r.rule_id, r.title, r.severity) for r in secrets_rules.SECRET_RULES]
    catalog += code_rules.all_rules()
    catalog += _RULE_CATALOG_STATIC
    return sorted(catalog, key=lambda x: x[0])


def _cmd_rules() -> int:
    print(f"{'RULE':<8} {'SEV':<9} TITLE")
    for rid, title, sev in _catalog():
        print(f"{rid:<8} {sev.name:<9} {title}")
    print(f"\n{len(_catalog())} rules")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2

    if args.changed_since is not None and args.staged:
        print("error: --changed-since and --staged are mutually exclusive", file=sys.stderr)
        return 2

    cfg = load_config(root, args.config)
    fail_on = args.fail_on or cfg.fail_on
    history = False if args.no_history else None
    history_commits = args.history_commits

    only_files: list[str] | None = None
    if args.changed_since is not None:
        changed = _changed_files(root, args.changed_since)
        if changed is None:
            return 2
        only_files = changed
        if not changed:
            print("no changed files", file=sys.stderr)

    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path is not None and history_commits is None:
        history_commits = cfg.history_commits
    cfg_history = history_commits if history_commits is not None else cfg.history_commits
    cfg.history_commits = cfg_history

    result = engine.scan(
        root,
        config=cfg,
        extra_excludes=args.exclude,
        staged=args.staged,
        only_files=only_files,
        run_git=not args.no_git,
        run_deps=not args.no_deps,
        history=history,
        baseline=baseline_path,
    )

    if args.update_baseline:
        target = baseline_path or root / ".sentinel-baseline"
        engine.write_baseline(target, result.findings, root)
        print(f"baseline updated: {target} ({len(result.findings)} finding(s))")
        return 0

    if args.format == "all":
        for fmt in ("json", "md", "html", "sarif"):
            report.write_report(fmt, result,
                                args.output or str(root / "sentinel-reports") + "/",
                                quiet=args.quiet)
    elif args.output or not args.quiet:
        report.write_report(args.format, result, args.output, quiet=args.quiet)

    return 1 if score.should_fail(result.exit_findings, fail_on) else 0


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=str(root), capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=30, check=False,
    )


def _changed_files(root: Path, ref: str) -> list[str] | None:
    """Relative paths changed since ``ref`` (PR semantics: merge-base diff),
    plus uncommitted and untracked changes. None = git error (bad ref)."""
    sets: list[list[str]] = []
    for args in (
        ("diff", "--name-only", "--diff-filter=ACMR", f"{ref}...HEAD"),
        ("diff", "--name-only", "--diff-filter=ACMR", "HEAD"),
        ("ls-files", "--others", "--exclude-standard"),
    ):
        proc = _git(root, *args)
        if proc.returncode != 0:
            print(f"error: git {' '.join(args)} failed: {proc.stderr.strip()}",
                  file=sys.stderr)
            return None
        sets.append([ln.strip() for ln in proc.stdout.splitlines() if ln.strip()])
    return list(dict.fromkeys(p for paths in sets for p in paths))


def _cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2
    target = root / "sentinel.toml"
    if target.exists() and not args.force:
        print(f"error: {target} already exists (use --force to overwrite)", file=sys.stderr)
        return 2
    target.write_text(STARTER_TOML, encoding="utf-8", newline="\n")
    print(f"wrote {target}")
    print("next: sentinel scan . --fail-on high")
    return 0


def _hooks_dir(root: Path) -> Path | None:
    proc = _git(root, "rev-parse", "--git-path", "hooks")
    if proc.returncode != 0:
        print(f"error: not a git repository: {root}", file=sys.stderr)
        return None
    raw = proc.stdout.strip() or ".git/hooks"
    path = Path(raw)
    return path if path.is_absolute() else root / path


def _cmd_install_hook(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    hooks = _hooks_dir(root)
    if hooks is None:
        return 2
    target = hooks / "pre-commit"
    if target.exists() and not args.force:
        existing = target.read_text(encoding="utf-8", errors="replace")
        if HOOK_MARKER not in existing:
            print(f"error: existing hook at {target} is not managed by sentinel "
                  "(use --force to overwrite)", file=sys.stderr)
            return 2
    hooks.mkdir(parents=True, exist_ok=True)
    target.write_text(_HOOK_BODY, encoding="utf-8", newline="\n")
    try:
        os.chmod(target, 0o755)
    except OSError:  # pragma: no cover - exotic filesystems
        pass
    print(f"installed {target}")
    print("commits now gate on staged findings (fail_on from sentinel.toml)")
    return 0


def _cmd_uninstall_hook(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    hooks = _hooks_dir(root)
    if hooks is None:
        return 2
    target = hooks / "pre-commit"
    if not target.exists():
        print("no pre-commit hook installed")
        return 0
    existing = target.read_text(encoding="utf-8", errors="replace")
    if HOOK_MARKER not in existing:
        print(f"error: existing hook at {target} is not managed by sentinel",
              file=sys.stderr)
        return 2
    target.unlink()
    print(f"removed {target}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2
    try:
        if args.command == "rules":
            return _cmd_rules()
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "init":
            return _cmd_init(args)
        if args.command == "install-hook":
            return _cmd_install_hook(args)
        if args.command == "uninstall-hook":
            return _cmd_uninstall_hook(args)
        parser.print_help()
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 2
    except Exception as exc:  # pragma: no cover - defensive
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
