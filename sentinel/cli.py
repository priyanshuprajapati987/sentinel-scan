"""Command-line interface.

Exit codes
----------
0  success (or findings below --fail-on threshold)
1  findings at/above the --fail-on threshold (CI gate)
2  usage / runtime error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, engine, report, score
from .config import load_config
from .models import Severity
from .rules import code as code_rules
from .rules import secrets as secrets_rules

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

    cfg = load_config(root, args.config)
    fail_on = args.fail_on or cfg.fail_on
    history = False if args.no_history else None
    history_commits = args.history_commits

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
