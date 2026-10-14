"""Configuration: sentinel.toml / .sentinel.json + defaults.

Precedence: explicit --config > sentinel.toml > .sentinel.json > defaults.
TOML needs stdlib ``tomllib`` (3.11+) or the tiny ``tomli`` backport — if
neither exists, TOML config is skipped with a note (JSON still works).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Severity

DEFAULT_EXCLUDES = [
    ".git/", "node_modules/", "vendor/", ".venv/", "venv/", "__pycache__/",
    ".pytest_cache/", ".ruff_cache/", "dist/", "build/", "*.egg-info/",
    "coverage/", "htmlcov/", "*.min.js", "*.min.css", "*.map",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Cargo.lock", "*.snap",
]

# Written by `sentinel init` — commented so users only uncomment what they need.
STARTER_TOML = """\
# sentinel.toml — Sentinel configuration (created by `sentinel init`).
# Precedence: --config flag > sentinel.toml > .sentinel.json > built-in defaults.

# Minimum severity that makes `sentinel scan` exit 1 (the CI gate).
fail_on = "high"

# Extra exclude globs, merged on top of the built-in defaults.
# exclude = ["tests/fixtures/", "*.generated.*"]

# Git-history secret scan (SEC055) over the last N commits.
history = true
history_commits = 100

# Committed values that must never be flagged (documented test credentials,
# docs samples). Matched as substrings of the extracted value.
# allow_secrets = ["fake-test-token-for-docs"]

# Ratchet: findings recorded here are ignored by every scan (and
# `--update-baseline` refreshes it). Relative paths resolve from the repo root.
# baseline = ".github/sentinel-baseline"

# Documented suppressions. Never suppress without a reason — an expired
# `expires` date (ISO format) makes the suppression active again.
# [[suppressions]]
# rule_id = "SEC014"
# path = "tests/fixtures/dummy_password.py"
# reason = "intentional fixture, value is a placeholder"
# expires = "2027-01-01"

# Custom rules — your own regex rules, scoped to file extensions.
# An invalid pattern is reported as a config note and skipped (scan continues).
# [[custom_rules]]
# id = "CORP001"
# title = "Internal API token"
# severity = "high"
# pattern = "corp_[A-Za-z0-9]{40}"
# extensions = [".py", ".env"]
# fix = "Rotate the token and move it to a secret store."
"""

# Glob-ish directory/file patterns suppressed by default for line scanners
DEFAULT_SCAN_LIMITS = {"max_file_bytes": 2_000_000}


@dataclass
class Suppression:
    rule_id: str = "*"
    path: str = ""  # substring or glob-ish match against rel path
    reason: str = ""
    expires: str = ""  # ISO date — empty = permanent


@dataclass(frozen=True)
class CustomRule:
    """A user-defined line rule from ``[[custom_rules]]`` in sentinel.toml."""

    id: str
    title: str
    severity: Severity
    pattern: str  # original source, kept for diagnostics
    regex: re.Pattern
    message: str = ""
    fix: str = ""
    extensions: tuple[str, ...] | None = None  # None = every scanned text file
    cwe: str = ""
    confidence: str = "high"


@dataclass
class Config:
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    allow_secrets: list[str] = field(default_factory=list)  # value substrings never flagged
    suppressions: list[Suppression] = field(default_factory=list)
    custom_rules: list[CustomRule] = field(default_factory=list)
    fail_on: str = "high"
    history: bool = True
    history_commits: int = 500
    deps_cves: bool = True
    inline_suppressions: bool = True  # honour `sentinel-ignore` comments in source
    baseline: str = ""  # committed known-findings file; scan ignores its entries
    max_file_bytes: int = DEFAULT_SCAN_LIMITS["max_file_bytes"]
    notes: list[str] = field(default_factory=list)


def _load_toml(path: Path) -> dict[str, Any] | None:
    try:
        import tomllib  # py3.11+
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return None
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        # Distinguish "broken TOML" from "no parser / unreadable" so
        # load_config can report the real problem instead of the misleading
        # "no TOML parser" note (which made users think the gate was active).
        return {"__toml_error__": str(exc)}
    except OSError:
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# Top-level keys `_apply` understands — anything else becomes a config note.
_KNOWN_KEYS = {
    "exclude", "allow_secrets", "fail_on", "history", "history_commits",
    "deps_cves", "inline_suppressions", "baseline", "max_file_bytes",
    "suppressions", "custom_rules",
}
# String spellings accepted for boolean config keys (case-insensitive).
_BOOL_STRINGS = {"true": True, "false": False, "1": True, "0": False}
_OFF_GATE_VALUES = {"never", "off", "none"}


def _coerce_bool(cfg: Config, key: str, value: Any) -> bool | None:
    """Return a real bool for ``value``, or None (with a note) if impossible."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in _BOOL_STRINGS:
        return _BOOL_STRINGS[value.strip().lower()]
    cfg.notes.append(f"config: {key} should be a boolean — ignored")
    return None


def _apply_int(cfg: Config, key: str, value: Any, target: str) -> None:
    # bools are ints in Python — reject them so `history_commits = true`
    # doesn't silently become 1.
    if isinstance(value, bool) or not isinstance(value, int):
        cfg.notes.append(f"config: {key} should be an integer — ignored")
        return
    setattr(cfg, target, value)


def _apply(cfg: Config, data: dict[str, Any]) -> None:
    for key in data:
        if key not in _KNOWN_KEYS:
            cfg.notes.append(f"config: unknown key {key!r}")

    if "exclude" in data:
        if isinstance(data["exclude"], list):
            cfg.excludes.extend(str(x) for x in data["exclude"])
        else:
            cfg.notes.append("config: exclude should be a list — ignored")
    if "allow_secrets" in data:
        if isinstance(data["allow_secrets"], list):
            cfg.allow_secrets.extend(str(x) for x in data["allow_secrets"])
        else:
            cfg.notes.append("config: allow_secrets should be a list — ignored")

    fail_on = data.get("fail_on")
    if fail_on:
        value = str(fail_on)
        if value.lower() not in _OFF_GATE_VALUES:
            try:
                Severity.parse(value)
            except ValueError:
                cfg.notes.append(f"config: invalid fail_on={fail_on!r} — using 'high'")
                value = "high"
        cfg.fail_on = value

    if "history" in data:
        coerced = _coerce_bool(cfg, "history", data["history"])
        if coerced is not None:
            cfg.history = coerced
    if "history_commits" in data:
        _apply_int(cfg, "history_commits", data["history_commits"], "history_commits")
    if "deps_cves" in data:
        coerced = _coerce_bool(cfg, "deps_cves", data["deps_cves"])
        if coerced is not None:
            cfg.deps_cves = coerced
    if "inline_suppressions" in data:
        coerced = _coerce_bool(cfg, "inline_suppressions", data["inline_suppressions"])
        if coerced is not None:
            cfg.inline_suppressions = coerced
    if data.get("baseline"):
        cfg.baseline = str(data["baseline"])
    if "max_file_bytes" in data:
        _apply_int(cfg, "max_file_bytes", data["max_file_bytes"], "max_file_bytes")
    for entry in data.get("suppressions", []) or []:
        if isinstance(entry, dict):
            cfg.suppressions.append(Suppression(
                rule_id=str(entry.get("rule_id", "*")),
                path=str(entry.get("path", "")),
                reason=str(entry.get("reason", "")),
                expires=str(entry.get("expires", "")),
            ))
    for entry in data.get("custom_rules", []) or []:
        _parse_custom_rule(cfg, entry)


def _parse_custom_rule(cfg: Config, entry: Any) -> None:
    """Validate one ``[[custom_rules]]`` entry — failures become config notes
    so a bad rule never crashes a scan (it is skipped instead)."""
    if not isinstance(entry, dict):
        cfg.notes.append("config: custom rule entry must be a table — skipped")
        return
    rid = str(entry.get("id", "")).strip()
    title = str(entry.get("title", "")).strip() or rid
    pattern = str(entry.get("pattern", ""))
    if not rid:
        cfg.notes.append("config: custom rule without an id — skipped")
        return
    if not pattern:
        cfg.notes.append(f"config: custom rule {rid}: no pattern — skipped")
        return
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        cfg.notes.append(f"config: custom rule {rid}: invalid pattern ({exc}) — skipped")
        return
    try:
        severity = Severity.parse(str(entry.get("severity", "medium")))
    except ValueError as exc:
        cfg.notes.append(f"config: custom rule {rid}: {exc} — using medium")
        severity = Severity.MEDIUM
    extensions: tuple[str, ...] | None = None
    ext_list = entry.get("extensions")
    if isinstance(ext_list, list) and ext_list:
        extensions = tuple(
            (str(e).lower() if str(e).startswith(".") else f".{str(e).lower()}")
            for e in ext_list
        )
    cfg.custom_rules.append(CustomRule(
        id=rid,
        title=title,
        severity=severity,
        pattern=pattern,
        regex=regex,
        message=str(entry.get("message", "")),
        fix=str(entry.get("fix", "")),
        extensions=extensions,
        cwe=str(entry.get("cwe", "")),
        confidence=str(entry.get("confidence", "high")),
    ))


def load_config(root: Path, explicit: str | None = None) -> Config:
    cfg = Config()
    root = Path(root)
    loaded = False

    if explicit:
        p = Path(explicit)
        data = _load_toml(p) if p.suffix.lower() == ".toml" else _load_json(p)
        if data is None:
            cfg.notes.append(f"config: could not read {explicit}")
        elif "__toml_error__" in data:
            cfg.notes.append(
                f"config: invalid TOML in {explicit}: {data['__toml_error__']}")
        else:
            _apply(cfg, data)
            loaded = True
    else:
        toml_path = root / "sentinel.toml"
        if toml_path.exists():
            data = _load_toml(toml_path)
            if data is None:
                cfg.notes.append(
                    "config: sentinel.toml found but no TOML parser (need Python 3.11+ or `pip install tomli`)")
            elif "__toml_error__" in data:
                cfg.notes.append(
                    f"config: invalid TOML in sentinel.toml: {data['__toml_error__']}")
            else:
                _apply(cfg, data)
                loaded = True
        else:
            json_path = root / ".sentinel.json"
            if json_path.exists():
                data = _load_json(json_path)
                if data is None:
                    cfg.notes.append("config: .sentinel.json is not valid JSON")
                else:
                    _apply(cfg, data)
                    loaded = True
    if not loaded and not cfg.notes:
        cfg.notes.append("config: using built-in defaults (no sentinel.toml found)")
    return cfg
