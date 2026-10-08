"""Configuration: sentinel.toml / .sentinel.json + defaults.

Precedence: explicit --config > sentinel.toml > .sentinel.json > defaults.
TOML needs stdlib ``tomllib`` (3.11+) or the tiny ``tomli`` backport — if
neither exists, TOML config is skipped with a note (JSON still works).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_EXCLUDES = [
    ".git/", "node_modules/", "vendor/", ".venv/", "venv/", "__pycache__/",
    ".pytest_cache/", ".ruff_cache/", "dist/", "build/", "*.egg-info/",
    "coverage/", "htmlcov/", "*.min.js", "*.min.css", "*.map",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Cargo.lock", "*.snap",
]

# Glob-ish directory/file patterns suppressed by default for line scanners
DEFAULT_SCAN_LIMITS = {"max_file_bytes": 2_000_000}


@dataclass
class Suppression:
    rule_id: str = "*"
    path: str = ""  # substring or glob-ish match against rel path
    reason: str = ""
    expires: str = ""  # ISO date — empty = permanent


@dataclass
class Config:
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    allow_secrets: list[str] = field(default_factory=list)  # value substrings never flagged
    suppressions: list[Suppression] = field(default_factory=list)
    fail_on: str = "high"
    history: bool = True
    history_commits: int = 500
    deps_cves: bool = True
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
    except (OSError, ValueError):
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _apply(cfg: Config, data: dict[str, Any]) -> None:
    if isinstance(data.get("exclude"), list):
        cfg.excludes.extend(str(x) for x in data["exclude"])
    if isinstance(data.get("allow_secrets"), list):
        cfg.allow_secrets.extend(str(x) for x in data["allow_secrets"])
    if data.get("fail_on"):
        cfg.fail_on = str(data["fail_on"])
    if "history" in data:
        cfg.history = bool(data["history"])
    if isinstance(data.get("history_commits"), int):
        cfg.history_commits = data["history_commits"]
    if "deps_cves" in data:
        cfg.deps_cves = bool(data["deps_cves"])
    if isinstance(data.get("max_file_bytes"), int):
        cfg.max_file_bytes = data["max_file_bytes"]
    for entry in data.get("suppressions", []) or []:
        if isinstance(entry, dict):
            cfg.suppressions.append(Suppression(
                rule_id=str(entry.get("rule_id", "*")),
                path=str(entry.get("path", "")),
                reason=str(entry.get("reason", "")),
                expires=str(entry.get("expires", "")),
            ))


def load_config(root: Path, explicit: str | None = None) -> Config:
    cfg = Config()
    root = Path(root)
    loaded = False

    if explicit:
        p = Path(explicit)
        data = _load_toml(p) if p.suffix == ".toml" else _load_json(p)
        if data is None:
            cfg.notes.append(f"config: could not read {explicit}")
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
