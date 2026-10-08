# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-10-08

### Added
- `sentinel init` — commented starter `sentinel.toml` (`--force` to overwrite)
- `sentinel install-hook` / `sentinel uninstall-hook` — marker-guarded managed
  `.git/hooks/pre-commit` gate; never touches a hook it did not install
- `sentinel scan --changed-since REF` — PR/diff mode: merge-base diff plus
  uncommitted and untracked files; history/deps still cover the whole repo
- `.pre-commit-hooks.yaml` — pre-commit framework integration
- `python -m sentinel` entrypoint
- GitHub action input `changed-since` (PR CI) and `upload-sarif`
- CHANGELOG.md, SECURITY.md, README badges

### Changed
- Pre-commit hook now runs `--staged --no-history --no-deps` — stays fast and
  fully offline; history/dependency audits belong in CI
- SEC014 entropy floor lowered 3.2 → 3.0 — `password = "hunter2secret99"`
  (H = 3.19) was missing the gate by 0.01 bits

## [0.1.0] - 2026-10-08

### Added
- First release: 45 rules across four layers
  - Secrets SEC001–SEC015 (vendor patterns, entropy-gated generics, redacted evidence)
  - Code SAST SEC020–SEC040 (py/js/sh/yml/env, CWE-tagged)
  - Git hygiene + history SEC050–SEC055 (excludes apply to history diffs)
  - Dependencies SEC060–SEC062 (pip-audit / npm audit, honest offline degradation)
- Score 0–100 + grade A–F, `--fail-on` CI gate (exit 0/1/2)
- Reports: console, JSON, Markdown, HTML, SARIF 2.1.0
- `sentinel.toml` / `.sentinel.json` config, baseline, suppressions with expiry
- `--staged` pre-commit mode, GitHub composite action, workflow_dispatch CI
- 178 tests, ruff clean, self-scan 100/A

[Unreleased]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/priyanshuprajapati987/sentinel-scan/releases/tag/v0.1.0
