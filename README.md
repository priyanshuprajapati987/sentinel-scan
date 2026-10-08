# Sentinel Scan

[![Release](https://img.shields.io/github/v/release/priyanshuprajapati987/sentinel-scan)](https://github.com/priyanshuprajapati987/sentinel-scan/releases)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-189%20passing-brightgreen)](CHANGELOG.md)

**Full-sweep security scanner for source repositories** — secrets, code
vulnerabilities, dependency audits and git hygiene in one command, with a
score, a grade, fix suggestions and SARIF output.

```bash
pip install .
sentinel init .                    # write a starter sentinel.toml
sentinel scan .                    # console report, exits 1 on HIGH+
sentinel install-hook .            # gate every commit on staged findings
sentinel scan . --changed-since origin/main   # PR/diff mode: changed files only
sentinel scan . -f sarif -o out.sarif
sentinel scan . --fail-on never    # report only, always exit 0
```

## Why not just GitHub's built-in security?

| Capability | GitHub (private repos, free) | Sentinel |
|---|---|---|
| Secret scanning | Basic pattern set, alerts need setup | 15 vendor rules + entropy-gated generics, redacted evidence |
| Code scanning (SAST) | CodeQL — Python/JS/Go/Java/C#/C++/Ruby/Rust/Go only | Lightweight line-level SAST for py/js/sh/yml/env/config, CWE-tagged, 0 dependencies |
| Dependency CVE audit | Dependabot (needs enablement + alerts) | `pip-audit` + `npm audit` when installed, graceful offline degradation |
| Git hygiene (tracked `.env`, credentialed remotes, >50 MB blobs) | Not covered | SEC050–SEC054 |
| Git **history** secret scan | Only on public repos (push protection) | SEC055 — `git log -p` scan, capped output |
| Works fully offline / locally | No | Yes — no network needed except optional CVE tools |
| `--staged` pre-commit gate | No | Yes (`sentinel install-hook` one-liner) |
| Baseline / suppressions / expiry | No | Yes (`--baseline`, `sentinel.toml`) |
| Score + letter grade | No | 0–100, grades A–F, CRITICAL caps the grade |
| SARIF upload | Yes | Yes (SARIF 2.1.0 + `security-severity`) |
| Free on private repos | Yes | Yes |

## Install

```bash
git clone https://github.com/priyanshuprajapati987/sentinel-scan.git
cd sentinel-scan
pip install .            # console script: sentinel
```

Python ≥ 3.11 recommended (TOML config via stdlib `tomllib`; `tomli` works
as a backport on 3.10). Optional: `pip install pip-audit` for Python CVE
coverage; `npm` on PATH for npm audit coverage.

## Usage

```
sentinel scan [path] [options]
sentinel init [path]               # write starter sentinel.toml (--force to overwrite)
sentinel install-hook [path]       # install the pre-commit gate (--force for foreign hooks)
sentinel uninstall-hook [path]     # remove the hook sentinel installed
sentinel rules                     # list the full rule catalog
```

| Option | Meaning |
|---|---|
| `-f, --format` | `console` (default), `json`, `md`, `html`, `sarif`, `all` |
| `-o, --output` | write report to file (or directory for `all`) |
| `--fail-on` | `critical` \| `high` (default) \| `medium` \| `low` \| `never` |
| `--staged` | scan only git-staged files (pre-commit mode) |
| `--changed-since REF` | scan only files changed since git `ref` (merge-base/PR diff) + uncommitted/untracked changes |
| `--exclude GLOB` | extra exclude pattern (repeatable) |
| `--config FILE` | explicit `sentinel.toml` / `.sentinel.json` |
| `--baseline FILE` / `--update-baseline` | ignore known findings / record current ones |
| `--no-git` / `--no-history` / `--no-deps` | skip git hygiene / history / dependency checks |
| `--history-commits N` | history scan window (default 500) |
| `-q, --quiet` | no stdout (files are still written) |

**Exit codes:** `0` below the gate · `1` findings at/above `--fail-on` ·
`2` usage or runtime error. INFO-level findings (e.g. "dependency audit
skipped") never fail the gate.

## Configuration — `sentinel.toml`

```toml
fail_on = "high"
exclude = ["vendor/**", "testdata/**"]
allow_secrets = ["my-test-token"]     # value substrings never flagged
history_commits = 500
deps_cves = true

[[suppressions]]
rule_id = "SEC020"
path = "tests/fixtures/**"
reason = "intentional vulnerable fixtures"
expires = "2027-01-01"                # optional — after this date the rule is live again
```

Precedence: `--config` → `sentinel.toml` → `.sentinel.json` → defaults.

## Rule catalog (45 rules)

| Range | Area | Examples |
|---|---|---|
| SEC001–SEC013 | Vendor secrets | AWS `AKIA…`, GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, Slack, JWT, DB URLs, Stripe, Telegram, basic-auth URLs |
| SEC014–SEC015 | Generic secrets | `password/api_key/token = "<literal>"` — only fires above an entropy threshold, placeholders (`changeme`, `${VAR}`, …) are never flagged |
| SEC020–SEC030 | Injection & dangerous APIs | `eval`/`exec`, `shell=True`, `os.system`, unsafe `pickle`/`yaml.load`, `verify=False`, `debug=True`, CORS `*`, f-string SQL |
| SEC031–SEC037 | Web/file risks | `innerHTML`, `dangerouslySetInnerHTML`, remote script piped to a shell, XXE, `mktemp`, dynamic `__import__` |
| SEC038–SEC040 | CI/workflow + perms | `pull_request_target` + checkout, unpinned third-party actions, `chmod 777` |
| SEC050–SEC055 | Git hygiene & history | tracked `.env`/keys, credentialed remotes, `.gitignore` gaps, >50 MB blobs, secrets in history |
| SEC060–SEC062 | Dependencies | unpinned versions, `pip-audit` CVEs, `npm audit` CVEs (offline → INFO note, never a failure) |

Every secret finding's evidence is **redacted before it leaves the rule
module** (`sk-pro…7f2c` style) — reports and CI logs never echo a live
credential.

## CI

```yaml
# .github/workflows/security.yml
on: [push, pull_request]
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # full history for SEC055
      - uses: priyanshuprajapati987/sentinel-scan@main
        with:
          path: .
          fail-on: high
```

PR mode (scan only what the PR touches, fast + zero unrelated noise):

```yaml
      - uses: priyanshuprajapati987/sentinel-scan@main
        with:
          changed-since: ${{ github.event.pull_request.base.sha }}
```

Or as a plain step: `pip install . && sentinel scan . --changed-since origin/main --fail-on high -f sarif -o sentinel.sarif`.

## Pre-commit

Managed hook (recommended — refuses to touch hooks sentinel did not install):

```bash
sentinel install-hook .            # writes .git/hooks/pre-commit
sentinel uninstall-hook .          # removes it again
```

[pre-commit](https://pre-commit.com) framework — add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/priyanshuprajapati987/sentinel-scan
  rev: v0.1.1
  hooks:
    - id: sentinel
```

Both run the **fast local gate**: staged files + git hygiene only —
`--no-history --no-deps` keeps every commit offline and instant; history and
dependency audits belong in CI. Manual equivalent:

```bash
sentinel scan . --staged --no-history --no-deps --fail-on high -q
```

> **Windows note:** GUI git clients often have a slim `PATH` — if the hook
> fails with `sentinel: not found`, use an absolute path to the `sentinel`
> script inside `.git/hooks/pre-commit`.

## Development

```bash
ruff check .          # lint
python -m pytest      # 189 tests
sentinel scan .       # self-scan (tests/ excluded via sentinel.toml)
```

## License

MIT — see [LICENSE](LICENSE).
