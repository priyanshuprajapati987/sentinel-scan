# Sentinel Scan

[![Release](https://img.shields.io/github/v/release/priyanshuprajapati987/sentinel-scan)](https://github.com/priyanshuprajapati987/sentinel-scan/releases)
[![CI](https://github.com/priyanshuprajapati987/sentinel-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/priyanshuprajapati987/sentinel-scan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-237%20passing-brightgreen)](CHANGELOG.md)

**One command that sweeps a repository's entire attack surface** — secrets,
code vulnerabilities, dependency CVEs, and git hygiene — then hands you a
score, a grade, fix suggestions, and SARIF that GitHub Code Scanning
understands. Zero runtime dependencies, fully offline, MIT.

---

## What it does

`sentinel scan .` inspects **four attack surfaces at once** and prints one
combined verdict:

1. **Secrets (SEC001–015)** — 15 vendor patterns (AWS, GitHub, OpenAI,
   Slack, JWT, database URLs, Stripe, Telegram, basic-auth URLs) plus
   entropy-gated generics. Evidence is **redacted before it leaves the rule
   module** — reports and CI logs never echo a live credential.
2. **Code vulnerabilities — SAST (SEC020–042)** — line-level rules for
   Python, JavaScript, shell, YAML, env and config files: `eval`/`exec`,
   `shell=True`, SQL f-strings, `verify=False`, CORS `*`, `innerHTML`,
   unsafe pickle/yaml.load, CI script injection (`${{ github.event.* }}`
   in `run:`), `permissions: write-all`, and more. CWE-tagged.
3. **Dependencies (SEC060–062)** — unpinned versions always; real CVE
   data via `pip-audit` / `npm audit` when installed. Offline → honest
   INFO note, never a fake pass or a crash.
4. **Git hygiene + history (SEC050–055)** — tracked `.env`/key files,
   credentialed remotes, `.gitignore` gaps, >50 MB blobs, and secrets in
   the last 500 commits.
5. **Container / IaC (SEC070–074)** — untagged/`:latest` base images,
   secrets baked into `ENV`/`ARG`, `privileged: true`, `docker.sock`,
   Dockerfile without `.dockerignore`.

And the verdict: **score 0–100 + letter grade A–F** (a CRITICAL finding
caps the grade), fix suggestions per finding, stable 12-char finding ids,
and exit codes that gate CI.

```bash
pip install .
sentinel init .                    # write a starter sentinel.toml
sentinel scan .                    # console report, exits 1 on HIGH+
sentinel allow a1b2c3d4e5f6 --reason "test fixture"   # accept a finding
sentinel install-hook .            # gate every commit on staged findings
sentinel scan . --changed-since origin/main   # PR/diff mode: changed files only
sentinel scan . -f sarif -o out.sarif
sentinel scan . --fail-on never    # report only, always exit 0
```

---

## Problems it solves

| The problem | How Sentinel fixes it |
|---|---|
| "I need gitleaks + Semgrep + Trivy + a git-hygiene script — five tools, five configs, five CI jobs" | **One command, one config** (`sentinel.toml`), 52 rules across all four surfaces, zero runtime dependencies to install |
| "Our secret scanner printed a live AWS key into the public CI log" | Evidence is **redacted inside the rule module** (`sk-pro…7f2c`) before any report, log, or SARIF file is built |
| "False positives block every PR; turning the scanner off feels worse" | `sentinel allow <id>` (one line, per finding), `[[suppressions]]` with glob paths, `allow_secrets` values, baselines, and **expiry dates** — suppressions that heal themselves |
| "GitHub's security features don't cover our private repos on the free plan" | Everything runs **locally and offline** — no plan, no cloud, no telemetry; works on private repos forever |
| "CI takes 10 minutes scanning files this PR never touched" | `--changed-since <base-sha>` scans only the diff + uncommitted changes; `--staged` for commit-time scans |
| "A wall of raw findings — no idea what's actually urgent" | Score + grade + severity gate (`--fail-on`); CRITICAL caps the grade so disasters can't hide behind an average |
| "History leaks even when the working tree is clean" | SEC055 scans `git log -p` output (windowed, capped) for committed secrets |

### Why not just GitHub's built-in security?

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

---

## Where you can use it

| Context | How | What you get |
|---|---|---|
| **1. On your laptop (fully offline)** | `sentinel scan .` | Full sweep incl. git history — no network, no account, no telemetry |
| **2. Every commit — pre-commit gate** | `sentinel install-hook .` (or the [pre-commit](https://pre-commit.com) framework) | Staged files + git hygiene only, instant and offline; history/deps stay in CI |
| **3. CI on every push / PR** | `uses: priyanshuprajapati987/sentinel-scan@main` ([details](#ci)) | Full scan or PR-diff mode (`changed-since`) with a hard `--fail-on` gate |
| **4. GitHub Code Scanning** | SARIF upload workflow ([details](#github-code-scanning)) | Findings appear as alerts in the repo's **Security → Code scanning** tab — [live example on this repo](https://github.com/priyanshuprajapati987/sentinel-scan/security/code-scanning/1) |
| **5. Any stack** | — | Python, JavaScript, shell, YAML, Dockerfiles, GitHub workflows, `.env` files, git history |
| **6. Private / air-gapped environments** | Same CLI | MIT, zero dependencies, offline by design — no paid plan required |

---

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
sentinel allow FINGERPRINT [path]  # accept a finding: appends [[suppressions]] to sentinel.toml
sentinel rules                     # list the full rule catalog (incl. your custom rules)
sentinel install-hook [path]       # install the pre-commit gate (--force for foreign hooks)
sentinel uninstall-hook [path]     # remove the hook sentinel installed
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

# Your own regex rules — scanned line-by-line like the built-ins.
[[custom_rules]]
id = "CORP001"
title = "Internal API token"
severity = "high"                     # info | low | medium | high | critical
pattern = "corp_[A-Za-z0-9]{40}"
extensions = [".py", ".env"]          # optional — omit to scan every text file
fix = "Rotate the token and move it to a secret store."
```

Precedence: `--config` → `sentinel.toml` → `.sentinel.json` → defaults.
An invalid custom-rule pattern becomes a config note and is skipped —
a typo never crashes a scan.

### Accepting a finding — `sentinel allow`

Every finding is printed with a stable 12-char id (`[a1b2c3…]` in the
console report, `"id"` in the JSON output). To accept one permanently:

```bash
sentinel allow a1b2c3d4e5f6 --reason "intentional test fixture"
```

This re-scans, resolves the id (6+ char prefix is enough) and appends a
`[[suppressions]]` block to `sentinel.toml`. Re-running on an already
allowed finding is a no-op. The suppression matches by rule + path, so the
finding stays gone even if the surrounding lines shift.

## Rule catalog (52 rules)

| Range | Area | Examples |
|---|---|---|
| SEC001–SEC013 | Vendor secrets | AWS `AKIA…`, GitHub `ghp_`/`github_pat_`, OpenAI `sk-`, Slack, JWT, DB URLs, Stripe, Telegram, basic-auth URLs |
| SEC014–SEC015 | Generic secrets | `password/api_key/token = "<literal>"` — only fires above an entropy threshold, placeholders (`changeme`, `${VAR}`, …) are never flagged |
| SEC020–SEC037 | Injection & dangerous APIs | `eval`/`exec`, `shell=True`, `os.system`, unsafe `pickle`/`yaml.load`, `verify=False`, `debug=True`, CORS `*`, f-string SQL, `innerHTML`, remote script piped to a shell, XXE, `mktemp`, dynamic `__import__` |
| SEC038–SEC042 | CI/workflow security | `pull_request_target` + checkout, unpinned third-party actions, `chmod 777`, **`${{ github.event.* }}` inside `run:` (script injection, SEC041)**, `permissions: write-all` (SEC042) |
| SEC050–SEC055 | Git hygiene & history | tracked `.env`/keys, credentialed remotes, `.gitignore` gaps, >50 MB blobs, secrets in history |
| SEC060–SEC062 | Dependencies | unpinned versions, `pip-audit` CVEs, `npm audit` CVEs (offline → INFO note, never a failure) |
| SEC070–SEC074 | Container / IaC | untagged `FROM` (SEC070, stage-aware), `:latest` (SEC071), secrets in `ENV`/`ARG` (SEC072), `privileged: true` / `docker.sock` (SEC073), Dockerfile without `.dockerignore` (SEC074); remote-script-piped-to-a-shell also covers Dockerfiles |

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
      - uses: actions/checkout@v7
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

### GitHub Code Scanning

Upload the SARIF so findings show up as **alerts in the Security tab**
(free for public repos; this repo dogfoods it — see the
[live alert](https://github.com/priyanshuprajapati987/sentinel-scan/security/code-scanning/1)):

```yaml
# .github/workflows/code-scanning.yml
name: code-scanning
on: [push]
permissions:
  contents: read
  security-events: write      # required for the upload
jobs:
  upload-sarif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v7
        with: { python-version: "3.11" }
      - run: pip install -e .
      - run: sentinel scan . -f sarif -o sentinel.sarif --fail-on high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with: { sarif_file: sentinel.sarif }
```

## Pre-commit

Managed hook (recommended — refuses to touch hooks sentinel did not install):

```bash
sentinel install-hook .            # writes .git/hooks/pre-commit
sentinel uninstall-hook .          # removes it again
```

[pre-commit](https://pre-commit.com) framework — add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/priyanshuprajapati987/sentinel-scan
  rev: v0.2.0
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
python -m pytest      # 237 tests
sentinel scan .       # self-scan (tests/ excluded via sentinel.toml)
```

CI runs lint + tests on **ubuntu and windows** + a self-scan gate +
a Code Scanning upload. See [CONTRIBUTING.md](CONTRIBUTING.md) for rule
conventions.

## License & Legal

The code is **MIT** — see [LICENSE](LICENSE). Full set of applicable
project files:

| File | What it covers |
|------|----------------|
| [LICENSE](LICENSE) | MIT license for all source, docs, and release artifacts (also shipped inside the wheel/sdist) |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | Zero runtime dependencies — full transparency on dev-only tools |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant v2.1 |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting via GitHub Security Advisories |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution + rule-authoring conventions |
