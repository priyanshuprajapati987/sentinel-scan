# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-10-13

### Added
- **PHP SAST** (6 new rules, `.php`/`.phtml`): SEC077 unsafe
  `unserialize()`, SEC078 shell exec (`system`/`exec`/`passthru`/
  `shell_exec`/`popen`/`proc_open`), SEC079 deprecated `mysql_query()`,
  SEC080 `preg_replace` `/e` code-execution modifier, SEC081 `extract()`
  on request superglobals, SEC082 weak password hashes `md5()`/`sha1()`
  — SEC020 (`eval`) now also covers PHP
- **C# SAST** (4 new rules, `.cs`): SEC083 SQL string concatenation,
  SEC084 `Process.Start` via cmd/powershell, SEC085 weak crypto
  (DES/RC2/MD5/SHA-1 providers), SEC086 `BinaryFormatter`/`SoapFormatter`
  deserialization
- **Multi-ecosystem pin hygiene** (SEC060 extended): Ruby `Gemfile`
  gems without a version constraint, PHP `composer.json` floating
  constraints (`*`/`dev-master`; platform reqs skipped), Maven
  `pom.xml` dynamic versions (`LATEST`/`RELEASE`)

## [0.5.0] - 2026-10-13

### Added
- **Polyglot SAST — Go, Java, Ruby** (languages now: Python, JavaScript/
  TypeScript, shell, YAML, Dockerfile, env/config, **Go, Java, Ruby**;
  9 new rules, 67 → 76)
  - Go: SEC058 SQL built with `fmt.Sprintf` / string concat into
    `db.Query`, SEC059 `InsecureSkipVerify: true`
  - Java: SEC064 `Runtime.exec` / `ProcessBuilder`, SEC065 MD5/SHA-1
    `MessageDigest`, SEC066 weak ciphers (DES/RC4/Blowfish),
    SEC067 `ObjectInputStream` / `readObject` native deserialization
  - Ruby: SEC068 unsafe `YAML.load` (Psych), SEC069 shell interpolation
    (`system("ls #{x}")`, backticks, Open3)
  - Shared: SEC063 `sh`/`bash -c` shell invocation (Go `exec.Command`,
    Java `String[]{"sh","-c",…}`, Ruby `system("sh","-c",…)`)
  - SEC020/SEC021 (`eval`/`exec`) now also cover Ruby
- **`-f junit` report format** — JUnit XML (one failing testcase per
  finding, grouped by rule) for GitLab "Unit test report", Jenkins test
  tabs, and any CI consuming JUnit artifacts; clean scans emit a single
  green suite; special characters XML-escaped

## [0.4.0] - 2026-10-13

### Added
- **`-f gitlab` report format** — GitLab Code Quality artifact
  (`reports: codequality`); fingerprints are line-shift-tolerant so
  GitLab's baseline dedup survives refactors; maps CRITICAL→critical …
  INFO→info; file-level findings land at `lines.begin: 1`
- **`baseline` config key** — set once in `sentinel.toml`
  (`baseline = ".github/sentinel-baseline"`); every scan ignores its
  findings and `--update-baseline` refreshes it in place. The `--baseline`
  flag still overrides the config
- **4 new rules (63 → 67)**
  - SEC048 security check implemented with `assert` — stripped under
    `python -O`, silently disabling the check (HIGH)
  - SEC049 deprecated `crypto.createCipher`/`createDecipher` (MEDIUM)
  - SEC056 `document.write` DOM XSS sink (MEDIUM)
  - SEC057 `jwt.decode` without an explicit `algorithms=` allowlist —
    blocks algorithm-confusion attacks (HIGH)

## [0.3.0] - 2026-10-13

### Added
- **Inline suppression comments** — `# sentinel-ignore SEC020` on the same
  line, or `# sentinel-ignore-next-line` on the line above (comma lists and
  bare `sentinel-ignore` for all rules); honoured for `#`, `//`, `--`
  comments; opt out with `inline_suppressions = false` in sentinel.toml;
  count surfaces in the `suppressed` stat
- **`sentinel diff OLD NEW`** — compare two SARIF or sentinel JSON reports
  and gate CI on findings that are **NEW** since a baseline (ratchet);
  matches by line-shift-tolerant `partialFingerprints` so a finding that
  merely moved is unchanged, not new+removed; `--fail-on`, `-f json`, `-o`
- **`-f github` report format** — GitHub Actions workflow-command
  annotations (`::error` / `::warning`) so findings render inline on the
  PR diff without a SARIF upload
- **SARIF `partialFingerprints`** — stable 12-char id per finding
  (`sentinelStable/v1`) derived from rule+path+evidence, independent of
  the line number
- **11 new rules (52 → 63)**
  - SEC016 AWS secret access key (context + 40-char value, redacted)
  - SEC017 credential in URL query string (`?api_key=…`, redacted)
  - SEC018 hardcoded Bearer token (entropy-gated, redacted)
  - SEC019 hardcoded application secret key (`SECRET_KEY`/`JWT_SECRET`/…,
    entropy-gated, redacted)
  - SEC043 open redirect (user input into redirect target)
  - SEC044 server-side template from dynamic string (SSTI)
  - SEC045 unsafe archive extraction (`extractall`)
  - SEC046 HTTP call without a timeout (`requests`/`httpx`)
  - SEC047 TLS verification disabled in download (`curl -k` / `--insecure`)
  - SEC075 Dockerfile `ADD` from remote URL
  - SEC076 container explicitly running as `USER root`
  - SEC040 extended: `0o777` mode literals in Python
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1 (enforcement via
  GitHub Security Advisories, no personal email required)
- `THIRD_PARTY_NOTICES.md` — explicit zero-runtime-dependency statement +
  dev-tool license transparency table
- README "License & Legal" table linking all applicable project files
- Dependabot config for GitHub Actions version bumps
- CI badge on README

### Changed
- README restructured around three questions — **what it does**, **what
  problems it solves**, **where you can use it** — plus a new "GitHub Code
  Scanning" integration section linking the live alert on this repo
- Repository made **public** (MIT from day one; description, topics, and
  secret scanning + push protection enabled)

### Fixed
- CI workflow YAML: step name containing `:` (`Self scan (gate: high)`)
  crashed the YAML parser — GitHub created runs with **0 jobs** and instant
  failure. Step name is now quoted; `pytest-timeout` installed properly
  (the `||` shell fallback is gone)
- CI actions bumped to v7 (`checkout`, `setup-python`, `upload-artifact`)
  — silences Node.js 20 deprecation warnings

## [0.2.0] - 2026-10-08

### Added
- `[[custom_rules]]` in `sentinel.toml` — your own regex line rules
  (id/title/severity/pattern, optional `extensions`, `fix`, `cwe`,
  `message`); invalid patterns become config notes and are skipped
- `sentinel allow FINGERPRINT` — accept a finding: resolves the 12-char id
  shown in console reports / JSON (`"id"`) and appends a
  `[[suppressions]]` block to `sentinel.toml` (idempotent, `--reason`
  supported, 6+ char prefix matching)
- `sentinel rules` now also lists custom rules from `./sentinel.toml`
- GitHub Actions rules: SEC041 `${{ github.event.* }}` / `github.head_ref`
  script injection inside `run:` steps (inline + block scalars; `if:` /
  `env:` contexts stay unflagged per GitHub's own hardening guide) and
  SEC042 `permissions: write-all`
- Container/IaC rules: SEC070 untagged `FROM` (stage-aware — named-stage
  re-entry and `${ARG}` templates are not flagged), SEC071 `:latest`,
  SEC072 secrets baked into `ENV`/`ARG`, SEC073 `privileged: true` /
  `docker.sock`, SEC074 Dockerfile present but no `.dockerignore`
- SEC034 (remote script piped to shell) now also covers Dockerfiles
- Console findings and JSON reports carry a stable 12-char finding id
- CI: test job runs on ubuntu **and** windows
- CONTRIBUTING.md — rule conventions, ID allocation, gates

### Changed
- `allow_secrets` filtering now applies only to secret findings — SAST and
  custom-rule hits are managed via suppressions / `sentinel allow`
- Dockerfile / Dockerfile.* are discovered and scanned like any other
  source file

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

[Unreleased]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/priyanshuprajapati987/sentinel-scan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/priyanshuprajapati987/sentinel-scan/releases/tag/v0.1.0
