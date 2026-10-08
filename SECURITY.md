# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |
| < 0.1 | ❌ (no releases) |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

This project is a security scanner — a bug in its detection logic can create
false confidence, which is treated as a security issue. Report privately via
**GitHub Security Advisories**:

https://github.com/priyanshuprajapati987/sentinel-scan/security/advisories/new

Include:

1. What rule/feature is affected (rule id, CLI flag, report format)
2. A minimal reproduction (file + content, or command line)
3. Impact — false negative (missed finding) or false positive (bad gate)?
4. Suggested fix, if you have one

You will get an acknowledgment within 7 days; fixes for confirmed issues ship
in a patch release with credit (unless you prefer anonymity).

## Scope

In scope: detection bypasses, incorrect redaction (evidence leaking a live
secret), command injection in CLI arguments, path traversal in report writing,
hook-suppression bypasses.

Out of scope: findings in *your* codebase (that is the tool working), CVEs in
optional third-party audit tools (pip-audit / npm audit).
