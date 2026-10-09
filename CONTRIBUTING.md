# Contributing to Sentinel Scan

Thanks for helping make Sentinel better. The bar is deliberately low on
process and high on evidence: every rule must be testable, every fix must
keep the self-scan green.

## Setup

```bash
git clone https://github.com/priyanshuprajapati987/sentinel-scan.git
cd sentinel-scan
pip install -e .
pip install pytest ruff
```

## Gates (all must pass before a PR)

```bash
ruff check .          # lint — zero errors
python -m pytest      # full suite
sentinel scan . --fail-on high    # self-scan must stay clean (exit 0)
```

The self-scan is the honesty gate: if your new rule flags this repository,
either the rule is too broad or this repo has a real problem — fix both
sides before shipping.

## Adding a built-in rule

1. **Pick the right bucket** (IDs are allocated per area — never reuse):

   | Range | Area | Module |
   |---|---|---|
   | SEC001–SEC015 | Secrets | `sentinel/rules/secrets.py` |
   | SEC020–SEC049 | Code / SAST / Actions | `sentinel/rules/code.py` |
   | SEC050–SEC055 | Git hygiene & history | `sentinel/rules/gitcheck.py` |
   | SEC060–SEC069 | Dependencies | `sentinel/rules/deps.py` |
   | SEC070–SEC079 | Container / IaC | `sentinel/rules/code.py` (DOCKER) + `container.py` |

2. **Line rule or stateful scan?** A line rule (`_c(...)`) fires on one
   unambiguous line — prefer it. Only write a stateful scanner
   (`_scan_actions`, `_scan_dockerfile` pattern) when the signal needs
   cross-line context; keep it deterministic and free of I/O.

3. **Every rule needs** a stable id, title, severity, CWE tag, a concrete
   `fix` string, and honest `confidence` (`medium` when false positives
   are plausible — they are suppressible).

4. **Register it** in `CODE_RULES` / `FILE_RULES` (or the matching module
   list) so it is scanned, and make sure `sentinel rules` lists it —
   line/file rules are picked up automatically; stateful scanners need an
   entry in `all_rules()`.

5. **Test it in `tests/`** — one file per area is fine. Cover:
   - the positive case (rule fires on the bad line),
   - at least two negatives (near-miss patterns that must NOT fire),
   - extension scoping where relevant.

6. **Secrets rules only**: evidence must stay redacted
   (`redact(secret_rules.VALUE_RULES, ...)`) — never let a live credential
   reach a report.

## Custom rules vs built-ins

Team-specific patterns (internal tokens, company conventions) belong in
`[[custom_rules]]` in `sentinel.toml`, not in the built-in catalog. If a
rule is broadly useful and vendor-standard (AWS/OpenAI/GitHub key formats,
documented CVEs, official hardening guides), a built-in is welcome.

## Style

- stdlib only in the `sentinel` package — zero runtime dependencies.
- Regexes: `re.IGNORECASE` by default via `_c()`; use `negate=` for known
  safe patterns (e.g. `usedforsecurity=False`) instead of complicating the
  main pattern.
- Windows + Linux: tests run on both in CI — no POSIX-only assumptions in
  scanning code (hooks may assume a POSIX shell; that is documented).

## Releases

1. Bump `project.version` in `pyproject.toml` and `sentinel.__version__`.
2. Add a `## [x.y.z]` section to `CHANGELOG.md` with the compare link.
3. `python -m build && twine check dist/*`
4. Tag `vX.Y.Z`, push, and attach `dist/*` to the GitHub release.
