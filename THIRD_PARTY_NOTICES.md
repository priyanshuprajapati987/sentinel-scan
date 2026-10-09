# Third-Party Notices

## Runtime dependencies: NONE

`sentinel-scan` ships **zero third-party runtime dependencies**. The
distributed package (`pip install sentinel-scan` / the GitHub release
artifacts) contains only original MIT-licensed code and the Python standard
library (Python 3.10+).

This was a deliberate design choice (see `pyproject.toml` — the
`dependencies` list is empty). No third-party attribution files are required
in the distribution because no third-party code is distributed.

## Development / test tools (NOT distributed)

These tools are used only to develop and test the project. They are **not**
bundled into the wheel, sdist, or GitHub Action, so no notice is legally
required — listed here for full transparency:

| Tool | License | Purpose |
|------|---------|---------|
| pytest | MIT | test runner |
| pytest-timeout | MIT | CI test timeouts |
| ruff | MIT | linting / formatting |
| build / twine | MIT / Apache-2.0 | packaging / release upload |
| PyYAML | MIT | CI workflow validation (dev only) |

## Other assets

* **Contributor Covenant** text in `CODE_OF_CONDUCT.md` — CC BY 4.0,
  https://www.contributor-covenant.org
* All other files in this repository — MIT, see [LICENSE](LICENSE)

Last reviewed: 2026-10-09 (audit each release: `pip install -e .` then
check `dependencies` in pyproject.toml stays empty).
