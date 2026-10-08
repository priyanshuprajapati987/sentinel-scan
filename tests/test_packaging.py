"""Release/packaging invariants — version sync, hook speed, ecosystem files."""

from __future__ import annotations

from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent


class TestVersionSync:
    def test_pyproject_matches_package_version(self):
        import sentinel
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["version"] == sentinel.__version__

    def test_changelog_documents_current_version(self):
        import sentinel
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert f"## [{sentinel.__version__}]" in text

    def test_console_script_entrypoint_declared(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["scripts"]["sentinel"] == "sentinel.cli:main"


class TestHookIsFastGate:
    def test_hook_body_skips_slow_layers(self):
        from sentinel.cli import _HOOK_BODY
        assert "--staged" in _HOOK_BODY
        assert "--no-history" in _HOOK_BODY  # git log -p on every commit = slow
        assert "--no-deps" in _HOOK_BODY     # network CVE call on every commit = worse

    def test_precommit_framework_hook_file(self):
        text = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        assert "- id: sentinel" in text
        assert "language: python" in text
        assert "pass_filenames: false" in text
        assert "--staged --no-history --no-deps" in text  # same fast gate as install-hook


class TestReleaseDocs:
    def test_security_policy_exists(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        assert "security/advisories" in text  # private reporting channel

    def test_changelog_has_release_links(self):
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert "compare/v0.1.0...v0.1.1" in text

    def test_readme_badges_present(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        assert "img.shields.io/github/v/release" in text
        assert "badge/license-MIT" in text
