"""Adoption commands: sentinel init, pre-commit hook, --changed-since PR mode."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from sentinel.cli import HOOK_MARKER, main
from sentinel.config import STARTER_TOML


def _git(path, *args):
    return subprocess.run(
        ["git", *args], cwd=str(path), capture_output=True, timeout=30, check=True,
        text=True, encoding="utf-8", errors="replace",
    )


def _commit_all(path, message):
    _git(path, "add", "-A")
    _git(path, "commit", "-m", message)


@pytest.fixture()
def repo(tmp_path):
    p = tmp_path / "repo"
    p.mkdir()
    _git(p, "init")
    _git(p, "config", "user.email", "test@example.com")
    _git(p, "config", "user.name", "Test")
    _git(p, "config", "commit.gpgsign", "false")
    return p


class TestInit:
    def test_writes_valid_starter_config(self, tmp_path):
        assert main(["init", str(tmp_path)]) == 0
        target = tmp_path / "sentinel.toml"
        assert target.exists()
        import tomllib
        data = tomllib.loads(target.read_text(encoding="utf-8"))
        assert data["fail_on"] == "high"
        assert data["history"] is True
        assert target.read_text(encoding="utf-8") == STARTER_TOML

    def test_refuses_existing_config(self, tmp_path):
        target = tmp_path / "sentinel.toml"
        target.write_text("# mine\n", encoding="utf-8")
        assert main(["init", str(tmp_path)]) == 2
        assert target.read_text(encoding="utf-8") == "# mine\n"

    def test_force_overwrites(self, tmp_path):
        (tmp_path / "sentinel.toml").write_text("# mine\n", encoding="utf-8")
        assert main(["init", str(tmp_path), "--force"]) == 0
        assert (tmp_path / "sentinel.toml").read_text(encoding="utf-8") == STARTER_TOML

    def test_missing_directory_errors(self, tmp_path):
        assert main(["init", str(tmp_path / "nope")]) == 2


class TestHooks:
    def test_install_writes_gate_hook(self, repo):
        assert main(["install-hook", str(repo)]) == 0
        hook = repo / ".git" / "hooks" / "pre-commit"
        text = hook.read_text(encoding="utf-8")
        assert HOOK_MARKER in text
        assert "sentinel scan --staged" in text
        assert text.startswith("#!/bin/sh")

    def test_install_is_idempotent(self, repo):
        assert main(["install-hook", str(repo)]) == 0
        assert main(["install-hook", str(repo)]) == 0  # own marker -> replaces

    def test_install_refuses_foreign_hook(self, repo):
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        assert main(["install-hook", str(repo)]) == 2
        assert "custom" in hook.read_text(encoding="utf-8")

    def test_install_force_overwrites_foreign_hook(self, repo):
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        assert main(["install-hook", str(repo), "--force"]) == 0
        assert HOOK_MARKER in hook.read_text(encoding="utf-8")

    def test_uninstall_removes_own_hook(self, repo):
        main(["install-hook", str(repo)])
        assert main(["uninstall-hook", str(repo)]) == 0
        assert not (repo / ".git" / "hooks" / "pre-commit").exists()

    def test_uninstall_absent_is_noop(self, repo, capsys):
        assert main(["uninstall-hook", str(repo)]) == 0
        assert "no pre-commit hook" in capsys.readouterr().out

    def test_uninstall_refuses_foreign_hook(self, repo):
        hook = repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho custom\n", encoding="utf-8")
        assert main(["uninstall-hook", str(repo)]) == 2
        assert hook.exists()

    def test_install_not_a_repo(self, tmp_path):
        assert main(["install-hook", str(tmp_path)]) == 2


class TestChangedSince:
    def _scan(self, repo, ref):
        out = repo.parent / "report.json"
        code = main([
            "scan", str(repo), "--changed-since", ref,
            "--no-history", "--no-deps", "-f", "json", "-o", str(out), "-q",
        ])
        data = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
        return code, data or {"findings": []}

    def test_only_changed_files_scanned(self, repo):
        (repo / "old.py").write_text('password = "oldsecretvalue99"\n', encoding="utf-8")
        (repo / "clean.py").write_text("print('hello')\n", encoding="utf-8")
        _commit_all(repo, "base")
        base = _git(repo, "rev-parse", "HEAD").stdout.strip()

        # committed change: eval lands in clean.py
        (repo / "clean.py").write_text("print('hello')\nresult = eval(user_input)\n",
                                       encoding="utf-8")
        # untracked new file: secret
        (repo / "new.py").write_text('password = "brandnewsecret42"\n', encoding="utf-8")
        _commit_all(repo, "change")  # commits BOTH (new.py gets added too)
        # keep one dirty-untracked file as well
        (repo / "dirty.py").write_text('api_key = "dirtysecretvalue88"\n', encoding="utf-8")

        code, data = self._scan(repo, base)
        paths = [f["path"].replace("\\", "/") for f in data["findings"]]
        ids = [(f["rule_id"], f["path"].replace("\\", "/")) for f in data["findings"]]

        assert any("clean.py" in p for p in paths), "changed file must be scanned"
        assert any(rid == "SEC020" and "clean.py" in p for rid, p in ids)
        assert any(rid == "SEC014" and "new.py" in p for rid, p in ids)
        assert any(rid == "SEC014" and "dirty.py" in p for rid, p in ids), \
            "untracked files count as changed"
        assert not any("old.py" in p for p in paths), "unchanged base file must be skipped"
        assert code == 1, "HIGH findings gate exit must be 1"

    def test_no_changes_means_no_findings(self, repo):
        (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
        _commit_all(repo, "base")
        base = _git(repo, "rev-parse", "HEAD").stdout.strip()
        code, data = self._scan(repo, base)
        assert data["findings"] == []
        assert code == 0

    def test_bad_ref_exits_2(self, repo):
        (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
        _commit_all(repo, "base")
        out = repo.parent / "r.json"
        code = main(["scan", str(repo), "--changed-since", "no-such-ref",
                     "--no-history", "--no-deps", "-f", "json", "-o", str(out), "-q"])
        assert code == 2

    def test_conflicts_with_staged(self, repo):
        code = main(["scan", str(repo), "--changed-since", "HEAD", "--staged"])
        assert code == 2


def test_python_dash_m_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel", "--version"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=60, check=False,
    )
    assert proc.returncode == 0
    assert "sentinel" in proc.stdout
