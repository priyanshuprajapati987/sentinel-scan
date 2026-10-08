"""Git hygiene + history scanning against real temporary repositories."""

import subprocess

import pytest

from sentinel.rules import gitcheck


def _git(path, *args):
    return subprocess.run(
        ["git", *args], cwd=str(path), capture_output=True, timeout=30, check=True,
        text=True, encoding="utf-8", errors="replace",
    )


@pytest.fixture()
def repo(tmp_path):
    p = tmp_path / "repo"
    p.mkdir()
    _git(p, "init")
    _git(p, "config", "user.email", "test@example.com")
    _git(p, "config", "user.name", "Test")
    _git(p, "config", "commit.gpgsign", "false")
    return p


def _commit_all(path, message):
    _git(path, "add", "-A")
    _git(path, "commit", "-m", message)


class TestNotARepo:
    def test_plain_dir_returns_nothing(self, tmp_path):
        assert gitcheck.scan(tmp_path) == []


class TestHygiene:
    def test_tracked_env_flagged(self, repo):
        (repo / ".env").write_text("ANY=1\n", encoding="utf-8")
        _git(repo, "add", ".env")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC050" in ids

    def test_tracked_env_ignored_when_ignored(self, repo):
        (repo / ".env").write_text("ANY=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text(".env*\n", encoding="utf-8")
        _git(repo, "add", "-A")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC050" not in ids  # never tracked
        assert "SEC053" not in ids  # ignore rule present

    def test_gitignore_gap_flagged(self, repo):
        (repo / ".env").write_text("ANY=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        _git(repo, "add", "-A")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC053" in ids

    def test_tracked_private_key_flagged(self, repo):
        (repo / "server.pem").write_text("fake key material\n", encoding="utf-8")
        _git(repo, "add", "server.pem")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC051" in ids

    def test_credentialled_remote_flagged_and_redacted(self, repo):
        _git(repo, "remote", "add", "origin", "https://alice:hunter2secret@github.com/x/y.git")
        hits = [f for f in gitcheck.scan_hygiene(repo) if f.rule_id == "SEC052"]
        assert hits, "credentialled remote must be flagged"
        assert "hunter2secret" not in hits[0].evidence
        assert "alice" in hits[0].evidence  # username ok to show, password redacted

    def test_clean_remote_not_flagged(self, repo):
        _git(repo, "remote", "add", "origin", "https://github.com/x/y.git")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC052" not in ids

    def test_oversized_file_flagged(self, repo, monkeypatch):
        (repo / "data.bin").write_bytes(b"x" * 1024)
        _git(repo, "add", "data.bin")
        monkeypatch.setattr(gitcheck, "_MAX_FILE_BYTES", 100)
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC054" in ids


class TestHistory:
    def test_secret_committed_then_deleted_still_found(self, repo):
        key = "AKIA" + "Z" * 16
        (repo / "conf.py").write_text(f'ACCESS = "{key}"\n', encoding="utf-8")
        _commit_all(repo, "add config")
        (repo / "conf.py").write_text("ACCESS = None\n", encoding="utf-8")
        _commit_all(repo, "remove secret")

        findings = gitcheck.scan_history(repo)
        assert findings, "history must expose the deleted secret"
        assert all(f.rule_id == "SEC055" for f in findings)
        assert all(key not in f.evidence for f in findings), "evidence must be redacted"
        assert any("SEC001" in f.evidence for f in findings)

    def test_clean_history_no_findings(self, repo):
        (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
        _commit_all(repo, "init")
        assert gitcheck.scan_history(repo) == []

    def test_scan_combines_hygiene_and_history(self, repo):
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        _commit_all(repo, "env")
        ids = {f.rule_id for f in gitcheck.scan(repo, history=True)}
        assert "SEC050" in ids

    def test_history_exclude_predicate_skips_path(self, repo):
        secret = "sk-live-" + "a" * 35
        (repo / "vendor").mkdir()
        (repo / "vendor" / "leak.env").write_text(f'TOKEN="{secret}"\n', encoding="utf-8")
        _commit_all(repo, "vendor fixture")
        excluded = gitcheck.scan_history(repo, exclude=lambda p: p.startswith("vendor/"))
        assert not any(f.rule_id == "SEC055" for f in excluded)
        included = gitcheck.scan_history(repo)  # no predicate -> still reported
        assert any(f.rule_id == "SEC055" for f in included)

    def test_gitcheck_source_does_not_self_match_in_history(self, repo):
        """Regression: gitcheck.py's own evidence-format strings must not
        trip SEC013/SEC055 when the rule file is committed (f-string split)."""
        import pathlib
        src = pathlib.Path(gitcheck.__file__).read_text(encoding="utf-8")
        (repo / "gitcheck_copy.py").write_text(src + "\n", encoding="utf-8")
        _commit_all(repo, "copy rule source")
        hits = [f for f in gitcheck.scan_history(repo)
                if f.rule_id in ("SEC013", "SEC055")]
        assert hits == []

    def test_scan_history_empty_on_no_commits(self, tmp_path):
        fresh = tmp_path / "fresh"
        fresh.mkdir()
        _git(fresh, "init")
        assert gitcheck.scan_history(fresh) == []
