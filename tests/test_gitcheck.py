"""Git hygiene + history scanning against real temporary repositories."""

import subprocess

import pytest

from sentinel.models import Severity
from sentinel.rules import container, gitcheck


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

    def test_history_honors_allow_values(self, repo):
        key = "AKIA" + "Z" * 16
        (repo / "conf.py").write_text(f'ACCESS = "{key}"\n', encoding="utf-8")
        _commit_all(repo, "add config")
        assert any(f.rule_id == "SEC055" for f in gitcheck.scan_history(repo))
        allowed = gitcheck.scan_history(repo, allow=[key.lower()])
        assert not any(f.rule_id == "SEC055" for f in allowed)


class _FailedProc:
    """Mock subprocess result for a failing git command."""

    returncode = 128
    stdout = b""
    stderr = b"fatal: boom"


def _break_git(monkeypatch, exc=None):
    if exc is not None:
        def _boom(*a, **k):
            raise exc
        monkeypatch.setattr(gitcheck.subprocess, "run", _boom)
    else:
        monkeypatch.setattr(gitcheck.subprocess, "run", lambda *a, **k: _FailedProc())


class TestGitFailureSignal:
    """#2/#13: git failure = visible GIT-SKIP note, never silently 'clean'."""

    def test_hygiene_failure_emits_skip_not_clean(self, repo, monkeypatch):
        _break_git(monkeypatch)
        findings = gitcheck.scan_hygiene(repo)
        skips = [f for f in findings if f.rule_id == "GIT-SKIP"]
        assert skips, "git failure must be visible, not an empty (clean) result"
        assert all(f.severity is Severity.INFO for f in skips)  # never gates exit
        assert all(f.scanner == "git" for f in skips)
        # no security verdicts can be reached without git output
        assert not any(f.rule_id in ("SEC050", "SEC051", "SEC052", "SEC053", "SEC054")
                       for f in findings)
        assert any("ls-files" in f.message for f in skips)
        assert any("remote -v" in f.message for f in skips)

    def test_hygiene_failure_lists_all_skipped_checks(self, repo, monkeypatch):
        _break_git(monkeypatch)
        messages = " | ".join(f.message for f in gitcheck.scan_hygiene(repo))
        assert "tracked-secret (SEC050/051)" in messages
        assert "blob-size (SEC054)" in messages
        assert "env-coverage (SEC053)" in messages
        assert "credentialled-remote check (SEC052)" in messages

    def test_history_failure_emits_skip_signal(self, repo, monkeypatch):
        _break_git(monkeypatch)
        findings = gitcheck.scan_history(repo)
        assert [f.rule_id for f in findings] == ["GIT-SKIP"]
        assert findings[0].severity is Severity.INFO
        assert "not clean" in findings[0].message
        assert "git-history secret scan" in findings[0].message

    def test_scan_dispatch_failure_emits_single_skip_signal(self, repo, monkeypatch):
        _break_git(monkeypatch)
        findings = gitcheck.scan(repo, history=True)
        assert [f.rule_id for f in findings] == ["GIT-SKIP"]

    def test_git_binary_missing_oserror_signals(self, repo, monkeypatch):
        _break_git(monkeypatch, exc=FileNotFoundError("git"))
        assert [f.rule_id for f in gitcheck.scan(repo)] == ["GIT-SKIP"]

    def test_git_timeout_oserror_signals(self, repo, monkeypatch):
        _break_git(monkeypatch, exc=subprocess.TimeoutExpired("git", 30))
        assert [f.rule_id for f in gitcheck.scan(repo)] == ["GIT-SKIP"]

    def test_working_git_empty_output_is_clean_not_skip(self, repo):
        # sanity: real git, no findings -> [] ("" means "ran clean", not None)
        assert gitcheck.scan_hygiene(repo) == []
        assert not any(f.rule_id == "GIT-SKIP" for f in gitcheck.scan(repo))


class TestEnvFileDetection:
    """#8: `.env` / `.env.<variant>` are SEC050; lookalikes are not."""

    def test_tracked_env_production_flagged(self, repo):
        (repo / ".env.production").write_text("A=1\n", encoding="utf-8")
        _git(repo, "add", ".env.production")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC050" in ids
        hit = [f for f in gitcheck.scan_hygiene(repo) if f.rule_id == "SEC050"][0]
        assert ".env.production" in hit.message

    def test_tracked_env_staging_flagged(self, repo):
        (repo / ".env.staging").write_text("A=1\n", encoding="utf-8")
        _git(repo, "add", ".env.staging")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC050" in ids

    def test_environment_file_not_treated_as_env(self, repo):
        (repo / ".environment").write_text("A=1\n", encoding="utf-8")
        _git(repo, "add", "-A")
        ids = [f.rule_id for f in gitcheck.scan_hygiene(repo)]
        assert "SEC050" not in ids


class TestGitignoreCoverage:
    """#9: env-covering pattern regex — coverage vs false positives."""

    @staticmethod
    def _flagged_ids(repo):
        return [f.rule_id for f in gitcheck.scan_hygiene(repo)]

    def test_gitignore_env_example_only_still_flagged(self, repo):
        # old regex anchored at line-start matched ".env.example" -> FN
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text(".env.example\n", encoding="utf-8")
        _git(repo, "add", "-A")
        assert "SEC053" in self._flagged_ids(repo)

    def test_missing_gitignore_with_tracked_env_flagged(self, repo):
        # extension of SEC053: absent .gitignore = zero coverage, not "skip"
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        _git(repo, "add", "-A")
        ids = self._flagged_ids(repo)
        assert "SEC053" in ids and "SEC050" in ids

    def test_root_anchored_env_pattern_counts_as_coverage(self, repo):
        # "/.env" anchored at repo root — old regex missed it (FP)
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text("/.env\n", encoding="utf-8")
        _git(repo, "add", "-f", ".env")
        _git(repo, "add", ".gitignore")
        assert "SEC053" not in self._flagged_ids(repo)

    def test_env_glob_pattern_counts_as_coverage(self, repo):
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text("**/.env*\n", encoding="utf-8")
        _git(repo, "add", "-f", ".env")
        _git(repo, "add", ".gitignore")
        assert "SEC053" not in self._flagged_ids(repo)

    def test_local_only_pattern_does_not_cover_bare_env(self, repo):
        # ".env.local" covers a DIFFERENT file than tracked ".env"
        (repo / ".env").write_text("A=1\n", encoding="utf-8")
        (repo / ".gitignore").write_text(".env.local\n", encoding="utf-8")
        _git(repo, "add", "-A")
        assert "SEC053" in self._flagged_ids(repo)


class TestDeletedFileHistory:
    """#10: deletion hunks attribute content to the OLD path."""

    @staticmethod
    def _write_secret(repo, path, secret):
        p = repo / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f'TOKEN="{secret}"\n', encoding="utf-8")

    def test_deleted_excluded_file_not_reported(self, repo):
        secret = "sk-live-" + "a" * 35
        self._write_secret(repo, "vendor/leak.env", secret)
        _commit_all(repo, "add secret")
        (repo / "vendor" / "leak.env").unlink()
        _commit_all(repo, "delete secret")
        excluded = gitcheck.scan_history(repo, exclude=lambda p: p.startswith("vendor/"))
        assert not any(f.rule_id == "SEC055" for f in excluded)
        # without the predicate the deletion still surfaces it
        assert any(f.rule_id == "SEC055" for f in gitcheck.scan_history(repo))

    def test_deletion_only_window_excluded_via_old_path(self, repo):
        """max_commits=1 shows ONLY the delete commit. The old-path attribution
        must keep the exclude predicate effective (old code set path=None here
        -> exclude silently skipped -> excluded paths leaked a finding)."""
        secret = "sk-live-" + "b" * 35
        self._write_secret(repo, "vendor/leak.env", secret)
        _commit_all(repo, "add secret")
        (repo / "vendor" / "leak.env").unlink()
        _commit_all(repo, "delete secret")
        excluded = gitcheck.scan_history(
            repo, max_commits=1, exclude=lambda p: p.startswith("vendor/"))
        assert not any(f.rule_id == "SEC055" for f in excluded)
        # ...while without the predicate the deleted content is still scanned
        included = gitcheck.scan_history(repo, max_commits=1)
        assert any(f.rule_id == "SEC055" for f in included)

    def test_deletion_dedupes_across_add_and_delete(self, repo):
        """Same secret in add + delete commits -> one finding (dedupe)."""
        secret = "sk-live-" + "c" * 35
        self._write_secret(repo, "temp.env", secret)
        _commit_all(repo, "add temp")
        (repo / "temp.env").unlink()
        _commit_all(repo, "remove temp")
        hits = [f for f in gitcheck.scan_history(repo) if f.rule_id == "SEC055"]
        assert len(hits) == 1
        assert hits[0].path == "<git-history>"


class TestContainerRepoNaming:
    """SEC074 naming fix (#11). Lives in this file only because test-file
    ownership for this task is limited to test_deps/test_gitcheck."""

    def test_dockerfiles_md_not_flagged(self, tmp_path):
        (tmp_path / "dockerfiles.md").write_text("notes\n", encoding="utf-8")
        assert container.scan_repo(tmp_path) == []

    def test_dockerfiles_plain_name_not_flagged(self, tmp_path):
        (tmp_path / "dockerfiles").write_text("notes\n", encoding="utf-8")
        assert container.scan_repo(tmp_path) == []

    def test_plain_dockerfile_flagged(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
        hits = container.scan_repo(tmp_path)
        assert [f.rule_id for f in hits] == ["SEC074"]

    def test_lowercase_dockerfile_flagged(self, tmp_path):
        (tmp_path / "dockerfile").write_text("FROM alpine\n", encoding="utf-8")
        assert [f.rule_id for f in container.scan_repo(tmp_path)] == ["SEC074"]

    def test_dockerfile_variant_flagged(self, tmp_path):
        (tmp_path / "Dockerfile.dev").write_text("FROM alpine\n", encoding="utf-8")
        assert [f.rule_id for f in container.scan_repo(tmp_path)] == ["SEC074"]

    def test_dockerignore_present_skips(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine\n", encoding="utf-8")
        (tmp_path / ".dockerignore").write_text(".git\n", encoding="utf-8")
        assert container.scan_repo(tmp_path) == []
