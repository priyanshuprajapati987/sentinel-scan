"""Phase 4 (v0.2.0) — custom rules, container/Actions rules, `sentinel allow`."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from sentinel import engine
from sentinel.config import Config, _parse_custom_rule
from sentinel.models import Finding, Severity
from sentinel.rules import code, container
from sentinel.rules import custom as custom_mod

# --------------------------------------------------------------------------- #
# fingerprint                                                                  #
# --------------------------------------------------------------------------- #


class TestFingerprint:
    def _finding(self, **kw) -> Finding:
        base = dict(rule_id="SEC020", title="t", severity=Severity.HIGH,
                    message="eval() on dynamic input: eval(x)", path="app.py", line=3)
        base.update(kw)
        return Finding(**base)

    def test_stable_12_hex(self):
        fp = self._finding().fingerprint()
        assert fp == self._finding().fingerprint()
        assert len(fp) == 12
        assert all(c in "0123456789abcdef" for c in fp)

    def test_same_key_same_fingerprint(self):
        a, b = self._finding(), self._finding(evidence="different")
        assert a.key() == b.key()
        assert a.fingerprint() == b.fingerprint()

    def test_different_finding_different_fingerprint(self):
        a = self._finding()
        assert a.fingerprint() != self._finding(line=4).fingerprint()
        assert a.fingerprint() != self._finding(rule_id="SEC021").fingerprint()
        assert a.fingerprint() != self._finding(path="other.py").fingerprint()

    def test_to_dict_exposes_id(self):
        f = self._finding()
        assert f.to_dict()["id"] == f.fingerprint()


# --------------------------------------------------------------------------- #
# custom rules                                                                 #
# --------------------------------------------------------------------------- #


class TestCustomRuleConfig:
    def test_valid_rule_parsed(self):
        cfg = Config()
        _parse_custom_rule(cfg, {
            "id": "CORP001", "title": "corp token", "severity": "high",
            "pattern": "corp_[A-Za-z0-9]{40}",
            "extensions": [".py", "env"], "fix": "rotate", "cwe": "CWE-798",
        })
        assert len(cfg.custom_rules) == 1
        r = cfg.custom_rules[0]
        assert r.id == "CORP001"
        assert r.severity == Severity.HIGH
        assert r.extensions == (".py", ".env")  # normalized with dot
        assert r.regex.search("corp_" + "A" * 40)

    def test_invalid_regex_becomes_note_not_crash(self):
        cfg = Config()
        _parse_custom_rule(cfg, {"id": "BAD", "pattern": "([unclosed"})
        assert cfg.custom_rules == []
        assert any("invalid pattern" in n for n in cfg.notes)

    def test_missing_id_skipped_with_note(self):
        cfg = Config()
        _parse_custom_rule(cfg, {"pattern": "x"})
        assert cfg.custom_rules == []
        assert any("without an id" in n for n in cfg.notes)

    def test_unknown_severity_defaults_to_medium(self):
        cfg = Config()
        _parse_custom_rule(cfg, {"id": "X", "pattern": "x", "severity": "bogus"})
        assert cfg.custom_rules[0].severity == Severity.MEDIUM
        assert any("unknown severity" in n for n in cfg.notes)

    def test_non_table_entry_skipped(self):
        cfg = Config()
        _parse_custom_rule(cfg, "not-a-table")
        assert cfg.custom_rules == []
        assert any("must be a table" in n for n in cfg.notes)


class TestCustomRuleScan:
    def _rule(self, **kw) -> object:
        cfg = Config()
        entry = {"id": "CORP001", "title": "corp token", "severity": "high",
                 "pattern": "corp_[A-Za-z0-9]{40}"}
        entry.update(kw)
        _parse_custom_rule(cfg, entry)
        return cfg.custom_rules[0]

    def test_hit_tagged_custom(self):
        r = self._rule()
        line = "token = 'corp_" + "A" * 40 + "'\n"
        findings = custom_mod.scan_text("app.py", line, [r])
        assert len(findings) == 1
        assert findings[0].scanner == "custom"
        assert findings[0].rule_id == "CORP001"
        assert findings[0].line == 1

    def test_extension_scoping(self):
        r = self._rule(extensions=[".py"])
        assert custom_mod.scan_text("app.js", "corp_" + "B" * 40, [r]) == []
        assert len(custom_mod.scan_text("app.py", "corp_" + "B" * 40, [r])) == 1

    def test_no_rules_returns_empty(self):
        assert custom_mod.scan_text("app.py", "anything", []) == []

    def test_all_rules_catalog(self):
        r = self._rule()
        assert custom_mod.all_rules([r]) == [("CORP001", "corp token", Severity.HIGH)]

    def test_engine_wires_custom_rules(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 'corp_" + "C" * 40 + "'\n", encoding="utf-8")
        cfg = Config()
        _parse_custom_rule(cfg, {"id": "CORP001", "pattern": "corp_[A-Za-z0-9]{40}"})
        result = engine.scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        hits = [f for f in result.findings if f.rule_id == "CORP001"]
        assert len(hits) == 1
        assert hits[0].scanner == "custom"


# --------------------------------------------------------------------------- #
# GitHub Actions rules (SEC041 / SEC042)                                       #
# --------------------------------------------------------------------------- #


class TestActionsRules:
    WFLOW = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        '      - run: echo "${{ github.event.issue.title }}"\n'
        "      - name: block\n"
        "        run: |\n"
        "          echo start\n"
        "          echo ${{ github.head_ref }}\n"
        "          echo done\n"
        "      - if: ${{ github.event.action }}\n"
        "        run: echo safe\n"
        "      - name: env-pass\n"
        "        env:\n"
        "          TITLE: ${{ github.event.issue.title }}\n"
        "        run: echo \"$TITLE\"\n"
    )

    def test_inline_injection_flagged(self):
        hits = code._scan_actions("ci.yml", self.WFLOW)
        lines = [f.line for f in hits if f.rule_id == "SEC041"]
        assert 4 in lines

    def test_block_injection_flagged(self):
        hits = code._scan_actions("ci.yml", self.WFLOW)
        lines = [f.line for f in hits if f.rule_id == "SEC041"]
        assert 8 in lines

    def test_if_and_env_contexts_not_flagged(self):
        hits = code._scan_actions("ci.yml", self.WFLOW)
        lines = [f.line for f in hits if f.rule_id == "SEC041"]
        assert 10 not in lines  # if: is an expression position
        assert 14 not in lines  # env: + quoted $VAR is GitHub's safe pattern
        assert len(hits) == 2

    def test_scan_text_invokes_actions_scan_for_yaml(self):
        findings = code.scan_text("workflows/ci.yml", self.WFLOW)
        assert any(f.rule_id == "SEC041" for f in findings)

    def test_write_all_flagged(self):
        text = "jobs:\n  x:\n    permissions: write-all\n    steps: []\n"
        findings = code.scan_text("w.yml", text)
        assert any(f.rule_id == "SEC042" for f in findings)

    def test_least_privilege_map_not_flagged(self):
        text = "permissions:\n  contents: read\n  issues: write\n"
        assert code.scan_text("w.yml", text) == []


# --------------------------------------------------------------------------- #
# Dockerfile rules (SEC070–073)                                                #
# --------------------------------------------------------------------------- #


class TestDockerRules:
    def test_ext_of_dockerfile_family(self):
        assert code._ext_of("Dockerfile") == ".dockerfile"
        assert code._ext_of("dockerfile") == ".dockerfile"
        assert code._ext_of("Dockerfile.dev") == ".dockerfile"
        assert code._ext_of("dockerfile.prod") == ".dockerfile"
        assert code._ext_of(".env") == ".env"
        assert code._ext_of("app.py") == ".py"

    def test_untagged_from_flagged(self):
        findings = code.scan_text("Dockerfile", "FROM alpine\n")
        assert [f.rule_id for f in findings] == ["SEC070"]

    def test_tagged_and_digest_from_skipped(self):
        text = "FROM node:20-slim\nFROM alpine@sha256:" + "0" * 64 + "\n"
        assert [f for f in code.scan_text("Dockerfile", text) if f.rule_id == "SEC070"] == []

    def test_stage_ref_not_flagged(self):
        text = "FROM golang:1.22 AS build\nFROM build\n"
        assert [f for f in code.scan_text("Dockerfile", text) if f.rule_id == "SEC070"] == []

    def test_untagged_pull_with_as_still_flagged(self):
        findings = code.scan_text("Dockerfile", "FROM ubuntu AS builder\n")
        assert [f.rule_id for f in findings] == ["SEC070"]

    def test_arg_template_skipped(self):
        assert code.scan_text("Dockerfile", "FROM ${BASE_IMAGE}\n") == []

    def test_latest_tag_flagged(self):
        findings = code.scan_text("Dockerfile", "FROM alpine:latest\n")
        assert [f.rule_id for f in findings] == ["SEC071"]

    def test_secret_in_env_and_arg(self):
        text = "ENV API_KEY=abc123\nARG GITHUB_TOKEN=tok\n"
        rids = [f.rule_id for f in code.scan_text("Dockerfile", text)]
        assert rids == ["SEC072", "SEC072"]

    def test_env_path_not_flagged(self):
        assert code.scan_text("Dockerfile", "ENV PATH=/usr/bin\n") == []

    def test_privileged_and_docker_sock(self):
        yml = "services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
        rids = [f.rule_id for f in code.scan_text("docker-compose.yml", yml)]
        assert rids.count("SEC073") == 2

    def test_curl_pipe_sh_in_dockerfile(self):
        text = "FROM alpine:3.19\nRUN curl -fsSL https://x.example/i.sh | sh\n"
        assert any(f.rule_id == "SEC034" for f in code.scan_text("Dockerfile", text))


# --------------------------------------------------------------------------- #
# container repo checks (SEC074)                                               #
# --------------------------------------------------------------------------- #


class TestContainerRepo:
    def test_dockerfile_without_ignore_flagged(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        findings = container.scan_repo(tmp_path)
        assert [f.rule_id for f in findings] == ["SEC074"]
        assert findings[0].path == ".dockerignore"

    def test_ignore_present_ok(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        (tmp_path / ".dockerignore").write_text(".git\n", encoding="utf-8")
        assert container.scan_repo(tmp_path) == []

    def test_no_dockerfile_ok(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
        assert container.scan_repo(tmp_path) == []

    def test_subdir_dockerfile_counts(self, tmp_path: Path):
        sub = tmp_path / "services" / "api"
        sub.mkdir(parents=True)
        (sub / "Dockerfile").write_text("FROM python:3.12-slim\n", encoding="utf-8")
        findings = container.scan_repo(tmp_path)
        assert [f.rule_id for f in findings] == ["SEC074"]
        assert "services/api/Dockerfile" in findings[0].message

    def test_exclude_predicate_respected(self, tmp_path: Path):
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        findings = container.scan_repo(tmp_path, exclude=lambda rel: rel.startswith("tests/"))
        assert findings == []

    def test_engine_runs_repo_check_on_full_scan(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        result = engine.scan(tmp_path, config=Config(), run_git=False, run_deps=False)
        assert any(f.rule_id == "SEC074" for f in result.findings)

    def test_engine_skips_repo_check_for_partial_scans(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = engine.scan(tmp_path, config=Config(), run_git=False, run_deps=False,
                             only_files=["a.py"])
        assert not any(f.rule_id == "SEC074" for f in result.findings)

    def test_discover_includes_dockerfile_variants(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n", encoding="utf-8")
        (tmp_path / "Dockerfile.dev").write_text("FROM alpine:3.19\n", encoding="utf-8")
        files, _ = engine.discover(tmp_path, Config())
        names = {p.name for p in files}
        assert "Dockerfile" in names and "Dockerfile.dev" in names


# --------------------------------------------------------------------------- #
# `sentinel allow`                                                             #
# --------------------------------------------------------------------------- #


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True, check=False)


class TestAllowCommand:
    @pytest.fixture()
    def repo(self, tmp_path: Path) -> Path:
        (tmp_path / "app.py").write_text("result = eval(user_input)\n", encoding="utf-8")
        _git_init(tmp_path)
        return tmp_path

    def _scan_fp(self, root: Path) -> str:
        result = engine.scan(root, config=Config(), run_git=False, run_deps=False)
        hit = next(f for f in result.findings if f.rule_id == "SEC020")
        return hit.fingerprint()

    def test_allow_appends_suppression(self, repo: Path):
        from sentinel.cli import main
        fp = self._scan_fp(repo)
        rc = main(["allow", fp, str(repo), "--reason", "intentional eval fixture"])
        assert rc == 0
        text = (repo / "sentinel.toml").read_text(encoding="utf-8")
        assert "[[suppressions]]" in text
        assert 'rule_id = "SEC020"' in text
        assert 'path = "app.py"' in text
        assert "intentional eval fixture" in text

    def test_suppression_takes_effect_on_next_scan(self, repo: Path):
        from sentinel.cli import main
        fp = self._scan_fp(repo)
        assert main(["allow", fp, str(repo)]) == 0
        result = engine.scan(repo, config=engine.load_config(repo),
                             run_git=False, run_deps=False)
        assert not any(f.rule_id == "SEC020" for f in result.findings)
        assert result.suppressed >= 1

    def test_prefix_match_is_enough(self, repo: Path):
        from sentinel.cli import main
        fp = self._scan_fp(repo)
        assert main(["allow", fp[:8], str(repo)]) == 0

    def test_too_short_fingerprint_rejected(self, repo: Path):
        from sentinel.cli import main
        assert main(["allow", "abc", str(repo)]) == 2

    def test_unknown_fingerprint_rejected(self, repo: Path):
        from sentinel.cli import main
        assert main(["allow", "deadbeef0000", str(repo)]) == 2

    def test_second_allow_is_idempotent(self, repo: Path, capsys):
        from sentinel.cli import main
        fp = self._scan_fp(repo)
        assert main(["allow", fp, str(repo)]) == 0
        rc = main(["allow", fp[:8], str(repo)])
        assert rc == 0
        assert "already allowed" in capsys.readouterr().out

    def test_default_reason_references_fingerprint(self, repo: Path):
        from sentinel.cli import main
        fp = self._scan_fp(repo)
        assert main(["allow", fp, str(repo)]) == 0
        text = (repo / "sentinel.toml").read_text(encoding="utf-8")
        assert fp in text  # traceable default reason


# --------------------------------------------------------------------------- #
# rule catalog                                                                 #
# --------------------------------------------------------------------------- #


class TestRuleCatalog:
    def test_catalog_contains_new_rules(self):
        from sentinel.cli import _catalog
        ids = {rid for rid, _, _ in _catalog()}
        for rid in ("SEC041", "SEC042", "SEC070", "SEC071", "SEC072", "SEC073", "SEC074"):
            assert rid in ids, rid

    def test_catalog_lists_custom_rules_from_cwd_config(self, tmp_path: Path, monkeypatch):
        (tmp_path / "sentinel.toml").write_text(
            '[[custom_rules]]\n'
            'id = "CORP001"\n'
            'title = "corp token"\n'
            'severity = "high"\n'
            'pattern = "corp_[A-Za-z0-9]{40}"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        from sentinel.cli import _catalog
        rows = [(rid, title, sev) for rid, title, sev in _catalog() if rid == "CORP001"]
        assert rows == [("CORP001", "corp token", Severity.HIGH)]
