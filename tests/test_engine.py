"""Engine: discovery, config, suppressions, baseline, staged mode."""

import json
import subprocess

import pytest

from sentinel.config import Config, Suppression, load_config
from sentinel.engine import discover, load_baseline, scan, write_baseline
from sentinel.models import Finding, Severity
from sentinel.score import counts, score


def _ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


class TestDiscovery:
    def test_excludes_default_dirs(self, tmp_path):
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "evil.js").write_text("eval(x)\n", encoding="utf-8")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "ok.py").write_text("print(1)\n", encoding="utf-8")
        files, _ = discover(tmp_path, Config())
        names = [f.name for f in files]
        assert "ok.py" in names
        assert "evil.js" not in names

    def test_glob_exclude(self, tmp_path):
        (tmp_path / "vendor").mkdir()
        (tmp_path / "vendor" / "a.js").write_text("eval(x)\n", encoding="utf-8")
        (tmp_path / "app.js").write_text("console.log(1)\n", encoding="utf-8")
        files, _ = discover(tmp_path, Config(excludes=["vendor/**"]))
        assert [f.name for f in files] == ["app.js"]

    def test_only_scanned_extensions(self, tmp_path):
        (tmp_path / "notes.xyz").write_text("eval(x)\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
        files, _ = discover(tmp_path, Config())
        assert [f.name for f in files] == ["a.py"]


class TestScan:
    def test_vulnerable_file_detected(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        s, _g = score(result.findings)
        assert s < 100

    def test_clean_project_scores_100(self, tmp_path):
        (tmp_path / "a.py").write_text("import json\nprint(json.dumps({}))\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert score(result.findings) == (100, "A")

    def test_severity_counts(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(x)\nos.system(cmd)\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        c = counts(result.findings)
        assert c["HIGH"] >= 2
        assert c["CRITICAL"] == 0

    def test_duplicate_on_one_line_deduped(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(x); eval(x)\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert _ids(result).count("SEC020") == 1

    def test_extra_excludes(self, tmp_path):
        (tmp_path / "gen").mkdir()
        (tmp_path / "gen" / "a.py").write_text("eval(x)\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False, extra_excludes=["gen/**"])
        assert "SEC020" not in _ids(result)


class TestSuppression:
    @staticmethod
    def _vuln(tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")

    def test_rule_id_suppression(self, tmp_path):
        self._vuln(tmp_path)
        cfg = Config(suppressions=[Suppression(rule_id="SEC020")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert "SEC020" not in _ids(result)
        assert result.suppressed == 1

    def test_path_suppression(self, tmp_path):
        self._vuln(tmp_path)
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", path="a.py")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert result.suppressed == 1

    def test_wrong_path_not_suppressed(self, tmp_path):
        self._vuln(tmp_path)
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", path="other.py")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        assert result.suppressed == 0

    def test_expired_suppression_ignored(self, tmp_path):
        self._vuln(tmp_path)
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", expires="2000-01-01")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        assert result.suppressed == 0

    def test_future_suppression_active(self, tmp_path):
        self._vuln(tmp_path)
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", expires="2099-01-01")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert result.suppressed == 1


class TestAllowSecrets:
    def test_allow_substring_filters_secret_evidence(self, tmp_path):
        (tmp_path / "a.py").write_text('password = "kR8mZq2vXw9TfLp0BnY3"\n', encoding="utf-8")
        raw = scan(tmp_path, run_git=False, run_deps=False)
        assert any(f.scanner == "secrets" for f in raw.findings)

        cfg = Config(allow_secrets=["kR8m"])
        filtered = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert not any(f.scanner == "secrets" for f in filtered.findings)


class TestBaseline:
    def test_baseline_filters_known_findings(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
        first = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" in _ids(first)

        bl = tmp_path / "baseline.json"
        write_baseline(bl, first.findings, tmp_path)

        second = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert "SEC020" not in _ids(second)
        assert any(n.startswith("baseline:") for n in second.notes)

    def test_new_finding_survives_baseline(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\nexec(y)\n", encoding="utf-8")
        first = scan(tmp_path, run_git=False, run_deps=False)
        bl = tmp_path / "b.json"
        # baseline only records SEC020, not SEC021
        write_baseline(bl, [f for f in first.findings if f.rule_id == "SEC020"], tmp_path)
        second = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert "SEC020" not in _ids(second)
        assert "SEC021" in _ids(second)

    def test_baseline_roundtrip(self, tmp_path):
        f = Finding(rule_id="SEC020", title="t", severity=Severity.HIGH, message="m",
                    path="a.py", line=1, evidence="e", fix="f", cwe="CWE-95",
                    confidence="high", scanner="code")
        p = tmp_path / "b.json"
        write_baseline(p, [f], tmp_path)
        loaded = load_baseline(p)
        assert len(loaded) == 1
        key = next(iter(loaded))
        assert key[0] == "SEC020" and key[1] == "a.py" and key[2] == 1

    def test_corrupt_baseline_ignored(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text("not json", encoding="utf-8")
        assert load_baseline(p) == set()


class TestConfigLoading:
    def test_toml_config_loaded(self, tmp_path):
        (tmp_path / "sentinel.toml").write_text(
            'fail_on = "critical"\n'
            'exclude = ["vendor/**"]\n'
            'allow_secrets = ["test-token"]\n'
            '[[suppressions]]\n'
            'rule_id = "SEC020"\n'
            'reason = "test fixture"\n',
            encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "critical"
        assert "vendor/**" in cfg.excludes
        assert cfg.allow_secrets == ["test-token"]
        assert cfg.suppressions[0].rule_id == "SEC020"
        assert cfg.suppressions[0].reason == "test fixture"

    def test_json_config_fallback(self, tmp_path):
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"fail_on": "never", "exclude": ["dist/**"]}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "never"
        assert "dist/**" in cfg.excludes

    def test_defaults_when_missing(self, tmp_path):
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "high"
        assert cfg.allow_secrets == []
        assert cfg.suppressions == []
        assert any("built-in defaults" in n for n in cfg.notes)

    def test_explicit_config_overrides_root_file(self, tmp_path):
        (tmp_path / "sentinel.toml").write_text('fail_on = "low"\n', encoding="utf-8")
        other = tmp_path / "other.toml"
        other.write_text('fail_on = "never"\n', encoding="utf-8")
        cfg = load_config(tmp_path, str(other))
        assert cfg.fail_on == "never"


class TestStagedMode:
    @pytest.fixture()
    def staged_repo(self, tmp_path):
        p = tmp_path / "r"
        p.mkdir()

        def run(*a):
            subprocess.run(["git", *a], cwd=str(p), check=True,
                           capture_output=True, timeout=30)

        run("init")
        run("config", "user.email", "t@t.io")
        run("config", "user.name", "T")
        (p / "staged.py").write_text("eval(x)\n", encoding="utf-8")
        (p / "unstaged.py").write_text("exec(y)\n", encoding="utf-8")
        run("add", "staged.py")
        return p

    def test_staged_only_scan(self, staged_repo):
        result = scan(staged_repo, staged=True, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        assert "SEC021" not in _ids(result)  # never git-added
        assert any("staged" in n.lower() for n in result.notes)


class TestDegradeNotes:
    def test_cve_note_present_when_tools_missing(self, tmp_path, monkeypatch):
        from sentinel.rules import deps
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=True, history=False)
        assert "SEC060" in _ids(result)  # pin hygiene still ran
        assert "DEPS-SKIP" in _ids(result)

    def test_deps_disabled_no_note(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert "DEPS-SKIP" not in _ids(result)
        assert "SEC060" not in _ids(result)
