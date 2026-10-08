"""CLI behavior: exit codes, formats, flags."""

import json

import pytest

from sentinel.cli import main


@pytest.fixture()
def vuln_dir(tmp_path):
    (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def clean_dir(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    return tmp_path


class TestBasics:
    def test_no_command_prints_help_and_exits_2(self, capsys):
        assert main([]) == 2
        assert "usage" in capsys.readouterr().out.lower()

    def test_rules_lists_catalog(self, capsys):
        assert main(["rules"]) == 0
        out = capsys.readouterr().out
        assert "SEC020" in out and "SEC001" in out
        assert "rules" in out.splitlines()[-1].lower()

    def test_version(self):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_nonexistent_path_exits_2(self, capsys):
        assert main(["scan", str(tmp_missing())]) == 2
        assert "does not exist" in capsys.readouterr().err


def tmp_missing() -> str:
    import os
    return os.path.join(os.environ.get("TEMP", "/tmp"), "sentinel-definitely-missing-xyz")


class TestGates:
    def test_vulnerable_dir_fails_high_gate(self, vuln_dir, capsys):
        assert main(["scan", str(vuln_dir), "--fail-on", "high"]) == 1

    def test_fail_on_never_passes(self, vuln_dir, capsys):
        assert main(["scan", str(vuln_dir), "--fail-on", "never", "-q"]) == 0

    def test_fail_on_critical_passes_for_high_only(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text("eval(user_input)\n", encoding="utf-8")
        assert main(["scan", str(tmp_path), "--fail-on", "critical", "-q"]) == 0

    def test_clean_dir_passes(self, clean_dir):
        assert main(["scan", str(clean_dir), "--no-deps", "-q"]) == 0

    def test_gate_from_config(self, vuln_dir):
        (vuln_dir / "sentinel.toml").write_text('fail_on = "never"\n', encoding="utf-8")
        assert main(["scan", str(vuln_dir), "-q"]) == 0


class TestOutput:
    def test_json_to_file(self, vuln_dir, tmp_path):
        out = tmp_path / "r" / "report.json"
        code = main(["scan", str(vuln_dir), "-f", "json", "-o", str(out),
                     "--fail-on", "never"])
        assert code == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["findings"][0]["rule_id"] == "SEC020"

    def test_sarif_output(self, vuln_dir, tmp_path):
        out = tmp_path / "report.sarif"
        main(["scan", str(vuln_dir), "-f", "sarif", "-o", str(out), "-q"])
        doc = json.loads(out.read_text(encoding="utf-8"))
        assert doc["version"] == "2.1.0"

    def test_quiet_console_prints_nothing(self, vuln_dir, capsys):
        main(["scan", str(vuln_dir), "-q", "--fail-on", "never"])
        assert capsys.readouterr().out.strip() == ""

    def test_console_shows_findings(self, vuln_dir, capsys):
        main(["scan", str(vuln_dir), "--fail-on", "never"])
        out = capsys.readouterr().out
        assert "SEC020" in out and "SCORE" in out


class TestFlags:
    def test_update_baseline_writes_and_exits_0(self, vuln_dir, tmp_path):
        bl = tmp_path / "bl.json"
        assert main(["scan", str(vuln_dir), "--baseline", str(bl),
                     "--update-baseline"]) == 0
        assert bl.exists()
        assert json.loads(bl.read_text(encoding="utf-8"))["findings"]

    def test_baseline_suppresses_on_next_run(self, vuln_dir, tmp_path):
        bl = tmp_path / "bl.json"
        main(["scan", str(vuln_dir), "--baseline", str(bl), "--update-baseline"])
        assert main(["scan", str(vuln_dir), "--baseline", str(bl),
                     "--fail-on", "high", "-q"]) == 0

    def test_exclude_flag(self, vuln_dir):
        # excluding the file itself -> nothing to scan -> pass
        assert main(["scan", str(vuln_dir), "--exclude", "app.py",
                     "--fail-on", "high", "-q"]) == 0

    def test_no_deps_flag_skips_cve_note(self, vuln_dir, capsys):
        main(["scan", str(vuln_dir), "--no-deps", "-f", "json",
              "-o", str(vuln_dir / "out.json"), "-q"])
        data = json.loads((vuln_dir / "out.json").read_text(encoding="utf-8"))
        assert not any(f["rule_id"] == "DEPS-SKIP" for f in data["findings"])

    def test_explicit_config(self, vuln_dir, tmp_path):
        cfg = tmp_path / "c.toml"
        cfg.write_text('fail_on = "never"\n[[suppressions]]\nrule_id = "SEC020"\n',
                       encoding="utf-8")
        assert main(["scan", str(vuln_dir), "--config", str(cfg), "-q"]) == 0
