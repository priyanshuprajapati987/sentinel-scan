"""Regression tests for the 2026-10 config audit fixes (config.py).

Covers: invalid-TOML reporting, type validation (int/bool/list), fail_on
validation, and case-insensitive --config suffix handling.
"""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.config import load_config


class TestInvalidToml:
    def test_syntax_error_reports_invalid_toml_not_parser(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text('fail_on = "high\n', encoding="utf-8")
        cfg = load_config(tmp_path)
        notes = "\n".join(cfg.notes)
        assert "invalid TOML" in notes
        assert "no TOML parser" not in notes

    def test_invalid_toml_keeps_defaults(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text("= = =\n", encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "high"
        assert cfg.history is True
        assert any("invalid TOML" in n for n in cfg.notes)

    def test_explicit_invalid_toml(self, tmp_path: Path):
        bad = tmp_path / "bad.toml"
        bad.write_text("[[[oops", encoding="utf-8")
        cfg = load_config(tmp_path, str(bad))
        assert any("invalid TOML" in n for n in cfg.notes)
        assert "no TOML parser" not in "\n".join(cfg.notes)
        assert cfg.fail_on == "high"


class TestTypeValidation:
    def test_int_key_bool_rejected(self, tmp_path: Path):
        # bools pass isinstance(int) — `history_commits = true` must not
        # silently become 1.
        (tmp_path / "sentinel.toml").write_text("history_commits = true\n",
                                                encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history_commits == 500  # default kept
        assert any("history_commits should be an integer" in n for n in cfg.notes)

    def test_int_key_wrong_type_rejected(self, tmp_path: Path):
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"max_file_bytes": "big"}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.max_file_bytes == 2_000_000
        assert any("max_file_bytes should be an integer" in n for n in cfg.notes)

    def test_valid_int_applied(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text("history_commits = 42\n",
                                                encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history_commits == 42
        assert not any("integer" in n for n in cfg.notes)

    def test_bool_string_false_converts(self, tmp_path: Path):
        (tmp_path / ".sentinel.json").write_text(json.dumps({
            "history": "false", "deps_cves": "FALSE", "inline_suppressions": "0",
        }), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history is False
        assert cfg.deps_cves is False
        assert cfg.inline_suppressions is False

    def test_bool_string_true_converts(self, tmp_path: Path):
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"history": "True", "deps_cves": "1"}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history is True
        assert cfg.deps_cves is True

    def test_bool_wrong_type_rejected(self, tmp_path: Path):
        # string "false" is converted, but an arbitrary int is not a bool
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"history": 5}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history is True  # default kept
        assert any("history should be a boolean" in n for n in cfg.notes)

    def test_real_bool_still_accepted(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text("history = false\n",
                                                encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.history is False
        assert not any("boolean" in n for n in cfg.notes)

    def test_list_wrong_type_rejected(self, tmp_path: Path):
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"exclude": "custom-dist/"}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert "custom-dist/" not in cfg.excludes
        assert any("exclude should be a list" in n for n in cfg.notes)

    def test_allow_secrets_wrong_type_rejected(self, tmp_path: Path):
        (tmp_path / ".sentinel.json").write_text(
            json.dumps({"allow_secrets": 42}), encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.allow_secrets == []
        assert any("allow_secrets should be a list" in n for n in cfg.notes)

    def test_unknown_key_noted(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text('fal_on = "high"\n', encoding="utf-8")
        cfg = load_config(tmp_path)
        assert any("unknown key 'fal_on'" in n for n in cfg.notes)

    def test_known_keys_not_flagged_unknown(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text(
            'fail_on = "low"\nhistory = true\nhistory_commits = 10\n'
            'exclude = ["x/"]\nallow_secrets = []\ndeps_cves = true\n'
            'inline_suppressions = true\nbaseline = "b.json"\nmax_file_bytes = 10\n',
            encoding="utf-8")
        cfg = load_config(tmp_path)
        assert not any("unknown key" in n for n in cfg.notes)


class TestFailOnValidation:
    def test_invalid_fail_on_defaults_high_with_note(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text('fail_on = "banana"\n',
                                                encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "high"
        assert any("invalid fail_on" in n for n in cfg.notes)

    def test_invalid_fail_on_scan_does_not_crash(self, tmp_path: Path):
        from sentinel.cli import main
        (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
        (tmp_path / "sentinel.toml").write_text('fail_on = "banana"\n',
                                                encoding="utf-8")
        assert main(["scan", str(tmp_path), "--no-git", "--no-deps", "-q"]) == 0

    def test_off_gate_values_pass(self, tmp_path: Path):
        for value in ("never", "off", "none"):
            (tmp_path / "sentinel.toml").write_text(f'fail_on = "{value}"\n',
                                                    encoding="utf-8")
            cfg = load_config(tmp_path)
            assert cfg.fail_on == value
            assert not any("fail_on" in n for n in cfg.notes)

    def test_valid_severity_pass(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text('fail_on = "critical"\n',
                                                encoding="utf-8")
        cfg = load_config(tmp_path)
        assert cfg.fail_on == "critical"
        assert not any("fail_on" in n for n in cfg.notes)


class TestExplicitConfigCase:
    def test_uppercase_toml_suffix_loads(self, tmp_path: Path):
        cfg_file = tmp_path / "X.TOML"
        cfg_file.write_text('fail_on = "never"\n', encoding="utf-8")
        cfg = load_config(tmp_path, str(cfg_file))
        assert cfg.fail_on == "never"

    def test_mixed_case_toml_suffix_loads(self, tmp_path: Path):
        cfg_file = tmp_path / "Conf.Toml"
        cfg_file.write_text('fail_on = "low"\n', encoding="utf-8")
        cfg = load_config(tmp_path, str(cfg_file))
        assert cfg.fail_on == "low"
