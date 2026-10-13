"""v0.4.0 — GitLab Code Quality format, config baseline key, new rules SEC048/049/056/057."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel import engine
from sentinel.config import Config, load_config
from sentinel.models import Finding, Severity
from sentinel.report import RENDERERS, render_gitlab, write_report
from sentinel.rules import code


def _finding(**kw) -> Finding:
    base = dict(rule_id="SEC020", title="eval() on dynamic input",
                severity=Severity.HIGH, message="eval on input",
                path="app.py", line=3, evidence="eval(x)", scanner="code")
    base.update(kw)
    return Finding(**base)


def _result(findings: list[Finding] | None = None, suppressed: int = 0):
    return engine.ScanResult(root=Path("."), findings=findings or [], suppressed=suppressed)


# --------------------------------------------------------------------------- #
# GitLab Code Quality                                                          #
# --------------------------------------------------------------------------- #

class TestGitlabFormat:
    def test_registered_renderer(self):
        assert "gitlab" in RENDERERS

    def test_issue_shape(self):
        payload = json.loads(render_gitlab(_result([_finding()])))
        assert len(payload) == 1
        issue = payload[0]
        assert issue["type"] == "issue"
        assert issue["check_id"] == "SEC020"
        assert issue["description"] == "eval on input"
        assert issue["severity"] == "high"
        assert issue["confidence"] == "high"
        assert issue["location"]["path"] == "app.py"
        assert issue["location"]["lines"]["begin"] == 3

    def test_severity_mapping(self):
        out = json.loads(render_gitlab(_result([
            _finding(severity=Severity.CRITICAL),
            _finding(severity=Severity.MEDIUM),
            _finding(severity=Severity.LOW),
            _finding(severity=Severity.INFO),
        ])))
        assert [i["severity"] for i in out] == ["critical", "medium", "low", "info"]

    def test_fingerprint_line_invariant(self):
        a = json.loads(render_gitlab(_result([_finding(line=3)])))[0]
        b = json.loads(render_gitlab(_result([_finding(line=99)])))[0]
        assert a["fingerprint"] == b["fingerprint"] == _finding().stable_fingerprint()

    def test_file_level_begin_is_one(self):
        out = json.loads(render_gitlab(_result([_finding(line=0)])))[0]
        assert out["location"]["lines"]["begin"] == 1

    def test_backslash_path_normalized(self):
        out = json.loads(render_gitlab(_result([_finding(path="src\\app.py")])))[0]
        assert out["location"]["path"] == "src/app.py"

    def test_empty_report_is_empty_array(self):
        assert json.loads(render_gitlab(_result([]))) == []

    def test_unknown_confidence_defaults(self):
        out = json.loads(render_gitlab(_result([_finding(confidence="??")])))[0]
        assert out["confidence"] == "medium"

    def test_write_report_dir_mapping(self, tmp_path: Path):
        write_report("gitlab", _result([_finding()]), str(tmp_path) + "/", quiet=True)
        assert (tmp_path / "codequality.json").exists()


# --------------------------------------------------------------------------- #
# config `baseline` key                                                        #
# --------------------------------------------------------------------------- #

class TestConfigBaseline:
    def test_toml_baseline_loaded(self, tmp_path: Path):
        (tmp_path / "sentinel.toml").write_text('baseline = ".ci/sentinel-baseline"\n',
                                                encoding="utf-8")
        assert load_config(tmp_path).baseline == ".ci/sentinel-baseline"

    def test_default_is_empty(self, tmp_path: Path):
        assert load_config(tmp_path).baseline == ""

    def test_scan_auto_applies_config_baseline(self, tmp_path: Path):
        vuln = tmp_path / "proj"
        vuln.mkdir()
        (vuln / "app.py").write_text("eval(x)\n", encoding="utf-8")
        # record a baseline first
        cfg = Config()
        first = engine.scan(vuln, config=cfg, run_git=False, run_deps=False)
        bl = vuln / "known.json"
        engine.write_baseline(bl, first.findings, vuln)
        (vuln / "sentinel.toml").write_text('baseline = "known.json"\n', encoding="utf-8")
        # without the flag: baseline from config still filters
        cfg2 = load_config(vuln)
        assert cfg2.baseline == "known.json"
        second = engine.scan(vuln, config=cfg2, run_git=False, run_deps=False,
                             baseline=vuln / cfg2.baseline)
        assert second.findings == []

    def test_cli_flag_overrides_config(self, tmp_path: Path, capsys):
        from sentinel.cli import main
        vuln = tmp_path / "proj"
        vuln.mkdir()
        (vuln / "app.py").write_text("eval(x)\n", encoding="utf-8")
        # config points at an EMPTY baseline file; flag points at a real one
        (vuln / "sentinel.toml").write_text('baseline = "empty.json"\n', encoding="utf-8")
        (vuln / "empty.json").write_text("{}", encoding="utf-8")
        real_bl = tmp_path / "real.json"
        main(["scan", str(vuln), "--no-git", "--no-deps", "-q",
              "--update-baseline", "--baseline", str(real_bl)])
        assert "finding(s)" in capsys.readouterr().out
        assert json.loads(real_bl.read_text(encoding="utf-8"))  # non-empty

    def test_update_baseline_writes_to_configured_path(self, tmp_path: Path, capsys):
        from sentinel.cli import main
        vuln = tmp_path / "proj"
        vuln.mkdir()
        (vuln / "app.py").write_text("eval(x)\n", encoding="utf-8")
        (vuln / "sentinel.toml").write_text('baseline = "known.json"\n', encoding="utf-8")
        rc = main(["scan", str(vuln), "--no-git", "--no-deps", "-q", "--update-baseline"])
        assert rc == 0
        assert (vuln / "known.json").exists()
        assert "known.json" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# new rules SEC048 / SEC049 / SEC056 / SEC057                                  #
# --------------------------------------------------------------------------- #

class TestNewRulesV040:
    def _ids(self, path: str, line: str) -> list[str]:
        return [h.rule_id for h in code.scan_text(path, line)]

    # SEC048 -----------------------------------------------------------------
    def test_sec048_assert_is_admin(self):
        assert "SEC048" in self._ids("a.py", "assert user.is_authenticated")

    def test_sec048_assert_check_password(self):
        assert "SEC048" in self._ids("a.py", "assert check_password(pw, h)")

    def test_sec048_plain_assert_ok(self):
        assert "SEC048" not in self._ids("a.py", "assert result is not None")

    def test_sec048_only_py(self):
        assert "SEC048" not in self._ids("a.js", "assert user.is_authenticated")

    # SEC049 -----------------------------------------------------------------
    def test_sec049_create_cipher(self):
        assert "SEC049" in self._ids("a.js", "const c = crypto.createCipher(alg, key)")

    def test_sec049_create_decipher_sync(self):
        assert "SEC049" in self._ids("a.js", "crypto.createDecipherSync('aes', k)")

    def test_sec049_cipheriv_ok(self):
        assert "SEC049" not in self._ids("a.js", "crypto.createCipheriv(alg, key, iv)")

    # SEC056 -----------------------------------------------------------------
    def test_sec056_document_write(self):
        assert "SEC056" in self._ids("a.js", "document.write(html)")

    def test_sec056_writeln_html_file(self):
        assert "SEC056" in self._ids("a.html", "document.writeln(x)")

    def test_sec056_dom_lookup_ok(self):
        assert "SEC056" not in self._ids("a.js", "document.getElementById('x')")

    # SEC057 -----------------------------------------------------------------
    def test_sec057_jwt_decode_no_algorithms(self):
        assert "SEC057" in self._ids("a.py", "jwt.decode(token, key)")

    def test_sec057_jwt_decode_js(self):
        assert "SEC057" in self._ids("a.js", "jwt.decode(token, key)")

    def test_sec057_jsonwebtoken_prefix(self):
        assert "SEC057" in self._ids("a.js", "jsonwebtoken.decode(token, secret)")

    def test_sec057_algorithms_allowlist_ok(self):
        assert "SEC057" not in self._ids(
            "a.py", "jwt.decode(token, key, algorithms=['HS256'])")

    # catalog ----------------------------------------------------------------
    def test_catalog_lists_new_rules(self):
        ids = {rid for rid, _t, _s in code.all_rules()}
        for rid in ("SEC048", "SEC049", "SEC056", "SEC057"):
            assert rid in ids

    def test_rule_count_is_67(self):
        from sentinel.cli import _catalog
        assert len(_catalog()) == 67
