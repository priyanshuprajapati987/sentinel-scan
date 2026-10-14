"""Audit-fix regression tests: staged unicode, fail-closed suppressions,
line-shift-tolerant baseline, exclude-matcher rewrite, BOM, accounting."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from sentinel import engine
from sentinel.config import Config, Suppression
from sentinel.engine import (
    _is_excluded,
    _read_text,
    discover,
    load_baseline,
    scan,
    write_baseline,
)
from sentinel.models import Finding, Severity
from sentinel.rules import code as code_mod


def _ids(result) -> list[str]:
    return [f.rule_id for f in result.findings]


def _finding(**kw) -> Finding:
    base = dict(rule_id="SEC020", title="eval() on dynamic input",
                severity=Severity.HIGH, message="eval on input",
                path="app.py", line=1, evidence="eval(x)", fix="f",
                cwe="CWE-95", confidence="high", scanner="code")
    base.update(kw)
    return Finding(**base)


# --------------------------------------------------------------------------- #
# P0: staged unicode paths (git core.quotepath quoting)                        #
# --------------------------------------------------------------------------- #

class TestStagedUnicodePath:
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
        (p / "café.py").write_text("eval(user_input)\n", encoding="utf-8")
        run("add", "café.py")
        return p

    def test_unicode_staged_path_is_scanned(self, staged_repo):
        result = scan(staged_repo, staged=True, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        assert any("staged: scanning 1" in n for n in result.notes)


# --------------------------------------------------------------------------- #
# P1: inline ignore-id parsing fails closed (no wildcard degradation)          #
# --------------------------------------------------------------------------- #

class TestIgnoreIdParsing:
    def test_invalid_id_keeps_finding(self):
        text = "x = eval(user_input)  # sentinel-ignore SEC020X"
        hits = code_mod.scan_text("a.py", text)
        assert [h.rule_id for h in hits] == ["SEC020"]
        assert engine._inline_suppress(hits, text) == 0
        assert [h.rule_id for h in hits] == ["SEC020"]

    def test_invalid_id_keeps_finding_scan_level(self, tmp_path):
        (tmp_path / "a.py").write_text(
            "eval(user_input)  # sentinel-ignore SEC020X\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)

    def test_bare_marker_still_suppresses(self):
        text = "eval(user_input)  # sentinel-ignore"
        hits = code_mod.scan_text("a.py", text)
        assert [h.rule_id for h in hits] == ["SEC020"]
        assert engine._inline_suppress(hits, text) == 1
        assert hits == []

    def test_bare_marker_suppresses_scan_level(self, tmp_path):
        (tmp_path / "a.py").write_text(
            "eval(user_input)  # sentinel-ignore\n", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" not in _ids(result)
        assert result.suppressed >= 1

    def test_marker_without_comment_start_not_suppressed(self):
        text = 'note = "eval(user_input) sentinel-ignore SEC020"'
        hits = code_mod.scan_text("a.py", text)
        assert any(h.rule_id == "SEC020" for h in hits)
        assert engine._inline_suppress(hits, text) == 0
        assert any(h.rule_id == "SEC020" for h in hits)

    def test_marker_in_string_kept_scan_level(self, tmp_path):
        (tmp_path / "a.py").write_text(
            'note = "eval(user_input) sentinel-ignore SEC020"\n', encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)


# --------------------------------------------------------------------------- #
# P1: malformed expiry fails closed (suppression does not become permanent)    #
# --------------------------------------------------------------------------- #

class TestExpiryFailClosed:
    @pytest.mark.parametrize("expires", ["2027-1-1", "garbage", "31-12-2027"])
    def test_malformed_expiry_reports_finding(self, tmp_path, expires):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", expires=expires)])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert "SEC020" in _ids(result)
        assert result.suppressed == 0

    def test_future_expiry_suppressed(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
        cfg = Config(suppressions=[Suppression(rule_id="SEC020", expires="2099-01-01")])
        result = scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert "SEC020" not in _ids(result)
        assert result.suppressed == 1


# --------------------------------------------------------------------------- #
# P1: baseline survives line shifts; update-twice keeps entries                #
# --------------------------------------------------------------------------- #

class TestBaselineStability:
    def test_baseline_survives_line_shift(self, tmp_path):
        p = tmp_path / "a.py"
        p.write_text("eval(user_input)\n", encoding="utf-8")
        first = scan(tmp_path, run_git=False, run_deps=False)
        assert "SEC020" in _ids(first)
        bl = tmp_path / "bl.json"
        write_baseline(bl, first.findings, tmp_path)

        p.write_text("\n\n\n" + "eval(user_input)\n", encoding="utf-8")
        second = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert "SEC020" not in _ids(second)
        assert any(n.startswith("baseline:") for n in second.notes)

    def test_update_baseline_twice_keeps_entries(self, tmp_path):
        p = tmp_path / "a.py"
        p.write_text("eval(user_input)\n", encoding="utf-8")
        bl = tmp_path / "bl.json"

        r1 = scan(tmp_path, run_git=False, run_deps=False)
        write_baseline(bl, r1.findings, tmp_path)  # update #1

        p.write_text("\n\n" + "eval(user_input)\n", encoding="utf-8")  # line shift
        (tmp_path / "b.py").write_text("exec(y)\n", encoding="utf-8")  # new finding
        r2 = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert "SEC020" not in _ids(r2)  # stable id survives the shift
        assert "SEC021" in _ids(r2)      # genuinely new finding still fires

        # update #2 (engine-level): previous entries + whatever is new
        write_baseline(bl, r1.findings + r2.findings, tmp_path)
        assert len(load_baseline(bl)) == len(r1.findings) + len(r2.findings)

        r3 = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert r3.findings == []

    def test_baseline_persists_stable_id(self, tmp_path):
        bl = tmp_path / "bl.json"
        write_baseline(bl, [_finding()], tmp_path)
        payload = json.loads(bl.read_text(encoding="utf-8"))
        entry = payload["findings"][0]
        assert entry["stable_id"] == _finding().stable_fingerprint()

    def test_legacy_baseline_without_stable_id_still_loads(self, tmp_path):
        bl = tmp_path / "legacy.json"
        bl.write_text(json.dumps({
            "version": 1,
            "findings": [{"rule_id": "SEC020", "path": "a.py", "line": 1,
                          "message": "eval on input"}],
        }), encoding="utf-8")
        keys = load_baseline(bl)
        assert keys == {("SEC020", "a.py", 1, "eval on input", "")}

    def test_unreadable_baseline_not_applied_and_noted(self, tmp_path):
        (tmp_path / "a.py").write_text("eval(user_input)\n", encoding="utf-8")
        bl = tmp_path / "bad.json"
        bl.write_text("not json", encoding="utf-8")
        result = scan(tmp_path, run_git=False, run_deps=False, baseline=bl)
        assert "SEC020" in _ids(result)  # fail closed: baseline NOT applied
        assert any("unreadable" in n for n in result.notes)


# --------------------------------------------------------------------------- #
# P1: _is_excluded matcher matrix                                              #
# --------------------------------------------------------------------------- #

class TestIsExcludedMatrix:
    @pytest.mark.parametrize("rel,patterns,expected", [
        # previously-dead directory patterns now match
        ("node_modules/x.js", ["**/node_modules/"], True),
        ("a/node_modules/x.js", ["**/node_modules/"], True),
        ("src/generated/out.py", ["src/generated/"], True),
        ("pkg.egg-info/PKG-INFO", ["*.egg-info/"], True),
        ("a/pkg.egg-info/file", ["*.egg-info/"], True),
        # leading "/" anchors to the scan root (gitignore semantics)
        ("build/x.py", ["/build/"], True),
        ("sub/build/x.py", ["/build/"], False),
        # plain prefix globs keep working
        ("vendor/a.js", ["vendor/**"], True),
        ("vendor/deep/a.js", ["vendor/**"], True),
        ("testdata/a.py", ["testdata/**"], True),
        ("src/vendor/a.js", ["vendor/**"], False),
        # plain file patterns
        ("app.py", ["app.py"], True),
        ("src/app.py", ["app.py"], True),
        ("other.py", ["app.py"], False),
        ("mockapi.py", ["api.py"], False),
        # bare dir pattern: positive at any depth + negatives
        ("node_modules/x.js", ["node_modules/"], True),
        ("src/node_modules/x.js", ["node_modules/"], True),
        ("mynode_modules/x.js", ["node_modules/"], False),
        ("node_modules.py", ["node_modules/"], False),
        # DEFAULT_EXCLUDES semantics preserved
        ("a/b.min.js", ["*.min.js"], True),
        ("package-lock.json", ["package-lock.json"], True),
        ("dist/x.js", ["dist/"], True),
        ("a/dist/x.js", ["dist/"], True),
        ("htmlcov/i.html", ["htmlcov/"], True),
        (".git/config", [".git/"], True),
        ("venv/lib/x.py", ["venv/"], True),
    ])
    def test_matrix(self, rel, patterns, expected):
        assert _is_excluded(rel, patterns) is expected

    def test_case_variant_is_platform_dependent(self):
        # Windows matches case-insensitively; POSIX stays case-sensitive
        nt = os.name == "nt"
        assert _is_excluded("NODE_MODULES/X.JS", ["node_modules/"]) is nt
        assert _is_excluded("Vendor/A.js", ["vendor/**"]) is nt

    def test_empty_pattern_never_matches(self):
        assert _is_excluded("a.py", ["", "/", "//"]) is False


# --------------------------------------------------------------------------- #
# P2: BOM stripping, suppression path precision, discover accounting          #
# --------------------------------------------------------------------------- #

class TestReadTextBom:
    def test_utf8_bom_stripped(self, tmp_path):
        p = tmp_path / "b.py"
        p.write_bytes(b"\xef\xbb\xbf" + "print(1)\n".encode("utf-8"))
        text = _read_text(p)
        assert text is not None
        assert text == "print(1)\n"
        assert not text.startswith("\ufeff")


class TestSuppressionPathPrecision:
    @staticmethod
    def _fs(path: str) -> list[Finding]:
        return [_finding(path=path)]

    def test_api_py_does_not_match_mockapi_py(self):
        findings = self._fs("mockapi.py")
        n = engine._suppressed_by(
            findings, [Suppression(rule_id="SEC020", path="api.py")])
        assert n == 0
        assert len(findings) == 1  # kept

    def test_exact_path_still_suppressed(self):
        findings = self._fs("api.py")
        n = engine._suppressed_by(
            findings, [Suppression(rule_id="SEC020", path="api.py")])
        assert n == 1
        assert findings == []

    def test_directory_prefix_still_suppressed(self):
        findings = self._fs("src/api/x.py")
        n = engine._suppressed_by(
            findings, [Suppression(rule_id="SEC020", path="src/api/")])
        assert n == 1
        assert findings == []


class TestOnlyFilesAccounting:
    def test_missing_only_file_counted_as_skipped(self, tmp_path):
        (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
        files, skipped = discover(tmp_path, Config(),
                                  only_files=["a.py", "ghost.py"])
        assert [f.name for f in files] == ["a.py"]
        assert skipped == 1

    def test_only_files_respects_size_cap(self, tmp_path):
        (tmp_path / "big.py").write_text("print(1)\n", encoding="utf-8")
        cfg = Config(max_file_bytes=5)  # file is 9 bytes → over the cap
        files, skipped = discover(tmp_path, cfg, only_files=["big.py"])
        assert files == []
        assert skipped == 1

    def test_only_file_outside_root_skipped_not_crashed(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        outside = tmp_path / "outside.py"
        outside.write_text("eval(user_input)\n", encoding="utf-8")
        rel = Path(os.path.relpath(outside, root)).as_posix()
        result = scan(root, config=Config(), run_git=False, run_deps=False,
                      only_files=[rel])
        assert result.files_scanned == 0
        assert result.files_skipped == 1
        assert "SEC020" not in _ids(result)
