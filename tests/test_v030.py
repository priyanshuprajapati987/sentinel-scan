"""v0.3.0 — inline suppressions, sentinel diff, GitHub annotations, new rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel import engine
from sentinel.config import Config
from sentinel.diff import (
    _stable_id,
    diff_reports,
    load_report_findings,
    render_diff,
)
from sentinel.models import Finding, Severity
from sentinel.report import render_github, render_sarif
from sentinel.rules import code
from sentinel.rules import secrets as secrets_mod

# --------------------------------------------------------------------------- #
# inline suppression comments                                                  #
# --------------------------------------------------------------------------- #

_PW = 'password = "abcdefghijklmnop"  # sentinel-ignore SEC014'


class TestInlineSuppressions:
    def _secrets(self, text: str) -> list[Finding]:
        hits = secrets_mod.scan_text("app.py", text)
        engine._inline_suppress(hits, text)
        return hits

    def test_same_line_specific_rule(self):
        assert self._secrets(_PW) == []

    def test_same_line_keeps_other_rules(self):
        text = 'password = "abcdefghijklmnop"  # sentinel-ignore SEC020'
        assert [h.rule_id for h in self._secrets(text)] == ["SEC014"]

    def test_same_line_wildcard(self):
        text = 'password = "abcdefghijklmnop"  # sentinel-ignore'
        assert self._secrets(text) == []

    def test_next_line_specific(self):
        text = '# sentinel-ignore-next-line SEC014\npassword = "abcdefghijklmnop"\n'
        assert self._secrets(text) == []

    def test_next_line_wildcard(self):
        text = '# sentinel-ignore-next-line\npassword = "abcdefghijklmnop"\n'
        assert self._secrets(text) == []

    def test_next_line_does_not_leak_to_line_after(self):
        text = (
            '# sentinel-ignore-next-line SEC014\n'
            'password = "abcdefghijklmnop"\n'
            'password = "qrstuvwxyzabcd"\n'
        )
        assert [h.line for h in self._secrets(text)] == [3]

    def test_comma_list(self):
        text = 'password = "abcdefghijklmnop"  # sentinel-ignore SEC014,SEC020'
        assert self._secrets(text) == []

    def test_slashslash_comment_style(self):
        hits = code.scan_text("app.js", 'let x = eval(userInput) // sentinel-ignore SEC020')
        engine._inline_suppress(hits, 'let x = eval(userInput) // sentinel-ignore SEC020')
        assert hits == []

    def test_scan_counts_suppressed(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(_PW + "\n", encoding="utf-8")
        result = engine.scan(tmp_path, config=Config(), run_git=False, run_deps=False)
        assert result.findings == []
        assert result.suppressed >= 1

    def test_config_can_disable(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(_PW + "\n", encoding="utf-8")
        cfg = Config(inline_suppressions=False)
        result = engine.scan(tmp_path, config=cfg, run_git=False, run_deps=False)
        assert [f.rule_id for f in result.findings] == ["SEC014"]

    def test_no_marker_is_noop(self):
        text = 'password = "abcdefghijklmnop"\n'
        hits = secrets_mod.scan_text("app.py", text)
        assert engine._inline_suppress(hits, text) == 0
        assert len(hits) == 1


# --------------------------------------------------------------------------- #
# new secret rules                                                             #
# --------------------------------------------------------------------------- #

_HIGH_ENTROPY = "Ab3xK9mQz7Wp2Ld5Rt8Yv4Nb6Hc1Jf0Gg5Ss2"


class TestNewSecretRules:
    def _ids(self, line: str) -> list[str]:
        return [h.rule_id for h in secrets_mod.scan_text("x.py", line)]

    def test_sec016_aws_secret_access_key(self):
        line = f'aws_secret_access_key = "{"A" * 40}"'
        assert "SEC016" in self._ids(line)

    def test_sec016_rejects_short_value(self):
        line = f'aws_secret_access_key = "{"A" * 39}"'
        assert "SEC016" not in self._ids(line)

    def test_sec017_url_query_credential(self):
        line = 'url = "https://api.example.com/v1?api_key=abcdefghijklmnop"'
        hits = secrets_mod.scan_text("x.py", line)
        assert [h.rule_id for h in hits] == ["SEC017"]
        assert "…" in hits[0].evidence  # redacted

    def test_sec017_no_query_credential(self):
        assert "SEC017" not in self._ids('url = "https://api.example.com/v1/items"')

    def test_sec018_bearer_token(self):
        line = f'headers = {{"Authorization": "Bearer {_HIGH_ENTROPY}"}}'
        hits = secrets_mod.scan_text("x.py", line)
        assert [h.rule_id for h in hits] == ["SEC018"]
        assert "…" in hits[0].evidence

    def test_sec018_entropy_gate_skips_placeholderish(self):
        # repeating low-entropy body is not a plausible live token
        line = 'headers = {"Authorization": "Bearer ' + "ab3" * 10 + '"}'
        assert "SEC018" not in self._ids(line)

    def test_sec019_flask_secret_key(self):
        hits = secrets_mod.scan_text("x.py", 'SECRET_KEY = "supersecretvalue99"')
        assert [h.rule_id for h in hits] == ["SEC019"]
        assert "…" in hits[0].evidence

    def test_sec019_jwt_secret(self):
        assert "SEC019" in self._ids('JWT_SECRET = "anothersecretvalue"')

    def test_sec019_placeholder_not_flagged(self):
        assert "SEC019" not in self._ids('SECRET_KEY = "changeme"')

    def test_evidence_is_redacted_everywhere(self):
        hits = secrets_mod.scan_text(
            "x.py", f'aws_secret_access_key = "{"B" * 40}"')
        assert all("B" * 10 not in h.evidence for h in hits)


# --------------------------------------------------------------------------- #
# new code / container rules                                                   #
# --------------------------------------------------------------------------- #

class TestNewCodeRules:
    def _ids(self, path: str, line: str) -> list[str]:
        return [h.rule_id for h in code.scan_text(path, line)]

    def test_sec043_open_redirect(self):
        assert "SEC043" in self._ids("a.py", 'redirect(request.args.get("next"))')

    def test_sec043_fixed_target_ok(self):
        assert "SEC043" not in self._ids("a.py", 'redirect("/dashboard")')

    def test_sec043_express(self):
        assert "SEC043" in self._ids("a.js", "res.redirect(req.query.next)")

    def test_sec044_ssti(self):
        assert "SEC044" in self._ids("a.py", "render_template_string(user_tpl)")

    def test_sec045_extractall(self):
        assert "SEC045" in self._ids("a.py", "tar.extractall(path)")

    def test_sec046_missing_timeout(self):
        assert "SEC046" in self._ids("a.py", "requests.get(url)")

    def test_sec046_with_timeout_ok(self):
        assert "SEC046" not in self._ids("a.py", "requests.get(url, timeout=5)")

    def test_sec047_curl_insecure(self):
        assert "SEC047" in self._ids("a.sh", "curl -k https://x.example.com")

    def test_sec047_curl_normal_ok(self):
        assert "SEC047" not in self._ids("a.sh", "curl https://x.example.com")

    def test_sec040_python_0o777(self):
        assert "SEC040" in self._ids("a.py", "os.chmod(p, 0o777)")

    def test_sec075_add_remote_url(self):
        assert "SEC075" in self._ids("Dockerfile", "ADD https://x.example.com/app.tgz /app")

    def test_sec075_copy_ok(self):
        assert "SEC075" not in self._ids("Dockerfile", "COPY app.tgz /app")

    def test_sec076_user_root(self):
        assert "SEC076" in self._ids("Dockerfile", "USER root")

    def test_sec076_non_root_ok(self):
        assert "SEC076" not in self._ids("Dockerfile", "USER app")

    def test_rule_catalog_lists_all_new_rules(self):
        ids = {rid for rid, _t, _s in code.all_rules()}
        for rid in ("SEC043", "SEC044", "SEC045", "SEC046", "SEC047", "SEC075", "SEC076"):
            assert rid in ids
        secret_ids = {r.rule_id for r in secrets_mod.SECRET_RULES}
        for rid in ("SEC016", "SEC017", "SEC018", "SEC019"):
            assert rid in secret_ids


# --------------------------------------------------------------------------- #
# GitHub annotations                                                           #
# --------------------------------------------------------------------------- #

def _finding(**kw) -> Finding:
    base = dict(rule_id="SEC020", title="eval() on dynamic input",
                severity=Severity.HIGH, message="eval on input",
                path="app.py", line=3, evidence="eval(x)", scanner="code")
    base.update(kw)
    return Finding(**base)


def _result(findings: list[Finding], suppressed: int = 0):
    return engine.ScanResult(root=Path("."), findings=findings, suppressed=suppressed)


class TestGithubAnnotations:
    def test_error_for_high(self):
        out = render_github(_result([_finding()]))
        assert out.startswith("::error file=app.py,line=3,title=SEC020")

    def test_warning_for_medium(self):
        out = render_github(_result([_finding(severity=Severity.MEDIUM)]))
        assert out.startswith("::warning ")

    def test_file_level_omits_line(self):
        out = render_github(_result([_finding(line=0)]))
        assert "line=" not in out
        assert "file=app.py" in out

    def test_message_includes_evidence_and_escape(self):
        f = _finding(message="50% bad\ncode", evidence="ev")
        out = render_github(_result([f]))
        assert "%25" in out and "%0A" in out
        assert "bad%0Acode" in out

    def test_no_findings_notice(self):
        assert render_github(_result([])).startswith("::notice::sentinel: no findings")

    def test_registered_renderer(self):
        from sentinel.report import RENDERERS
        assert "github" in RENDERERS


# --------------------------------------------------------------------------- #
# stable fingerprints + SARIF                                                  #
# --------------------------------------------------------------------------- #

class TestStableFingerprint:
    def test_line_shift_invariant(self):
        a = _finding(line=3)
        b = _finding(line=99)
        assert a.stable_fingerprint() == b.stable_fingerprint()

    def test_fingerprint_still_line_sensitive(self):
        # the allow-id must stay unique per line — the two ids differ
        assert _finding(line=3).fingerprint() != _finding(line=99).fingerprint()

    def test_different_evidence_differs(self):
        assert _finding(evidence="eval(x)").stable_fingerprint() != \
            _finding(evidence="eval(y)").stable_fingerprint()

    def test_sarif_carries_partial_fingerprints(self):
        payload = json.loads(render_sarif(_result([_finding()])))
        result = payload["runs"][0]["results"][0]
        assert result["partialFingerprints"]["sentinelStable/v1"] == \
            _finding().stable_fingerprint()


# --------------------------------------------------------------------------- #
# sentinel diff                                                                #
# --------------------------------------------------------------------------- #

class TestDiff:
    def test_moved_finding_is_unchanged(self):
        old = {_stable_id("SEC020", "a.py", "eval(x)"): _finding(line=3)}
        new = {_stable_id("SEC020", "a.py", "eval(x)"): _finding(line=9)}
        d = diff_reports(old, new)
        assert d.added == [] and d.removed == [] and d.unchanged == 1

    def test_new_and_resolved(self):
        old = {_stable_id("SEC020", "a.py", "eval(x)"): _finding()}
        new = {_stable_id("SEC021", "b.py", "exec(y)"):
               _finding(rule_id="SEC021", path="b.py", evidence="exec(y)", severity=Severity.LOW)}
        d = diff_reports(old, new)
        assert len(d.added) == 1 and len(d.removed) == 1 and d.unchanged == 0

    def test_render_diff_mentions_counts(self):
        d = diff_reports({}, {_stable_id("SEC020", "a.py", "eval(x)"): _finding()})
        text = render_diff(d)
        assert "1 new" in text and "NEW FINDINGS" in text

    def test_load_sarif_roundtrip(self, tmp_path: Path):
        sarif = tmp_path / "r.sarif"
        sarif.write_text(render_sarif(_result([_finding()])), encoding="utf-8")
        loaded = load_report_findings(sarif)
        assert _finding().stable_fingerprint() in loaded

    def test_load_json_roundtrip(self, tmp_path: Path):
        from sentinel.report import render_json
        p = tmp_path / "r.json"
        p.write_text(render_json(_result([_finding()])), encoding="utf-8")
        loaded = load_report_findings(p)
        assert _finding().stable_fingerprint() in loaded

    def test_bad_file_raises(self, tmp_path: Path):
        p = tmp_path / "bad.sarif"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_report_findings(p)

    def test_unrecognised_shape_raises(self, tmp_path: Path):
        p = tmp_path / "x.json"
        p.write_text('{"hello": 1}', encoding="utf-8")
        with pytest.raises(ValueError):
            load_report_findings(p)


class TestDiffCli:
    def _write_pair(self, tmp_path: Path, new_findings: list[Finding]) -> tuple[Path, Path]:
        from sentinel.report import render_json
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(render_json(_result([])), encoding="utf-8")
        new.write_text(render_json(_result(new_findings)), encoding="utf-8")
        return old, new

    def test_exit_1_on_new_high(self, tmp_path: Path, capsys):
        from sentinel.cli import main
        old, new = self._write_pair(tmp_path, [_finding(severity=Severity.HIGH)])
        assert main(["diff", str(old), str(new)]) == 1
        assert "1 new" in capsys.readouterr().out

    def test_exit_0_when_only_removed(self, tmp_path: Path):
        from sentinel.cli import main
        from sentinel.report import render_json
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(render_json(_result([_finding()])), encoding="utf-8")
        new.write_text(render_json(_result([])), encoding="utf-8")
        assert main(["diff", str(old), str(new)]) == 0

    def test_fail_on_never(self, tmp_path: Path):
        from sentinel.cli import main
        old, new = self._write_pair(tmp_path, [_finding(severity=Severity.CRITICAL)])
        assert main(["diff", str(old), str(new), "--fail-on", "never"]) == 0

    def test_fail_on_low_catches_low(self, tmp_path: Path):
        from sentinel.cli import main
        old, new = self._write_pair(
            tmp_path, [_finding(severity=Severity.LOW)])
        assert main(["diff", str(old), str(new), "--fail-on", "low"]) == 1
        assert main(["diff", str(old), str(new), "--fail-on", "medium"]) == 0

    def test_bad_report_is_usage_error(self, tmp_path: Path):
        from sentinel.cli import main
        bad = tmp_path / "bad.json"
        bad.write_text("[]", encoding="utf-8")
        assert main(["diff", str(bad), str(bad)]) == 2

    def test_json_output(self, tmp_path: Path, capsys):
        from sentinel.cli import main
        old, new = self._write_pair(tmp_path, [_finding()])
        assert main(["diff", str(old), str(new), "-f", "json", "--fail-on", "never"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["added"][0]["rule_id"] == "SEC020"
        assert payload["unchanged"] == 0


# --------------------------------------------------------------------------- #
# github format via scan CLI                                                   #
# --------------------------------------------------------------------------- #

class TestGithubFormatCli:
    def test_scan_github_format(self, tmp_path: Path, capsys):
        from sentinel.cli import main
        (tmp_path / "app.py").write_text('password = "abcdefghijklmnop"\n', encoding="utf-8")
        rc = main(["scan", str(tmp_path), "-f", "github", "--fail-on", "never",
                   "--no-git", "--no-deps"])
        assert rc == 0
        # SEC014 (HIGH) → ::error annotation
        assert "::error file=app.py" in capsys.readouterr().out
