"""Report renderers: console, json, markdown, html, SARIF 2.1.0,
JUnit XML, GitLab Code Quality, HTML entity and NO_COLOR edge cases."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sentinel.engine import ScanResult
from sentinel.models import Finding, Severity
from sentinel.report import (
    _html,
    render_console,
    render_gitlab,
    render_html,
    render_json,
    render_junit,
    render_markdown,
    render_sarif,
    write_report,
)


def _finding(rule_id="SEC020", severity=Severity.HIGH, path="app.py", line=3,
             scanner="code", evidence="eval(user_input)", title="Unsafe eval"):
    return Finding(
        rule_id=rule_id, title=title, severity=severity,
        message="eval() on dynamic input", path=path, line=line,
        evidence=evidence, fix="Use ast.literal_eval", cwe="CWE-95",
        confidence="high", scanner=scanner)


def _result(findings=None):
    fs = findings if findings is not None else [_finding()]
    return ScanResult(root=Path("."), findings=fs, files_scanned=2, files_skipped=1)


class TestConsole:
    def test_shows_score_and_rule(self):
        out = render_console(_result(), show_evidence=False)
        assert "SCORE" in out and "90/100" in out
        assert "HIGH" in out and "SEC020" in out

    def test_no_ansi_when_no_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        out = render_console(_result())
        assert "\033[" not in out

    def test_evidence_shown_by_default(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert "eval(user_input)" in render_console(_result())

    def test_evidence_hidden_when_disabled(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert "eval(user_input)" not in render_console(_result(), show_evidence=False)

    def test_empty_scan_message(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        out = render_console(_result([]))
        assert "no findings" in out.lower()


class TestJson:
    def test_valid_json_with_all_keys(self):
        data = json.loads(render_json(_result()))
        assert data["score"] == 90
        assert data["grade"] == "A"
        assert data["files_scanned"] == 2
        assert data["findings"][0]["rule_id"] == "SEC020"
        assert data["counts"]["HIGH"] == 1
        assert data["tool"]["name"] == "sentinel"

    def test_severity_serialized_as_name(self):
        data = json.loads(render_json(_result()))
        assert data["findings"][0]["severity"] == "HIGH"

    def test_roundtrip_stable(self):
        data = json.loads(render_json(_result()))
        again = json.loads(json.dumps(data))
        assert again == data


class TestMarkdown:
    def test_contains_rule_and_score(self):
        md = render_markdown(_result())
        assert "SEC020" in md
        assert "90" in md
        assert "| HIGH | `SEC020` |" in md

    def test_empty_scan(self):
        md = render_markdown(_result([]))
        assert "No findings" in md

    def test_pipe_in_title_escaped(self):
        f = _finding(title="Bad | thing")
        md = render_markdown(_result([f]))
        assert "Bad \\| thing" in md


class TestHtml:
    def test_single_file_contains_grade_and_rule(self):
        html = render_html(_result())
        assert html.lower().startswith("<!doctype html")
        assert "SEC020" in html
        assert "grade a" in html.lower()
        assert "eval(user_input)" in html

    def test_escapes_evidence(self):
        html = render_html(_result([_finding(evidence="<script>alert(1)</script>")]))
        assert "<script>alert(1)" not in html
        assert "&lt;script&gt;" in html


class TestSarif:
    def test_sarif210_shape(self):
        doc = json.loads(render_sarif(_result()))
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
        run = doc["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"] == "sentinel"
        assert any(r["id"] == "SEC020" for r in driver["rules"])
        res = run["results"][0]
        assert res["ruleId"] == "SEC020"
        assert res["level"] == "error"  # HIGH -> error

    def test_level_mapping(self):
        assert _sarif_level(Severity.CRITICAL) == "error"
        assert _sarif_level(Severity.HIGH) == "error"
        assert _sarif_level(Severity.MEDIUM) == "warning"
        assert _sarif_level(Severity.LOW) == "note"
        assert _sarif_level(Severity.INFO) == "note"

    def test_location_and_security_severity(self):
        doc = json.loads(render_sarif(_result()))
        res = doc["runs"][0]["results"][0]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "8.0"  # HIGH

    def test_critical_security_severity(self):
        doc = json.loads(render_sarif(_result([_finding(severity=Severity.CRITICAL)])))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "9.5"


def _sarif_level(sev: Severity) -> str:
    doc = json.loads(render_sarif(_result([_finding(severity=sev)])))
    return doc["runs"][0]["results"][0]["level"]


class TestJUnitControlChars:
    def test_illegal_control_chars_do_not_break_xml(self):
        f = _finding(evidence="bad \x00\x1b\x0b\x0c chars")
        root = ET.fromstring(render_junit(_result([f])))  # must not ParseError
        assert root.tag == "testsuites"
        failure = root.find("testsuite/testcase/failure")
        assert failure is not None
        body = failure.text or ""
        for ch in ("\x00", "\x1b", "\x0b", "\x0c"):
            assert ch not in body
        assert "bad" in body and "chars" in body  # content kept

    def test_legal_whitespace_preserved(self):
        f = _finding(evidence="line1\nline2\ttab\r")
        root = ET.fromstring(render_junit(_result([f])))
        body = root.find("testsuite/testcase/failure").text or ""
        assert "line1\nline2\ttab" in body

    def test_control_chars_in_path_and_title_stripped(self):
        f = _finding(path="we\x00ird.py", title="ti\x1btle")
        root = ET.fromstring(render_junit(_result([f])))
        case = root.find("testsuite/testcase")
        assert "\x00" not in (case.get("name") or "")


class TestGitlabSeverity:
    def test_all_severities_in_gitlab_enum(self):
        sev_findings = [
            _finding(severity=sev, path=f"p{i}.py", line=i + 1)
            for i, sev in enumerate(
                [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO])
        ]
        out = json.loads(render_gitlab(_result(sev_findings)))
        allowed = {"info", "minor", "major", "critical", "blocker"}
        assert len(out) == 5
        assert all(i["severity"] in allowed for i in out)
        assert [i["severity"] for i in out] == [
            "blocker", "major", "minor", "info", "info"]


class TestHtmlEntities:
    def test_escapes_apostrophe(self):
        assert _html("it's") == "it&#39;s"
        assert "'" not in _html("don't <b>'</b>")

    def test_escapes_in_rendered_html(self):
        html = render_html(_result([_finding(title="it's bad")]))
        assert "it&#39;s bad" in html
        assert "it's bad" not in html


class TestMarkdownPathPipe:
    def test_pipe_in_path_escaped_single_row(self):
        f = _finding(path="dir|evil.py")
        md = render_markdown(_result([f]))
        assert "dir\\|evil.py" in md
        rows = [ln for ln in md.splitlines()
                if ln.startswith("|") and "SEC020" in ln]
        assert len(rows) == 1
        assert rows[0].count("`") == 4  # path cell intact, not split by the pipe


class TestNoColorPresence:
    def test_empty_no_color_disables_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        out = render_console(_result())
        assert "\033[" not in out


class TestWriteReportDashOutput:
    def test_dash_output_raises(self):
        with pytest.raises(ValueError, match="not supported"):
            write_report("json", _result(), "-")
