"""Report renderers: console, json, markdown, html, SARIF 2.1.0."""

import json
from pathlib import Path

from sentinel.engine import ScanResult
from sentinel.models import Finding, Severity
from sentinel.report import render_console, render_html, render_json, render_markdown, render_sarif


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
