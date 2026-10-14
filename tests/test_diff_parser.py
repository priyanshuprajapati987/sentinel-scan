"""Audit-fix tests: diff parser multiplicity, fail-closed malformed loads,
SARIF/JSON hardening, Severity.parse, stable_key title-reword, filter API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.diff import (
    DiffReport,
    _finding_from_json,
    _finding_from_sarif_result,
    diff_reports,
    load_report_findings,
)
from sentinel.models import Finding, Severity


def _json_finding(**kw) -> dict:
    base = {"rule_id": "SEC020", "title": "eval() on dynamic input",
            "severity": "HIGH", "message": "eval on input", "path": "a.py",
            "line": 3, "evidence": "eval(x)"}
    base.update(kw)
    return base


def _sarif_report(results: list) -> str:
    return json.dumps({"runs": [{"results": results}]})


def _json_report(findings: list) -> str:
    return json.dumps({"findings": findings})


def _sarif_result(**kw) -> dict:
    base = {
        "ruleId": "SEC020",
        "message": {"text": "eval on input"},
        "level": "warning",
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.py"},
            "region": {"startLine": 3}}}],
        "properties": {"severity": "HIGH", "title": "eval() on dynamic input"},
    }
    base.update(kw)
    return base


# --------------------------------------------------------------------------- #
# duplicate stable ids keep multiplicity (JSON + SARIF)                        #
# --------------------------------------------------------------------------- #

class TestDuplicateStableIds:
    def test_json_duplicate_counts_as_added(self, tmp_path: Path):
        # old: 1 finding @line3; new: same @line3 + same @line9 → exactly 1 added
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(_json_report([_json_finding(line=3)]), encoding="utf-8")
        new.write_text(_json_report([_json_finding(line=3),
                                     _json_finding(line=9)]), encoding="utf-8")
        d = diff_reports(load_report_findings(old), load_report_findings(new))
        assert len(d.added) == 1
        assert d.added[0].line == 9
        assert len(d.removed) == 0
        assert d.unchanged == 1

    def test_sarif_duplicate_counts_as_added(self, tmp_path: Path):
        old = tmp_path / "old.sarif"
        new = tmp_path / "new.sarif"
        old.write_text(_sarif_report([_sarif_result()]), encoding="utf-8")
        new.write_text(_sarif_report([
            _sarif_result(),
            _sarif_result(locations=[{"physicalLocation": {
                "artifactLocation": {"uri": "a.py"},
                "region": {"startLine": 9}}}]),
        ]), encoding="utf-8")
        d = diff_reports(load_report_findings(old), load_report_findings(new))
        assert len(d.added) == 1
        assert d.added[0].line == 9
        assert d.unchanged == 1

    def test_identical_reports_fully_unchanged(self, tmp_path: Path):
        report = _json_report([_json_finding(line=3), _json_finding(line=7)])
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(report, encoding="utf-8")
        new.write_text(report, encoding="utf-8")
        d = diff_reports(load_report_findings(old), load_report_findings(new))
        assert d.added == [] and d.removed == [] and d.unchanged == 2

    def test_moved_sole_finding_still_unchanged(self, tmp_path: Path):
        # key() differs by line, but same stable id + single occurrence
        # must stay "unchanged" (line-shift tolerance)
        old = tmp_path / "old.json"
        new = tmp_path / "new.json"
        old.write_text(_json_report([_json_finding(line=3)]), encoding="utf-8")
        new.write_text(_json_report([_json_finding(line=9)]), encoding="utf-8")
        d = diff_reports(load_report_findings(old), load_report_findings(new))
        assert d.added == [] and d.removed == [] and d.unchanged == 1


# --------------------------------------------------------------------------- #
# fail-closed: raw findings present but none parseable                         #
# --------------------------------------------------------------------------- #

class TestMalformedReports:
    def test_json_all_unparseable_raises(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text(_json_report([{"rule_id": "X", "line": "junk"},
                                   "not-even-a-dict"]), encoding="utf-8")
        with pytest.raises(ValueError, match="none parseable"):
            load_report_findings(p)

    def test_sarif_all_unparseable_raises(self, tmp_path: Path):
        p = tmp_path / "bad.sarif"
        p.write_text(_sarif_report([{"no_rule_id": True}]), encoding="utf-8")
        with pytest.raises(ValueError, match="none parseable"):
            load_report_findings(p)

    def test_empty_findings_list_is_ok(self, tmp_path: Path):
        p = tmp_path / "empty.json"
        p.write_text(_json_report([]), encoding="utf-8")
        assert load_report_findings(p) == {}


# --------------------------------------------------------------------------- #
# SARIF hardening                                                              #
# --------------------------------------------------------------------------- #

class TestSarifHardening:
    def test_plain_string_message_kept(self):
        parsed = _finding_from_sarif_result(
            _sarif_result(message="plain string message"))
        assert parsed is not None
        assert parsed[1].message == "plain string message"

    def test_properties_as_list_degrades_to_defaults(self):
        parsed = _finding_from_sarif_result(
            _sarif_result(properties=["severity", "HIGH"]))
        assert parsed is not None
        # properties not a dict → {} → level "warning" → MEDIUM
        assert parsed[1].severity is Severity.MEDIUM

    def test_startline_null_keeps_finding_line_zero(self):
        parsed = _finding_from_sarif_result(_sarif_result(locations=[
            {"physicalLocation": {
                "artifactLocation": {"uri": "a.py"},
                "region": {"startLine": None}}}]))
        assert parsed is not None
        assert parsed[1].line == 0

    def test_severity_trailing_whitespace_parsed(self):
        parsed = _finding_from_sarif_result(_sarif_result(
            properties={"severity": "critical ", "title": "t"}))
        assert parsed is not None
        assert parsed[1].severity is Severity.CRITICAL

    def test_malformed_item_skipped_not_raised(self):
        assert _finding_from_sarif_result({"ruleId": 42, "locations": "junk"}) is None
        assert _finding_from_sarif_result("not-a-dict") is None

    def test_report_count_preserved_with_hostile_items(self, tmp_path: Path):
        p = tmp_path / "mix.sarif"
        p.write_text(_sarif_report([
            _sarif_result(message="plain", properties={"severity": "critical "}),
            {"no_rule_id": True},  # skipped
            _sarif_result(),       # kept
        ]), encoding="utf-8")
        loaded = load_report_findings(p)
        assert sum(len(v) for v in loaded.values()) == 2
        assert any(f.severity is Severity.CRITICAL
                   for bucket in loaded.values() for f in bucket)


# --------------------------------------------------------------------------- #
# JSON hardening                                                               #
# --------------------------------------------------------------------------- #

class TestJsonHardening:
    def test_bad_line_item_skipped_good_kept(self, tmp_path: Path):
        p = tmp_path / "mix.json"
        p.write_text(_json_report([
            _json_finding(line="junk"),       # int("junk") → skipped
            _json_finding(line=5),            # kept
        ]), encoding="utf-8")
        loaded = load_report_findings(p)
        flat = [f for bucket in loaded.values() for f in bucket]
        assert len(flat) == 1
        assert flat[0].line == 5

    def test_unknown_severity_defaults_medium(self):
        parsed = _finding_from_json(_json_finding(severity="banana"))
        assert parsed is not None
        assert parsed[1].severity is Severity.MEDIUM


# --------------------------------------------------------------------------- #
# Severity.parse                                                               #
# --------------------------------------------------------------------------- #

class TestSeverityParse:
    def test_strips_whitespace(self):
        assert Severity.parse(" high ") is Severity.HIGH

    def test_mixed_case(self):
        assert Severity.parse("Critical") is Severity.CRITICAL

    def test_bool_rejected(self):
        with pytest.raises(ValueError, match="bool is not a severity"):
            Severity.parse(True)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# stable_key: evidence-less findings immune to title reword                    #
# --------------------------------------------------------------------------- #

class TestStableKeyTitleReword:
    def _eviless(self, title: str) -> Finding:
        return Finding(rule_id="SEC030", title=title, severity=Severity.HIGH,
                       message="m", path="app.py", line=1, evidence="  ")

    def test_title_reword_same_fingerprint(self):
        a = self._eviless("file-level: dangerous pattern")
        b = self._eviless("File level — hazardous thing detected!")
        assert a.stable_fingerprint() == b.stable_fingerprint()

    def test_evidence_still_discriminates(self):
        a = Finding(rule_id="SEC020", title="t", severity=Severity.HIGH,
                    message="m", path="a.py", evidence="eval(x)")
        b = Finding(rule_id="SEC020", title="t", severity=Severity.HIGH,
                    message="m", path="a.py", evidence="eval(y)")
        assert a.stable_fingerprint() != b.stable_fingerprint()


# --------------------------------------------------------------------------- #
# new_at_or_above                                                              #
# --------------------------------------------------------------------------- #

class TestNewAtOrAbove:
    def _finding(self, sev: Severity, line: int = 1) -> Finding:
        return Finding(rule_id="SEC020", title="t", severity=sev,
                       message="m", path="a.py", line=line)

    def test_filters_by_threshold(self):
        d = DiffReport(added=[self._finding(Severity.INFO),
                              self._finding(Severity.MEDIUM),
                              self._finding(Severity.HIGH, line=2),
                              self._finding(Severity.CRITICAL, line=3)])
        highs = d.new_at_or_above(Severity.HIGH)
        assert [f.severity for f in highs] == [Severity.HIGH, Severity.CRITICAL]

    def test_empty_added(self):
        assert DiffReport().new_at_or_above(Severity.LOW) == []
