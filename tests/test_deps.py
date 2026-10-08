"""Dependency scanning: pin hygiene + graceful CVE degradation."""

import json

from sentinel.models import Severity
from sentinel.rules import deps


class TestPinHygiene:
    def test_unpinned_requirement_flagged_with_line(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "flask==3.0.0\nrequests\nnumpy>=1.26\n", encoding="utf-8")
        hits = deps.scan_pin_hygiene(tmp_path)
        assert len(hits) == 1
        assert hits[0].rule_id == "SEC060"
        assert hits[0].line == 2
        assert "requests" in hits[0].message

    def test_all_pinned_no_findings(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests==2.32.0\n",
                                                   encoding="utf-8")
        assert deps.scan_pin_hygiene(tmp_path) == []

    def test_comments_and_flags_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "# comment\n-r base.txt\n-e .\nflask==3.0.0\n", encoding="utf-8")
        assert deps.scan_pin_hygiene(tmp_path) == []

    def test_floating_npm_range_flagged(self, tmp_path):
        (tmp_path / "package.json").write_text(json.dumps({
            "dependencies": {"react": "^18.2.0", "left-pad": "*"},
        }), encoding="utf-8")
        hits = deps.scan_pin_hygiene(tmp_path)
        assert any("left-pad" in h.message for h in hits)
        assert not any(h.message.startswith("react ") for h in hits)


class TestCveGraceful:
    def test_missing_tools_degrade_to_info_note(self, tmp_path, monkeypatch):
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        findings = deps.scan(tmp_path, cves=True)
        notes = [f for f in findings if f.rule_id == "DEPS-SKIP"]
        assert len(notes) == 1
        assert notes[0].severity is Severity.INFO
        assert "pip-audit" in notes[0].message

    def test_no_requirements_no_package_json_still_returns_note(self, tmp_path, monkeypatch):
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        findings = deps.scan(tmp_path, cves=True)
        assert any(f.rule_id == "DEPS-SKIP" for f in findings)

    def test_cves_disabled_returns_no_note(self, tmp_path, monkeypatch):
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        findings = deps.scan(tmp_path, cves=False)
        assert not any(f.rule_id == "DEPS-SKIP" for f in findings)

    def test_pip_audit_output_parsed(self, tmp_path, monkeypatch):
        payload = json.dumps([{
            "id": "CVE-2024-9999",
            "dependencies": [{"name": "requests", "version": "2.0.0"}],
            "fix_versions": ["2.32.4"],
        }])
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        (tmp_path / "requirements.txt").write_text("requests==2.0.0\n", encoding="utf-8")
        hits = [f for f in deps.scan(tmp_path) if f.rule_id == "SEC061"]
        assert len(hits) == 1
        assert "CVE-2024-9999" in hits[0].message
        assert "2.32.4" in hits[0].fix

    def test_npm_audit_output_parsed(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        payload = json.dumps({"vulnerabilities": {
            "lodash": {"severity": "high", "via": [{"title": "Prototype pollution",
                                                    "url": "https://x/CVE"}]},
        }})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        hits = [f for f in deps.scan(tmp_path) if f.rule_id == "SEC062"]
        assert len(hits) == 1
        assert hits[0].severity is Severity.HIGH
