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
        # concrete fixture assertions: only left-pad ('*') floats; ^18.2.0 carries
        # a digit and is treated as pinned -> exactly one SEC060 finding.
        assert len(hits) == 1
        assert hits[0].rule_id == "SEC060"
        assert hits[0].path == "package.json"
        assert "left-pad" in hits[0].message
        assert not any("react" in h.message for h in hits)


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


class TestManifestRobustness:
    """#1: non-dict package.json/composer.json must not crash other checks."""

    def test_array_package_json_notes_and_gemfile_still_runs(self, tmp_path, monkeypatch):
        (tmp_path / "package.json").write_text("[]", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        (tmp_path / "Gemfile").write_text("gem 'rails'\n", encoding="utf-8")
        findings = deps.scan(tmp_path, cves=True)
        notes = [f for f in findings if f.rule_id == "DEPS-SKIP"]
        assert any("package.json" in n.message for n in notes)
        assert any(f.rule_id == "SEC060" and "rails" in f.message for f in findings)

    def test_package_json_dependencies_as_list_notes_and_continues(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps({"dependencies": ["react"]}), encoding="utf-8")
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        findings = deps.scan_pin_hygiene(tmp_path)
        assert not any(f.rule_id == "SEC060" for f in findings)

    def test_array_composer_json_notes_and_gemfile_still_runs(self, tmp_path, monkeypatch):
        (tmp_path / "composer.json").write_text("[]", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: None)
        (tmp_path / "Gemfile").write_text("gem 'rails'\n", encoding="utf-8")
        findings = deps.scan(tmp_path, cves=True)
        notes = [f for f in findings if f.rule_id == "DEPS-SKIP"]
        assert any("composer.json" in n.message for n in notes)
        assert any(f.rule_id == "SEC060" and "rails" in f.message for f in findings)

    def test_composer_non_dict_section_ignored(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"require": ["php"]}), encoding="utf-8")
        assert deps.scan_pin_hygiene(tmp_path) == []


class TestRequirementsParsing:
    """#6: env markers + URL requirement lines."""

    def test_env_marker_only_line_unpinned(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "flask==3.0.0 ; python_version >= '3.11'\nrequests; sys_platform == 'win32'\n",
            encoding="utf-8")
        hits = deps.scan_pin_hygiene(tmp_path)
        assert len(hits) == 1
        assert hits[0].line == 2
        assert "requests" in hits[0].message

    def test_env_marker_with_pin_is_clean(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "requests==2.32.0 ; sys_platform == 'win32'\n", encoding="utf-8")
        assert deps.scan_pin_hygiene(tmp_path) == []

    def test_url_requirement_lines_skipped(self, tmp_path):
        (tmp_path / "requirements.txt").write_text(
            "git+https://github.com/x/y.git\n"
            "https://example.com/pkg.tar.gz\n"
            "-e .\n", encoding="utf-8")
        assert deps.scan_pin_hygiene(tmp_path) == []

    def test_requirements_dev_and_subdir_scanned(self, tmp_path, monkeypatch):
        (tmp_path / "requirements-dev.txt").write_text("black\n", encoding="utf-8")
        sub = tmp_path / "requirements"
        sub.mkdir()
        (sub / "prod.txt").write_text("uvicorn\n", encoding="utf-8")
        seen: list[list[str]] = []
        monkeypatch.setattr(deps, "_run", lambda cmd, *a, **k: seen.append(list(cmd)) or "[]")
        deps.scan_cves(tmp_path)
        flat = [" ".join(c) for c in seen]
        assert any("requirements-dev.txt" in f for f in flat)
        assert any("requirements/prod.txt" in f for f in flat)
        # empty list [] = valid pip-audit shape -> ran cleanly, no note
        assert not any(f.rule_id == "DEPS-SKIP" for f in deps.scan_cves(tmp_path))


class TestGemfileParsing:
    """#7: version positionals count, option kwargs must not."""

    def test_positional_version_pinned_kwarg_only_unpinned(self, tmp_path):
        (tmp_path / "Gemfile").write_text(
            "gem 'rails'\n"
            "gem 'puma', '~> 6.0'\n"
            "gem 'dotenv', require: false\n"
            "gem 'rack', :git => 'https://example.com/rack.git'\n"
            "gem 'nokogiri', '1.15.0'\n", encoding="utf-8")
        hits = deps.scan_pin_hygiene(tmp_path)
        flagged = [h.message for h in hits if h.rule_id == "SEC060"]
        # kwarg-only lines (`require:`, `:git =>`) carry NO version -> unpinned;
        # only a positional second arg pins (puma/nokogiri stay clean).
        assert len(flagged) == 3
        assert any("rails" in m for m in flagged)
        assert any("dotenv" in m for m in flagged)
        assert any("rack" in m for m in flagged)
        assert not any("puma" in m for m in flagged)
        assert not any("nokogiri" in m for m in flagged)

    def test_probe_gemfile_matrix(self, tmp_path):
        """The exact 7-line probe matrix (audit #7)."""
        cases = [
            ("gem 'rails'", "finding"),
            ("gem 'puma', '~> 6.0'", "clean"),
            ("gem 'x', '1.0'", "clean"),
            ("gem 'x', '1.0', require: false", "clean"),
            ("gem 'x', require: false", "finding"),
            ("gem 'x', github: 'a/b'", "finding"),
            ("gem 'x', '1.0', groups: [:dev]", "clean"),
        ]
        (tmp_path / "Gemfile").write_text(
            "\n".join(c for c, _ in cases) + "\n", encoding="utf-8")
        hits = {h.line for h in deps.scan_pin_hygiene(tmp_path) if h.path == "Gemfile"}
        for i, (_, expected) in enumerate(cases, 1):
            got = "finding" if i in hits else "clean"
            assert got == expected, f"line {i}: want {expected}, got {got}"


class TestCveSeverityMapping:
    """#3: npm severity labels must map, never collapse to HIGH."""

    def test_npm_severity_labels_map(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        payload = json.dumps({"vulnerabilities": {
            "a": {"severity": "critical"},
            "b": {"severity": "moderate"},
            "c": {"severity": "info"},
            "d": {"severity": "unknown-ish"},
            "e": {"severity": "low"},
            "f": {"severity": "high"},
            "g": {},
        }})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        hits = {f.evidence: f for f in deps.scan_cves(tmp_path)
                if f.rule_id == "SEC062"}
        assert hits["a"].severity is Severity.CRITICAL
        assert hits["b"].severity is Severity.MEDIUM   # moderate -> MEDIUM
        assert hits["c"].severity is Severity.INFO
        assert hits["d"].severity is Severity.MEDIUM   # unknown label -> honest default
        assert hits["e"].severity is Severity.LOW
        assert hits["f"].severity is Severity.HIGH
        assert hits["g"].severity is Severity.MEDIUM   # missing label -> MEDIUM

    def test_npm_non_dict_vuln_entry_skipped_no_crash(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        payload = json.dumps({"vulnerabilities": {"bad": "just-a-string"}})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        assert [f for f in deps.scan_cves(tmp_path) if f.rule_id == "SEC062"] == []
        assert not any(f.rule_id == "DEPS-SKIP" for f in deps.scan_cves(tmp_path))

    def test_pip_audit_severity_from_payload(self, tmp_path, monkeypatch):
        payload = json.dumps([
            {"id": "CVE-A", "severity": "MODERATE",
             "dependencies": [{"name": "flask", "version": "1.0"}]},
            {"id": "CVE-B", "cvss": 9.8,
             "dependencies": [{"name": "jinja2", "version": "2.0"}]},
            {"id": "CVE-C",
             "dependencies": [{"name": "click", "version": "8.0"}]},
        ])
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        (tmp_path / "requirements.txt").write_text("flask==1.0\n", encoding="utf-8")
        hits = [f for f in deps.scan_cves(tmp_path) if f.rule_id == "SEC061"]
        assert [h.severity for h in hits] == [
            Severity.MEDIUM, Severity.CRITICAL, Severity.HIGH]

    def test_pip_audit_cvss_dict_score_extracted(self, tmp_path, monkeypatch):
        payload = json.dumps([{"id": "CVE-D", "cvss": {"base_score": 7.5},
                               "dependencies": [{"name": "x", "version": "1"}]}])
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        (tmp_path / "requirements.txt").write_text("x==1\n", encoding="utf-8")
        hits = [f for f in deps.scan_cves(tmp_path) if f.rule_id == "SEC061"]
        assert hits and hits[0].severity is Severity.HIGH


class TestPipAuditModernFormat:
    """Current pip-audit emits {"dependencies":[{"name","version","vulns":[...]}]}
    — NOT a list. Reading it as malformed dropped every real CVE."""

    def test_modern_dict_parses_vulns_no_note(self, tmp_path, monkeypatch):
        payload = json.dumps({"dependencies": [
            {"name": "absl-py", "version": "2.5.0", "vulns": [
                {"id": "PYSEC-2026-3804", "fix_versions": ["2.6.0"],
                 "aliases": ["CVE-2026-69112"], "description": "x"}]},
            {"name": "clean-pkg", "version": "1.0", "vulns": []},
            {"name": "no-vulns-key", "version": "1.0"},
        ], "fixes": []})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        findings = deps.scan_cves(tmp_path)
        hits = [f for f in findings if f.rule_id == "SEC061"]
        assert len(hits) == 1
        assert "absl-py 2.5.0" in hits[0].message
        assert "PYSEC-2026-3804" in hits[0].message
        assert "2.6.0" in hits[0].fix
        # audit RAN with valid shape -> must NOT claim coverage skipped/clean
        assert not any(f.rule_id == "DEPS-SKIP" for f in findings)

    def test_modern_format_without_severity_defaults_high(self, tmp_path, monkeypatch):
        payload = json.dumps({"dependencies": [
            {"name": "accelerate", "version": "1.14.0", "vulns": [
                {"id": "CVE-2026-69112", "fix_versions": []}]},
        ], "fixes": []})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        (tmp_path / "requirements.txt").write_text("accelerate==1.14.0\n",
                                                   encoding="utf-8")
        hits = [f for f in deps.scan_cves(tmp_path) if f.rule_id == "SEC061"]
        assert hits and hits[0].severity is Severity.HIGH

    def test_modern_empty_deps_is_honest_zero_no_note(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            deps, "_run", lambda *a, **k: '{"dependencies": [], "fixes": []}')
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        findings = deps.scan_cves(tmp_path)
        assert not any(f.rule_id == "SEC061" for f in findings)
        assert not any(f.rule_id == "DEPS-SKIP" for f in findings)

    def test_modern_dict_with_string_dep_skipped_no_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            deps, "_run",
            lambda *a, **k: '{"dependencies": ["oops"], "fixes": []}')
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        findings = deps.scan_cves(tmp_path)
        assert not any(f.rule_id == "SEC061" for f in findings)
        assert not any(f.rule_id == "DEPS-SKIP" for f in findings)  # shape valid


class TestMalformedCveOutputs:
    """#4: unparsable tool output = visible note, never '0 vulnerabilities'."""

    def test_malformed_npm_json_skips_with_note_not_clean(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: "{not-json")
        findings = deps.scan_cves(tmp_path)
        notes = [f for f in findings if f.rule_id == "DEPS-SKIP"]
        assert len(notes) == 1
        assert "npm audit" in notes[0].message
        assert "not the expected JSON" in notes[0].message
        assert not any(f.rule_id == "SEC062" for f in findings)

    def test_wrong_shape_pip_audit_skips_with_note_not_clean(self, tmp_path, monkeypatch):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        # valid JSON but a dict (npm-style) — shape check, not just JSONDecodeError
        monkeypatch.setattr(deps, "_run", lambda *a, **k: '{"vulnerabilities": {}}')
        findings = deps.scan_cves(tmp_path)
        notes = [f for f in findings if f.rule_id == "DEPS-SKIP"]
        assert len(notes) == 1
        assert "pip-audit" in notes[0].message
        assert "not the expected JSON" in notes[0].message
        assert not any(f.rule_id == "SEC061" for f in findings)
        # parse_failed must suppress the generic "unavailable/offline" note
        assert not any("offline" in f.message for f in findings)

    def test_list_of_non_dicts_is_shape_failure(self, tmp_path, monkeypatch):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: '["not-a-vuln-object"]')
        findings = deps.scan_cves(tmp_path)
        assert any(f.rule_id == "DEPS-SKIP" and "not the expected JSON" in f.message
                   for f in findings)

    def test_empty_npm_vulns_is_honest_zero_with_no_note(self, tmp_path, monkeypatch):
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: '{"vulnerabilities": {}}')
        findings = deps.scan_cves(tmp_path)
        assert findings == []          # shape valid, genuinely 0 vulns

    def test_empty_pip_audit_list_is_honest_zero_with_no_note(self, tmp_path, monkeypatch):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        monkeypatch.setattr(deps, "_run", lambda *a, **k: "[]")
        findings = deps.scan_cves(tmp_path)
        assert findings == []


class TestPipAuditProjectMode:
    """pyproject fallback must audit the PROJECT's declared deps
    (`pip-audit .`), never the ambient environment — env CVEs are not this
    repo's dependencies and made self-scan results machine-dependent."""

    def test_pyproject_target_passes_project_path(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\n', encoding="utf-8")
        seen: list[list[str]] = []
        monkeypatch.setattr(
            deps, "_run",
            lambda cmd, *a, **k: seen.append(list(cmd)) or '{"dependencies": [], "fixes": []}')
        findings = deps.scan_cves(tmp_path)
        assert seen and seen[0][-1] == "."      # project_path, not bare env audit
        assert "-r" not in seen[0]
        assert len(seen) == 1                   # exactly one pip-audit invocation
        assert findings == []

    def test_requirements_targets_still_use_r_flag(self, tmp_path, monkeypatch):
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
        seen: list[list[str]] = []
        monkeypatch.setattr(
            deps, "_run",
            lambda cmd, *a, **k: seen.append(list(cmd)) or '{"dependencies": [], "fixes": []}')
        deps.scan_cves(tmp_path)
        assert seen and "-r" in seen[0] and seen[0][-1] == "requirements.txt"

    def test_project_mode_vulns_attribute_to_pyproject(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "x"\n', encoding="utf-8")
        payload = json.dumps({"dependencies": [
            {"name": "demo", "version": "1.0",
             "vulns": [{"id": "CVE-TEST-1", "severity": "high",
                        "fix_versions": ["1.1"]}]}], "fixes": []})
        monkeypatch.setattr(deps, "_run", lambda *a, **k: payload)
        hits = [f for f in deps.scan_cves(tmp_path) if f.rule_id == "SEC061"]
        assert len(hits) == 1
        assert hits[0].path == "pyproject.toml"
        assert hits[0].severity is Severity.HIGH
        assert hits[0].evidence == "CVE-TEST-1"
