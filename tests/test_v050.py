"""v0.5.0 — Go/Java/Ruby SAST rules, JUnit XML format."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from sentinel import engine
from sentinel.models import Finding, Severity
from sentinel.report import RENDERERS, render_junit, write_report
from sentinel.rules import code


def _finding(**kw) -> Finding:
    base = dict(rule_id="SEC020", title="eval() on dynamic input",
                severity=Severity.HIGH, message="eval on input",
                path="app.py", line=3, evidence="eval(x)", scanner="code",
                fix="use json.loads")
    base.update(kw)
    return Finding(**base)


def _result(findings: list[Finding] | None = None, suppressed: int = 0):
    return engine.ScanResult(root=Path("."), findings=findings or [], suppressed=suppressed)


# --------------------------------------------------------------------------- #
# JUnit XML                                                                    #
# --------------------------------------------------------------------------- #

class TestJunitFormat:
    def test_registered_renderer(self):
        assert "junit" in RENDERERS

    def test_well_formed_with_failures(self):
        root = ET.fromstring(render_junit(_result([_finding()])))
        assert root.tag == "testsuites"
        assert root.get("failures") == "1"
        suite = root.find("testsuite")
        assert suite is not None and suite.get("name") == "sentinel.SEC020"
        case = suite.find("testcase")
        assert case is not None
        assert case.get("name") == "app.py:3"
        assert case.get("classname") == "sentinel.SEC020"
        failure = case.find("failure")
        assert failure is not None
        assert "HIGH" in (failure.get("message") or "")
        assert "eval(x)" in (failure.text or "")
        assert "fix: use json.loads" in (failure.text or "")

    def test_groups_by_rule(self):
        root = ET.fromstring(render_junit(_result([
            _finding(), _finding(line=9), _finding(rule_id="SEC021", title="exec"),
        ])))
        assert root.get("tests") == "3"
        names = [s.get("name") for s in root.findall("testsuite")]
        assert names == ["sentinel.SEC020", "sentinel.SEC021"]

    def test_clean_scan_is_green_suite(self):
        root = ET.fromstring(render_junit(_result([])))
        assert root.get("failures") == "0"
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.get("failures") == "0"

    def test_special_chars_escaped(self):
        out = render_junit(_result([_finding(
            path='we"ird<>.py', evidence="<script>alert(1)</script>",
            message='a "quoted" <msg>')]))
        root = ET.fromstring(out)  # would raise if not well-formed
        case = root.find("testsuite/testcase")
        assert case is not None
        assert case.get("name") == 'we"ird<>.py:3'

    def test_file_level_location(self):
        root = ET.fromstring(render_junit(_result([_finding(line=0)])))
        case = root.find("testsuite/testcase")
        assert case is not None
        assert case.get("name") == "app.py"

    def test_write_report_dir_mapping(self, tmp_path: Path):
        write_report("junit", _result([_finding()]), str(tmp_path) + "/", quiet=True)
        assert (tmp_path / "junit.xml").exists()


# --------------------------------------------------------------------------- #
# Go rules                                                                     #
# --------------------------------------------------------------------------- #

class TestGoRules:
    def _ids(self, line: str) -> list[str]:
        return [h.rule_id for h in code.scan_text("a.go", line)]

    def test_sec058_sprintf_sql(self):
        assert "SEC058" in self._ids(
            'q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)')

    def test_sec058_query_string_concat(self):
        assert "SEC058" in self._ids(
            'rows, err := db.Query("SELECT * FROM t WHERE x = " + x)')

    def test_sec058_parameterized_ok(self):
        assert "SEC058" not in self._ids(
            'rows, err := db.Query("SELECT * FROM t WHERE id = ?", id)')

    def test_sec059_insecure_skip_verify(self):
        assert "SEC059" in self._ids("&tls.Config{InsecureSkipVerify: true}")

    def test_sec059_secure_config_ok(self):
        assert "SEC059" not in self._ids("&tls.Config{MinVersion: tls.VersionTLS12}")

    def test_sec063_go_shell(self):
        assert "SEC063" in self._ids('exec.Command("sh", "-c", cmd).Run()')


# --------------------------------------------------------------------------- #
# Java rules                                                                   #
# --------------------------------------------------------------------------- #

class TestJavaRules:
    def _ids(self, line: str) -> list[str]:
        return [h.rule_id for h in code.scan_text("a.java", line)]

    def test_sec063_java_shell(self):
        assert "SEC063" in self._ids(
            'Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});')

    def test_sec064_runtime_exec(self):
        assert "SEC064" in self._ids("Runtime.getRuntime().exec(userInput);")

    def test_sec064_process_builder(self):
        assert "SEC064" in self._ids("new ProcessBuilder(cmds).start();")

    def test_sec065_md5(self):
        assert "SEC065" in self._ids('MessageDigest.getInstance("MD5");')

    def test_sec065_sha1(self):
        assert "SEC065" in self._ids('MessageDigest.getInstance("SHA-1");')

    def test_sec065_sha256_ok(self):
        assert "SEC065" not in self._ids('MessageDigest.getInstance("SHA-256");')

    def test_sec066_des(self):
        assert "SEC066" in self._ids('Cipher.getInstance("DES");')

    def test_sec066_rc4(self):
        assert "SEC066" in self._ids('Cipher.getInstance("RC4");')

    def test_sec066_aes_gcm_ok(self):
        assert "SEC066" not in self._ids('Cipher.getInstance("AES/GCM/NoPadding");')

    def test_sec067_constructor(self):
        assert "SEC067" in self._ids(
            "ObjectInputStream ois = new ObjectInputStream(in);")

    def test_sec067_read_object(self):
        assert "SEC067" in self._ids("obj = ois.readObject();")

    def test_sec067_json_ok(self):
        assert "SEC067" not in self._ids("JSON.parse(userInput);")


# --------------------------------------------------------------------------- #
# Ruby rules                                                                   #
# --------------------------------------------------------------------------- #

class TestRubyRules:
    def _ids(self, line: str) -> list[str]:
        return [h.rule_id for h in code.scan_text("a.rb", line)]

    def test_sec068_yaml_load(self):
        assert "SEC068" in self._ids("data = YAML.load(params[:data])")

    def test_sec068_safe_load_ok(self):
        assert "SEC068" not in self._ids("data = YAML.safe_load(params[:data])")

    def test_sec069_system_interpolation(self):
        assert "SEC069" in self._ids('system("ls #{dir}")')

    def test_sec069_backtick_interpolation(self):
        assert "SEC069" in self._ids("puts `git log #{ref}`")

    def test_sec069_open3(self):
        assert "SEC069" in self._ids('Open3.capture2("grep #{pattern} file")')

    def test_sec069_argv_ok(self):
        assert "SEC069" not in self._ids('system("ls", "-la", dir)')

    def test_sec020_covers_ruby_eval(self):
        assert "SEC020" in self._ids("eval(params[:code])")

    def test_sec021_covers_ruby_exec(self):
        assert "SEC021" in self._ids("exec(user_command)")


# --------------------------------------------------------------------------- #
# catalog                                                                      #
# --------------------------------------------------------------------------- #

class TestCatalogV050:
    def test_catalog_lists_new_rules(self):
        ids = {rid for rid, _t, _s in code.all_rules()}
        for rid in ("SEC058", "SEC059", "SEC063", "SEC064", "SEC065",
                    "SEC066", "SEC067", "SEC068", "SEC069"):
            assert rid in ids

    def test_rule_count_is_76(self):
        from sentinel.cli import _catalog
        assert len(_catalog()) == 76
