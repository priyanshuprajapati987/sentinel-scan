"""v0.6.0 — PHP/C# SAST rules, multi-ecosystem pin hygiene."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from sentinel.rules import code, deps


def _ids(path: str, line: str) -> list[str]:
    return [h.rule_id for h in code.scan_text(path, line)]


# --------------------------------------------------------------------------- #
# PHP                                                                          #
# --------------------------------------------------------------------------- #

class TestPhpRules:
    def test_sec020_covers_php_eval(self):
        assert "SEC020" in _ids("a.php", "eval($_POST['x']);")

    def test_sec077_unserialize(self):
        assert "SEC077" in _ids("a.php", "$data = unserialize($_COOKIE['d']);")

    def test_sec077_json_ok(self):
        assert "SEC077" not in _ids("a.php", "$data = json_decode($input);")

    def test_sec078_system(self):
        assert "SEC078" in _ids("a.php", "system($cmd);")

    def test_sec078_shell_exec(self):
        assert "SEC078" in _ids("a.php", "shell_exec($cmd);")

    def test_sec078_passthru(self):
        assert "SEC078" in _ids("a.php", "passthru($cmd);")

    def test_sec078_echo_ok(self):
        assert "SEC078" not in _ids("a.php", "echo htmlspecialchars($x);")

    def test_sec079_mysql_query(self):
        assert "SEC079" in _ids("a.php", "mysql_query($q);")

    def test_sec080_preg_replace_e(self):
        assert "SEC080" in _ids("a.php", 'preg_replace("/pattern/e", $repl, $sub);')

    def test_sec080_normal_repl_ok(self):
        assert "SEC080" not in _ids("a.php", 'preg_replace("/pattern/", $repl, $sub);')

    def test_sec081_extract_get(self):
        assert "SEC081" in _ids("a.php", "extract($_GET);")

    def test_sec081_extract_local_ok(self):
        assert "SEC081" not in _ids("a.php", "extract($options);")

    def test_sec082_md5(self):
        assert "SEC082" in _ids("a.php", "$h = md5($password);")

    def test_sec082_sha1(self):
        assert "SEC082" in _ids("a.php", "$h = sha1($password);")

    def test_sec082_password_hash_ok(self):
        assert "SEC082" not in _ids(
            "a.php", "$h = password_hash($password, PASSWORD_DEFAULT);")


# --------------------------------------------------------------------------- #
# C#                                                                           #
# --------------------------------------------------------------------------- #

class TestCSharpRules:
    def test_sec083_sql_concat(self):
        assert "SEC083" in _ids(
            "a.cs", 'var cmd = new SqlCommand("SELECT * FROM t WHERE id=" + id);')

    def test_sec083_parameterized_ok(self):
        assert "SEC083" not in _ids(
            "a.cs", 'var cmd = new SqlCommand("SELECT * FROM t WHERE id=@id", conn);')

    def test_sec084_cmd_exe(self):
        assert "SEC084" in _ids("a.cs", 'Process.Start("cmd.exe", "/c " + args);')

    def test_sec084_powershell_filename(self):
        assert "SEC084" in _ids(
            "a.cs", 'var psi = new ProcessStartInfo { FileName = "powershell.exe" };')

    def test_sec084_direct_binary_ok(self):
        assert "SEC084" not in _ids("a.cs", 'Process.Start("git", "status");')

    def test_sec085_des(self):
        assert "SEC085" in _ids("a.cs", "var aes = new DESCryptoServiceProvider();")

    def test_sec085_md5_provider(self):
        assert "SEC085" in _ids("a.cs", "var md5 = new MD5CryptoServiceProvider();")

    def test_sec085_aes_gcm_ok(self):
        assert "SEC085" not in _ids("a.cs", "using var aes = new AesGcm(key);")

    def test_sec086_binary_formatter(self):
        assert "SEC086" in _ids("a.cs", "var fmt = new BinaryFormatter();")

    def test_sec086_deserialize_via_formatter(self):
        assert "SEC086" in _ids(
            "a.cs", "obj = ((BinaryFormatter)fmt).Deserialize(stream);")

    def test_sec086_json_ok(self):
        assert "SEC086" not in _ids(
            "a.cs", "var obj = JsonSerializer.Deserialize<MyType>(json);")


# --------------------------------------------------------------------------- #
# Multi-ecosystem pin hygiene (SEC060)                                         #
# --------------------------------------------------------------------------- #

class TestPinHygieneEcosystems:
    def _scan(self, files: dict[str, str]):
        with TemporaryDirectory() as td:
            root = Path(td)
            for name, content in files.items():
                (root / name).write_text(content, encoding="utf-8")
            return deps.scan_pin_hygiene(root)

    def test_gemfile_unpinned(self):
        out = self._scan({"Gemfile": "gem 'rails'\n"})
        hits = [f for f in out if f.path == "Gemfile"]
        assert len(hits) == 1
        assert "rails" in hits[0].message

    def test_gemfile_pinned_ok(self):
        out = self._scan({"Gemfile": "gem 'puma', '~> 6.0'\n"})
        assert not [f for f in out if f.path == "Gemfile"]

    def test_composer_star_constraint(self):
        out = self._scan({"composer.json": '{"require": {"monolog/monolog": "*"}}'})
        hits = [f for f in out if f.path == "composer.json"]
        assert len(hits) == 1 and "monolog" in hits[0].message

    def test_composer_platform_req_skipped(self):
        out = self._scan({"composer.json": '{"require": {"php": ">=8.1", "ext-json": "*"}}'})
        assert not [f for f in out if f.path == "composer.json"]

    def test_composer_bounded_range_ok(self):
        out = self._scan({"composer.json": '{"require": {"symfony/console": "^6.0"}}'})
        assert not [f for f in out if f.path == "composer.json"]

    def test_pom_latest(self):
        out = self._scan({"pom.xml": "<version>LATEST</version>"})
        hits = [f for f in out if f.path == "pom.xml"]
        assert len(hits) == 1 and "LATEST" in hits[0].message

    def test_pom_exact_version_ok(self):
        out = self._scan({"pom.xml": "<version>1.2.3</version>"})
        assert not [f for f in out if f.path == "pom.xml"]


# --------------------------------------------------------------------------- #
# catalog                                                                      #
# --------------------------------------------------------------------------- #

class TestCatalogV060:
    def test_catalog_lists_new_rules(self):
        ids = {rid for rid, _t, _s in code.all_rules()}
        for rid in ("SEC077", "SEC078", "SEC079", "SEC080", "SEC081",
                    "SEC082", "SEC083", "SEC084", "SEC085", "SEC086"):
            assert rid in ids
