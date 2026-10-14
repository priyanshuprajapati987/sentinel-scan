"""v0.7.0 — C/C++ SAST rules (SEC087-091), mktemp/tmpnam extension, `sentinel explain`."""

from __future__ import annotations

from sentinel import cli
from sentinel.rules import code


def _ids(path: str, line: str) -> list[str]:
    return [h.rule_id for h in code.scan_text(path, line)]


# --------------------------------------------------------------------------- #
# C / C++ rules                                                                 #
# --------------------------------------------------------------------------- #

class TestNativeRules:
    def test_sec087_gets(self):
        assert "SEC087" in _ids("a.c", "gets(buf);")

    def test_sec087_fgets_ok(self):
        assert "SEC087" not in _ids("a.c", "fgets(buf, sizeof(buf), stdin);")

    def test_sec087_only_native_files(self):
        assert "SEC087" not in _ids("a.py", "gets(buf);")

    def test_sec088_strcpy(self):
        assert "SEC088" in _ids("a.cpp", "strcpy(dst, src);")

    def test_sec088_strcat(self):
        assert "SEC088" in _ids("a.c", "strcat(a, b);")

    def test_sec088_strncpy_ok(self):
        assert "SEC088" not in _ids("a.c", "strncpy(dst, src, n);")

    def test_sec088_strncat_ok(self):
        assert "SEC088" not in _ids("a.c", "strncat(a, b, n);")

    def test_sec089_sprintf(self):
        assert "SEC089" in _ids("a.c", 'sprintf(buf, "%s", x);')

    def test_sec089_vsprintf(self):
        assert "SEC089" in _ids("a.c", "vsprintf(buf, fmt, ap);")

    def test_sec089_snprintf_ok(self):
        assert "SEC089" not in _ids("a.c", 'snprintf(buf, n, "%s", x);')

    def test_sec090_system(self):
        assert "SEC090" in _ids("a.cpp", "system(cmd);")

    def test_sec090_popen(self):
        assert "SEC090" in _ids("a.c", 'FILE* f = popen(cmd, "r");')

    def test_sec090_std_system(self):
        assert "SEC090" in _ids("a.cpp", 'std::system("ls");')

    def test_sec090_member_call_ok(self):
        assert "SEC090" not in _ids("a.cpp", "obj.system(cmd);")

    def test_sec091_bare_printf_format(self):
        assert "SEC091" in _ids("a.c", "printf(buf);")

    def test_sec091_literal_format_ok(self):
        assert "SEC091" not in _ids("a.c", 'printf("%d", n);')

    def test_sec091_fprintf_first_arg_file_ok(self):
        assert "SEC091" not in _ids("a.c", 'fprintf(fp, "%s", x);')

    def test_sec036_mktemp_c(self):
        assert "SEC036" in _ids("a.c", "mktemp(name);")

    def test_sec036_tmpnam_c(self):
        assert "SEC036" in _ids("a.c", "tmpnam(name);")

    def test_sec036_tempnam_c(self):
        assert "SEC036" in _ids("a.c", "tempnam(dir, pfx);")

    def test_sec036_python_still_works(self):
        assert "SEC036" in _ids("b.py", "tempfile.mktemp(f)")

    def test_native_langs_in_all(self):
        for ext in (".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"):
            assert ext in code.ALL

    def test_native_lang_scoped_to_new_rules(self):
        by_id = {r.rule_id: r for r in code.CODE_RULES}
        assert ".c" in by_id["SEC087"].langs
        assert ".c" not in by_id["SEC020"].langs  # eval stays Python/JS


# --------------------------------------------------------------------------- #
# sentinel explain                                                              #
# --------------------------------------------------------------------------- #

class TestExplain:
    def test_explain_code_rule(self, capsys):
        rc = cli.main(["explain", "SEC089"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "sprintf" in out
        assert "CWE-120" in out
        assert "snprintf" in out  # fix text
        assert ".c" in out       # applies-to extensions
        assert "Pattern:" in out

    def test_explain_case_insensitive(self, capsys):
        rc = cli.main(["explain", "sec001"])
        out = capsys.readouterr().out
        assert rc == 0
        assert out.startswith("SEC001")

    def test_explain_secret_rule(self, capsys):
        rc = cli.main(["explain", "SEC001"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "AWS" in out

    def test_explain_static_rule(self, capsys):
        rc = cli.main(["explain", "SEC050"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "logic-based" in out
        assert "engine-level" in out

    def test_explain_file_rule(self, capsys):
        rc = cli.main(["explain", "SEC038"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "pull_request_target" in out
        assert "&&" in out  # multi-pattern requirement

    def test_explain_unknown_rule(self, capsys):
        rc = cli.main(["explain", "SEC999"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "unknown rule" in err
        assert "sentinel rules" in err

    def test_explain_custom_rule(self, tmp_path, monkeypatch, capsys):
        (tmp_path / "sentinel.toml").write_text(
            '[[custom_rules]]\n'
            'id = "XTEST1"\n'
            'title = "Forbidden token"\n'
            'severity = "high"\n'
            'pattern = "forbidden_token"\n'
            'fix = "Remove the token."\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        rc = cli.main(["explain", "xtest1"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "XTEST1" in out
        assert "forbidden_token" in out
        assert "Remove the token." in out

    def test_explain_every_catalog_rule(self, capsys):
        """Every id in the catalog must be explainable (no lookup gaps)."""
        for rid, _title, _sev in cli._catalog():
            capsys.readouterr()
            rc = cli.main(["explain", rid])
            assert rc == 0, f"explain failed for {rid}"

    def test_rule_count_is_91(self):
        assert len(cli._catalog()) == 91
