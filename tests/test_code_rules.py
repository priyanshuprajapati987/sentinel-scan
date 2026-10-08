"""Code SAST rules — true positives, false positives, file-level context."""

from sentinel.rules.code import FILE_RULES, scan_text


def _ids(text: str, path: str) -> list[str]:
    return [f.rule_id for f in scan_text(path, text)]


class TestPythonRules:
    def test_eval(self):
        assert "SEC020" in _ids("result = eval(user_input)\n", "a.py")

    def test_eval_attribute_not_flagged(self):
        # pandas df.eval(...) is not the builtin
        assert "SEC020" not in _ids("df = df.eval('a > 1')\n", "a.py")

    def test_exec(self):
        assert "SEC021" in _ids("exec(code)\n", "a.py")

    def test_os_system(self):
        assert "SEC023" in _ids("os.system('ls ' + path)\n", "a.py")

    def test_shell_true(self):
        assert "SEC022" in _ids("subprocess.run(cmd, shell=True)\n", "a.py")

    def test_pickle_load(self):
        assert "SEC024" in _ids("obj = pickle.loads(blob)\n", "a.py")

    def test_yaml_load_unsafe(self):
        assert "SEC025" in _ids("cfg = yaml.load(f)\n", "a.py")

    def test_yaml_safe_load_not_flagged(self):
        assert "SEC025" not in _ids("cfg = yaml.safe_load(f)\n", "a.py")

    def test_weak_hash(self):
        assert "SEC026" in _ids("h = hashlib.md5(pw)\n", "a.py")

    def test_md5_usedforsecurity_false_not_flagged(self):
        assert "SEC026" not in _ids("h = hashlib.md5(data, usedforsecurity=False)\n", "a.py")

    def test_verify_false(self):
        assert "SEC027" in _ids("requests.get(url, verify=False)\n", "a.py")

    def test_debug_true(self):
        assert "SEC028" in _ids("app.run(debug=True)\n", "a.py")

    def test_cors_wildcard(self):
        assert "SEC029" in _ids('CORS(app, resources={r"/api/*": {"origins": "*"}})\n', "a.py")

    def test_sql_fstring(self):
        assert "SEC030" in _ids(
            'q = f"SELECT * FROM users WHERE name = \'{name}\'"\n', "a.py")

    def test_sql_fstring_keyword_after_placeholder(self):
        assert "SEC030" in _ids(
            'q = f"WHERE id = {uid} AND x IN (SELECT y FROM t)"\n', "a.py")

    def test_word_containing_update_not_sql(self):
        # regression: "updated" must not match UPDATE without a word boundary
        line = 'print(f"baseline updated: {target} ({n} finding(s))")\n'
        assert "SEC030" not in _ids(line, "a.py")

    def test_sql_concat(self):
        assert "SEC030" in _ids('q = "SELECT * FROM t WHERE id = " + user_id\n', "a.py")

    def test_parameterized_query_clean(self):
        text = 'cur.execute("SELECT * FROM users WHERE name = %s", (name,))\n'
        assert "SEC030" not in _ids(text, "a.py")

    def test_xxe_etree(self):
        assert "SEC035" in _ids("root = ET.fromstring(blob)\n", "a.py")

    def test_mktemp(self):
        assert "SEC036" in _ids("path = tempfile.mktemp()\n", "a.py")

    def test_dynamic_import(self):
        assert "SEC037" in _ids("mod = __import__(name)\n", "a.py")


class TestJavaScriptRules:
    def test_inner_html(self):
        assert "SEC031" in _ids("el.innerHTML = userInput;\n", "app.js")

    def test_text_content_clean(self):
        assert "SEC031" not in _ids("el.textContent = userInput;\n", "app.js")

    def test_dangerously_set_inner_html(self):
        assert "SEC033" in _ids("return <div dangerouslySetInnerHTML={{__html: html}} />;\n", "App.jsx")

    def test_child_process_exec(self):
        assert "SEC032" in _ids('exec("ls -la " + arg);\n', "a.js")

    def test_new_function(self):
        assert "SEC021" in _ids("const fn = new Function('return ' + s);\n", "a.ts")

    def test_reject_unauthorized(self):
        assert "SEC027" in _ids("axios.get(url, { httpsAgent: new Agent({ rejectUnauthorized: false }) });\n", "a.js")


class TestShellAndYamlRules:
    def test_curl_pipe_bash(self):
        text = "curl -fsSL https://example.com/install.sh | sh\n"
        assert "SEC034" in _ids(text, "install.sh")

    def test_wget_pipe_sh(self):
        assert "SEC034" in _ids("wget -qO- https://x.io/i.sh | bash\n", "run.sh")

    def test_plain_pipeline_not_flagged(self):
        assert "SEC034" not in _ids("cat file | grep pattern\n", "run.sh")

    def test_chmod_777(self):
        assert "SEC040" in _ids("chmod 777 /var/www\n", "setup.sh")

    def test_pull_request_target_plus_checkout_is_critical(self):
        text = "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
        hits = [f for f in scan_text(".github/workflows/x.yml", text) if f.rule_id == "SEC038"]
        assert len(hits) == 1
        assert hits[0].severity.name == "CRITICAL"

    def test_pull_request_target_alone_not_flagged(self):
        text = "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n      - run: echo hi\n"
        assert "SEC038" not in _ids(text, ".github/workflows/x.yml")

    def test_third_party_action_unpinned_flagged(self):
        text = "steps:\n  - uses: some-org/some-action@v1\n"
        assert "SEC039" in _ids(text, ".github/workflows/x.yml")

    def test_official_action_not_flagged_as_unpinned(self):
        text = "steps:\n  - uses: actions/checkout@v4\n"
        assert "SEC039" not in _ids(text, ".github/workflows/x.yml")

    def test_sha_pinned_action_not_flagged(self):
        sha = "a" * 40
        text = f"steps:\n  - uses: some-org/some-action@{sha}\n"
        assert "SEC039" not in _ids(text, ".github/workflows/x.yml")


class TestLanguageGating:
    def test_eval_in_yml_not_flagged_by_py_rule(self):
        assert "SEC020" not in _ids("script: eval(something)\n", "config.yml")

    def test_file_rules_catalog_nonempty(self):
        assert len(FILE_RULES) >= 2
