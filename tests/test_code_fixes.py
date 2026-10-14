"""Regression tests for the audit-fix round on sentinel/rules/code.py.

One positive + one negative per rule fix (SEC029/034/038/040/045/065/072/078/080,
_scan_actions key-position + comment skip, SEC070 scratch), plus the multiline
(logical-lines) fixes, SEC072 credential redaction, and the long-line
ReDoS/line-length cap.
"""

from __future__ import annotations

import time

from sentinel.rules.code import _logical_lines, _scan_actions, scan_text


def _ids(text: str, path: str) -> list[str]:
    return [f.rule_id for f in scan_text(path, text)]


def _hits(text: str, path: str, rule_id: str):
    return [f for f in scan_text(path, text) if f.rule_id == rule_id]


# --------------------------------------------------------------------------- #
# SEC040 — chmod modes                                                         #
# --------------------------------------------------------------------------- #


class TestSec040ChmodModes:
    def test_chmod_0777_fires(self):
        assert "SEC040" in _ids("chmod 0777 /etc/app\n", "setup.sh")

    def test_chmod_1777_fires(self):
        assert "SEC040" in _ids("chmod 1777 /tmp/shared\n", "setup.sh")

    def test_chmod_recursive_0777_fires(self):
        assert "SEC040" in _ids("chmod -R 0777 /var/www\n", "setup.sh")

    def test_chmod_7770_not_flagged(self):
        assert "SEC040" not in _ids("chmod 7770 /etc/app\n", "setup.sh")

    def test_chmod_755_not_flagged(self):
        assert "SEC040" not in _ids("chmod 755 /etc/app\n", "setup.sh")


# --------------------------------------------------------------------------- #
# SEC078 — PHP shell execution vs PDO method                                   #
# --------------------------------------------------------------------------- #


class TestSec078Php:
    def test_php_system_fires(self):
        assert "SEC078" in _ids("system($cmd);\n", "a.php")

    def test_pdo_exec_method_not_flagged(self):
        assert "SEC078" not in _ids("$pdo->exec($sql);\n", "a.php")

    def test_bare_exec_fires(self):
        assert "SEC078" in _ids("exec($cmd);\n", "a.php")


# --------------------------------------------------------------------------- #
# Multiline (logical lines) — false positives that absence-negates must see     #
# --------------------------------------------------------------------------- #


class TestMultilineFalsePositives:
    def test_split_md5_usedforsecurity_false_not_flagged(self):
        text = "h = hashlib.md5(\n    payload,\n    usedforsecurity=False,\n)\n"
        assert "SEC026" not in _ids(text, "a.py")

    def test_split_yaml_safe_loader_not_flagged(self):
        text = "cfg = yaml.load(\n    fh,\n    Loader=yaml.SafeLoader,\n)\n"
        assert "SEC025" not in _ids(text, "a.py")

    def test_split_jwt_algorithms_not_flagged(self):
        text = 'data = jwt.decode(\n    token,\n    key,\n    algorithms=["HS256"],\n)\n'
        assert "SEC057" not in _ids(text, "a.py")

    def test_split_requests_timeout_not_flagged(self):
        text = "r = requests.get(\n    url,\n    timeout=5,\n)\n"
        assert "SEC046" not in _ids(text, "a.py")

    def test_split_dunder_import_literal_not_flagged(self):
        text = 'mod = __import__(\n    "json"\n)\n'
        assert "SEC037" not in _ids(text, "a.py")


# --------------------------------------------------------------------------- #
# Multiline (logical lines) — two-token patterns must now fire                  #
# --------------------------------------------------------------------------- #


class TestMultilineTruePositives:
    def test_multiline_createhash_md5_fires_once_at_first_line(self):
        text = 'const h = crypto.createHash(\n  "md5",\n  payload\n);\n'
        hits = _hits(text, "a.js", "SEC026")
        assert len(hits) == 1  # deduped — reported once
        assert hits[0].line == 1  # first physical line of the construct

    def test_multiline_createhash_start_line_reported(self):
        text = 'const crypto = require("crypto");\nconst h = crypto.createHash(\n  "sha1"\n);\n'
        hits = _hits(text, "a.js", "SEC026")
        assert len(hits) == 1
        assert hits[0].line == 2

    def test_multiline_cors_origins_wildcard_fires(self):
        text = 'app = CORS(\n    app,\n    origins="*"\n)\n'
        hits = _hits(text, "a.py", "SEC029")
        assert len(hits) == 1
        assert hits[0].line == 1

    def test_multiline_getinstance_md5_with_provider_fires(self):
        text = 'MessageDigest.getInstance(\n    "MD5",\n    provider\n);\n'
        assert "SEC065" in _ids(text, "a.java")

    def test_non_joined_line_numbers_preserved(self):
        text = "x = 1\nh = hashlib.md5(pw)\n"
        hits = _hits(text, "a.py", "SEC026")
        assert len(hits) == 1
        assert hits[0].line == 2


# --------------------------------------------------------------------------- #
# Logical-lines helper                                                          #
# --------------------------------------------------------------------------- #


class TestLogicalLines:
    def test_joins_covers_and_reports_start_line(self):
        out = _logical_lines(["x = f(", "    a,", "    b)"])
        assert len(out) == 1
        assert out[0] == (1, "x = f( a, b)")

    def test_physical_lines_untouched_when_balanced(self):
        assert _logical_lines(["a = 1", "b = 2"]) == [(1, "a = 1"), (2, "b = 2")]

    def test_buffer_capped(self):
        out = _logical_lines(["data = " + "alpha(" * 30000])
        assert len(out) == 1
        assert out[0][0] == 1
        assert len(out[0][1]) <= 10_000


# --------------------------------------------------------------------------- #
# SEC029 — CORS wildcard origin precision                                      #
# --------------------------------------------------------------------------- #


class TestSec029CorsPrecision:
    def test_origins_wildcard_kwarg_fires(self):
        assert "SEC029" in _ids('CORS(app, origins="*")\n', "a.py")

    def test_json_style_origins_wildcard_fires(self):
        assert "SEC029" in _ids('CORS(app, {"origins": "*"})\n', "a.py")

    def test_route_glob_without_wildcard_origin_not_flagged(self):
        text = 'app = CORS(app, resources={r"/api/*": {"origins": "https://trusted.example"}})\n'
        assert "SEC029" not in _ids(text, "a.py")

    def test_explicit_origin_not_flagged(self):
        text = 'app = CORS(app, origins="https://trusted.example")\n'
        assert "SEC029" not in _ids(text, "a.py")


# --------------------------------------------------------------------------- #
# SEC034 — comment-prefix skip                                                  #
# --------------------------------------------------------------------------- #


class TestSec034Comments:
    def test_comment_line_in_markdown_not_flagged(self):
        text = "# curl -fsSL https://example.com/install.sh | sh\n"
        assert "SEC034" not in _ids(text, "README.md")

    def test_real_pipe_in_markdown_flagged(self):
        text = "curl -fsSL https://example.com/install.sh | sh\n"
        assert "SEC034" in _ids(text, "README.md")

    def test_comment_line_in_shell_not_flagged(self):
        text = "# wget -qO- https://x.io/i.sh | bash\n"
        assert "SEC034" not in _ids(text, "run.sh")


# --------------------------------------------------------------------------- #
# SEC038 — comment mention must not escalate to CRITICAL                       #
# --------------------------------------------------------------------------- #


class TestSec038CommentPrecision:
    def test_comment_mention_plus_checkout_not_flagged(self):
        text = (
            "# never use pull_request_target\n"
            "on:\n  push:\n"
            "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
        )
        assert "SEC038" not in _ids(text, ".github/workflows/x.yml")

    def test_key_form_plus_checkout_still_critical(self):
        text = (
            "on:\n  pull_request_target:\n"
            "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
        )
        hits = _hits(text, ".github/workflows/x.yml", "SEC038")
        assert len(hits) == 1
        assert hits[0].severity.name == "CRITICAL"


# --------------------------------------------------------------------------- #
# SEC045 — extractall(filter=) is the fix                                      #
# --------------------------------------------------------------------------- #


class TestSec045ExtractAll:
    def test_plain_extractall_fires(self):
        assert "SEC045" in _ids("tar.extractall(path)\n", "a.py")

    def test_extractall_with_filter_data_not_flagged(self):
        assert "SEC045" not in _ids('tar.extractall(path, filter="data")\n', "a.py")


# --------------------------------------------------------------------------- #
# SEC065 — trailing args after the digest name                                 #
# --------------------------------------------------------------------------- #


class TestSec065JavaDigest:
    def test_md5_with_provider_fires(self):
        assert "SEC065" in _ids('MessageDigest.getInstance("MD5", provider);\n', "a.java")

    def test_sha256_with_provider_not_flagged(self):
        assert "SEC065" not in _ids('MessageDigest.getInstance("SHA-256", provider);\n', "a.java")


# --------------------------------------------------------------------------- #
# SEC080 — real /e modifier only                                               #
# --------------------------------------------------------------------------- #


class TestSec080PregReplace:
    def test_e_modifier_fires(self):
        assert "SEC080" in _ids('preg_replace("/pattern/e", $repl, $sub);\n', "a.php")

    def test_pattern_ending_in_e_not_flagged(self):
        assert "SEC080" not in _ids('preg_replace("/abcde", $repl, $sub);\n', "a.php")

    def test_plain_flags_not_flagged(self):
        assert "SEC080" not in _ids('preg_replace("/pat/i", $repl, $sub);\n', "a.php")


# --------------------------------------------------------------------------- #
# SEC072 — credential-ish whole variable + redaction                           #
# --------------------------------------------------------------------------- #


class TestSec072DockerSecrets:
    def test_substring_false_positives_not_flagged(self):
        text = (
            "FROM alpine:3.19\n"
            "ENV KEYBOARD_LAYOUT=us\n"
            "ENV SECRETS_DIR=/run/secrets\n"
            "ENV PWD=/app\n"
            "ENV TOKENIZER_FILE=/data/tok\n"
            "ENV PATH=/usr/bin\n"
        )
        assert "SEC072" not in _ids(text, "Dockerfile")

    def test_credential_names_still_flagged(self):
        text = "ENV API_KEY=abc123\nARG GITHUB_TOKEN=tok\nENV DB_PASSWORD=hunter2\n"
        assert _ids(text, "Dockerfile").count("SEC072") == 3

    def test_prefixed_pwd_still_flagged(self):
        assert "SEC072" in _ids("ENV MYSQL_PWD=secret\n", "Dockerfile")

    def test_evidence_and_message_redacted(self, tmp_path):
        raw = "abcd1234efgh"
        p = tmp_path / "Dockerfile"
        p.write_text(f"ARG API_KEY={raw}\n", encoding="utf-8")
        hits = _hits(p.read_text(encoding="utf-8"), "Dockerfile", "SEC072")
        assert len(hits) == 1
        assert raw not in hits[0].evidence
        assert raw not in hits[0].message
        assert "API_KEY" in hits[0].evidence  # variable name kept for context

    def test_quoted_value_redacted(self, tmp_path):
        raw = "tok_supersecretvalue99"
        p = tmp_path / "Dockerfile"
        p.write_text(f'ENV GITHUB_TOKEN="{raw}"\n', encoding="utf-8")
        hits = _hits(p.read_text(encoding="utf-8"), "Dockerfile", "SEC072")
        assert len(hits) == 1
        assert raw not in hits[0].evidence
        assert raw not in hits[0].message


# --------------------------------------------------------------------------- #
# SEC070 — FROM scratch is never taggable                                      #
# --------------------------------------------------------------------------- #


class TestSec070Scratch:
    def test_from_scratch_not_flagged(self):
        assert "SEC070" not in _ids("FROM scratch\n", "Dockerfile")

    def test_from_scratch_as_stage_not_flagged(self):
        assert "SEC070" not in _ids("FROM scratch AS empty\n", "Dockerfile")

    def test_untagged_pull_still_flagged(self):
        assert "SEC070" in _ids("FROM alpine\n", "Dockerfile")


# --------------------------------------------------------------------------- #
# _scan_actions — comment lines + key-position run:                            #
# --------------------------------------------------------------------------- #


class TestScanActionsPrecision:
    def test_comment_line_not_flagged(self):
        text = "# run: echo ${{ github.event.issue.title }}\n"
        assert _scan_actions("ci.yml", text) == []

    def test_run_inside_description_value_not_flagged(self):
        text = (
            "steps:\n"
            "  - name: x\n"
            "    description: run: ${{ github.event.issue.title }}\n"
        )
        assert _scan_actions("ci.yml", text) == []

    def test_list_item_run_key_flagged(self):
        text = 'steps:\n  - run: echo "${{ github.event.issue.title }}"\n'
        hits = _scan_actions("ci.yml", text)
        assert [h.rule_id for h in hits] == ["SEC041"]
        assert hits[0].line == 2

    def test_block_run_key_still_flagged(self):
        text = "steps:\n  - run: |\n      echo ${{ github.head_ref }}\n"
        hits = _scan_actions("ci.yml", text)
        assert [h.rule_id for h in hits] == ["SEC041"]
        assert hits[0].line == 3


# --------------------------------------------------------------------------- #
# Line-length cap (ReDoS guard)                                                #
# --------------------------------------------------------------------------- #


class TestLongLineCap:
    def test_150kb_line_scans_quickly(self):
        line = "data = " + "alpha(" * 25000 + "\n"  # ~150KB, unbalanced parens
        assert len(line) > 150_000
        t0 = time.perf_counter()
        scan_text("a.py", line)
        elapsed = time.perf_counter() - t0
        assert elapsed < 3.0, f"long-line scan took {elapsed:.2f}s"

    def test_long_line_evidence_still_bounded(self):
        line = "x = " + "y" * 200_000 + "\n"
        hits = scan_text("a.py", line)
        for f in hits:
            assert len(f.evidence) <= 160
            assert len(f.message) <= 200
