"""Audit-fix regressions for sentinel/rules/secrets.py.

Covers fixes 1-11: unquoted values, keyword prefix/suffix matching,
value-aware vendor suppression, allow=[] fail-open, redaction stump
threshold, scan_bytes decode/TypeError, is_secret_candidate, value_group
validation, placeholder scheme, None guards, and positive/negative
coverage for the 7 previously untested rules (SEC002/005/009/010/011/012/015).
"""

from __future__ import annotations

import pytest

from sentinel.models import Severity
from sentinel.rules.secrets import (
    SECRET_EXTENSIONS,
    SECRET_RULES,
    _is_placeholder,
    _r,
    is_secret_candidate,
    redact,
    scan_bytes,
    scan_text,
    shannon_entropy,
)

_HIGH = "kR8mZq2vXw9TfLp0BnY3"  # entropy 4.32 — clears the SEC014 3.0 gate


def _ids(text: str, path: str = "app.py", allow: list | None = None) -> list[str]:
    return [f.rule_id for f in scan_text(path, text, allow=allow)]


# --------------------------------------------------------------------------- #
# fix 1 — quotes optional in value-matching patterns                           #
# --------------------------------------------------------------------------- #

class TestUnquotedValues:
    def test_unquoted_db_password_fires(self):
        assert _ids("DB_PASSWORD=longsecret123") == ["SEC014"]

    def test_unquoted_stops_at_delimiter(self):
        hits = scan_text("app.env", "DB_PASSWORD=longsecret123;  # prod")
        assert [h.rule_id for h in hits] == ["SEC014"]
        assert hits[0].evidence == redact("longsecret123")

    def test_unquoted_api_key_fires(self):
        assert "SEC014" in _ids(f"api_key={_HIGH}")

    def test_quoted_value_with_spaces_fires_and_redacts(self):
        raw = "correct horse battery staple"
        hits = scan_text("app.py", f'password = "{raw}"')
        assert [h.rule_id for h in hits] == ["SEC014"]
        assert raw not in hits[0].evidence  # value_group captured the secret
        assert hits[0].evidence == redact(raw)

    def test_single_quoted_value_fires(self):
        assert _ids(f"secret = '{_HIGH}'") == ["SEC014"]

    def test_sec015_unquoted_high_entropy_fires(self):
        tok = "Ab3xK9mQz7Wp2Ld5Rt8Yv4Nb6Hc1Jf0Gg5Ss2"
        assert _ids(f"token={tok}") == ["SEC015"]

    def test_sec016_unquoted_aws_secret_fires(self):
        secret40 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
        assert len(secret40) == 40
        # SEC014 also matches (secret...access_key prefix) but is suppressed
        # as an exact restatement of the vendor value.
        assert _ids(f"aws_secret_access_key={secret40}") == ["SEC016"]

    def test_sec019_unquoted_flask_secret_fires(self):
        assert _ids("SECRET_KEY=supersecretvalue99x") == ["SEC019"]


# --------------------------------------------------------------------------- #
# fix 2 — keyword prefix / suffix segments inside the identifier               #
# --------------------------------------------------------------------------- #

class TestKeywordPrefixSuffix:
    def test_db_password_prefixed_identifier(self):
        assert "SEC014" in _ids(f'DB_PASSWORD = "{_HIGH}"')

    def test_admin_password_prefixed_identifier(self):
        assert "SEC014" in _ids("ADMIN_PASSWORD=AnotherSecret99x")

    def test_db_secret_prefixed_identifier(self):
        assert "SEC014" in _ids(f'db_secret = "{_HIGH}"')

    def test_api_key_hash_suffix_identifier(self):
        assert "SEC014" in _ids(f'api_key_hash = "{_HIGH}"')

    def test_passwordless_validation_not_flagged(self):
        assert "SEC014" not in _ids(f'PASSWORDLESS_VALIDATION = "{_HIGH}"')

    def test_mid_word_password_not_flagged(self):
        assert "SEC014" not in _ids(f'MYPASSWORD = "{_HIGH}"')

    def test_lowercase_db_password_unquoted_fires(self):
        assert _ids("db_password=longsecret123") == ["SEC014"]


# --------------------------------------------------------------------------- #
# fix 3 — vendor suppression is value-aware                                    #
# --------------------------------------------------------------------------- #

class TestVendorSuppression:
    def test_jwt_and_password_same_line_both_reported(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
        line = f'TOKEN = "{jwt}"  password = "{_HIGH}"'
        ids = _ids(line)
        assert "SEC007" in ids
        assert "SEC014" in ids  # unrelated generic survives the vendor line

    def test_redundant_generic_still_suppressed_for_vendor_value(self):
        ids = _ids('API_KEY = "sk-proj-' + "z9Y8" * 8 + '"')
        assert "SEC004" in ids
        assert "SEC014" not in ids
        assert "SEC015" not in ids

    def test_generic_equal_to_vendor_value_suppressed(self):
        url = "https://admin:s3cr3tpassw0rd@example.com/api"
        assert _ids(f'password = "{url}"') == ["SEC013"]

    def test_generic_substring_of_vendor_value_suppressed(self):
        # SEC017 captures ?api_key=abc...; the generic value is a substring
        ids = _ids('url = "https://api.example.com/v1?api_key=abcdefghijklmnop"')
        assert "SEC017" in ids
        assert "SEC014" not in ids


# --------------------------------------------------------------------------- #
# fix 4 — allow=[] fail-open                                                   #
# --------------------------------------------------------------------------- #

class TestAllowFailOpen:
    def test_allow_empty_string_still_reports(self):
        assert "SEC014" in _ids(f'password = "{_HIGH}"', allow=[""])

    def test_allow_falsy_entries_filtered(self):
        assert "SEC014" in _ids(f'password = "{_HIGH}"', allow=[None, ""])

    def test_allow_real_value_still_suppresses(self):
        # scan_text matches allow entries against value.lower() (documented)
        assert "SEC014" not in _ids(f'password = "{_HIGH}"', allow=["kr8m"])


# --------------------------------------------------------------------------- #
# fix 5 — redaction stump must not expose the bulk of a short secret           #
# --------------------------------------------------------------------------- #

class TestRedactionThreshold:
    def test_eleven_char_secret_fully_masked(self):
        out = redact("abcdefghijk")
        assert set(out) <= {"•"}
        assert "abcdef" not in out

    def test_sixteen_char_secret_fully_masked(self):
        out = redact("abcdefghijklmnop")
        assert set(out) <= {"•"}

    def test_long_secret_keeps_stump(self):
        out = redact("sk-proj-abcdefghijklmnopqrstuvwx1234")
        assert out.startswith("sk-pro") and out.endswith("1234")

    def test_seventeen_char_boundary_keeps_stump(self):
        # 10/17 = 59% visible <= the 60% budget
        out = redact("abcdefghijklmnopq")
        assert "…" in out and out.startswith("abcdef")

    def test_redact_none_is_empty(self):
        assert redact(None) == ""

    def test_redact_blank_is_empty(self):
        assert redact("") == ""


# --------------------------------------------------------------------------- #
# fix 6 — scan_bytes decoding + TypeError                                      #
# --------------------------------------------------------------------------- #

class TestScanBytes:
    def test_invalid_utf8_falls_back_to_latin1(self):
        blob = b'\x80password = "kR8mZq2vXw9TfLp0BnY3"'
        with pytest.raises(UnicodeDecodeError):
            blob.decode("utf-8")  # proves the strict decode really fails
        assert "SEC014" in [f.rule_id for f in scan_bytes("blob.env", blob)]

    def test_non_bytes_raises_type_error(self):
        with pytest.raises(TypeError, match="scan_bytes expects bytes"):
            scan_bytes("x.py", "AKIA" + "A" * 16)

    def test_none_raises_type_error(self):
        with pytest.raises(TypeError, match="scan_bytes expects bytes"):
            scan_bytes("x.py", None)

    def test_bytearray_accepted(self):
        blob = bytearray(("AKIA" + "A" * 16).encode())
        assert "SEC001" in [f.rule_id for f in scan_bytes("x.py", blob)]


# --------------------------------------------------------------------------- #
# fix 7 — is_secret_candidate extension / .env checks                          #
# --------------------------------------------------------------------------- #

class TestSecretCandidate:
    def test_extensionless_files_not_candidates(self):
        assert is_secret_candidate("proj/Makefile") is False
        assert is_secret_candidate("LICENSE") is False

    def test_env_exact_and_dot_prefix(self):
        assert is_secret_candidate(".env") is True
        assert is_secret_candidate("config/.env") is True
        assert is_secret_candidate(".env.local") is True
        assert is_secret_candidate(".env.production") is True

    def test_environment_is_not_env(self):
        assert is_secret_candidate(".environment") is False

    def test_known_secret_filenames_still_match(self):
        assert is_secret_candidate("secrets") is True  # extensionless, filename set
        assert is_secret_candidate("id_rsa") is True

    def test_regular_extension_still_matches(self):
        assert is_secret_candidate("app.py") is True
        assert is_secret_candidate("app.rs") is False

    def test_empty_extension_dropped_from_set(self):
        assert "" not in SECRET_EXTENSIONS


# --------------------------------------------------------------------------- #
# fix 8 — value_group validation at rule construction                          #
# --------------------------------------------------------------------------- #

class TestValueGroupValidation:
    def test_value_group_beyond_groups_raises(self):
        with pytest.raises(ValueError, match="value_group"):
            _r("SECX98", "broken", "(abc)", Severity.HIGH, "CWE-798", "f",
               value_group=2)

    def test_value_group_within_groups_ok(self):
        rule = _r("SECX99", "ok", "(abc)", Severity.HIGH, "CWE-798", "f",
                  value_group=1)
        assert rule.value_group == 1

    def test_all_secret_rules_valid(self):
        for rule in SECRET_RULES:
            assert 1 <= rule.value_group <= rule.pattern.groups, rule.rule_id


# --------------------------------------------------------------------------- #
# fix 9 — placeholder must not swallow real secrets                            #
# --------------------------------------------------------------------------- #

class TestPlaceholderScheme:
    @pytest.mark.parametrize("value", [
        "example", "changeme", "dummy", "your-api-key-here",
        "xxxxxxxx", "{{SECRET}}", "${API_KEY}",
    ])
    def test_placeholders_suppress(self, value):
        assert _is_placeholder(value) is True
        assert "SEC014" not in _ids(f'password = "{value}"')

    @pytest.mark.parametrize("value", [
        "exampleREALKEY123", "testsecret999999", "password12345678",
        "kR8mZq2vXw9TfLp0BnY3",
    ])
    def test_non_placeholders_do_not_suppress(self, value):
        assert _is_placeholder(value) is False

    def test_example_real_key_fires(self):
        assert "SEC014" in _ids('password = "exampleREALKEY123"')

    def test_password_with_digits_fires(self):
        assert "SEC014" in _ids('password = "password12345678"')


# --------------------------------------------------------------------------- #
# fix 10 — None guards                                                         #
# --------------------------------------------------------------------------- #

class TestNoneGuards:
    def test_scan_text_none_returns_empty(self):
        assert scan_text("app.py", None) == []

    def test_scan_text_empty_returns_empty(self):
        assert scan_text("app.py", "") == []

    def test_shannon_none_is_zero(self):
        assert shannon_entropy(None) == 0.0
        assert shannon_entropy("") == 0.0

    def test_redact_none_is_empty_string(self):
        assert redact(None) == ""


# --------------------------------------------------------------------------- #
# fix 11 — coverage for the 7 untested rules                                   #
# --------------------------------------------------------------------------- #

class TestUntestedRuleCoverage:
    # SEC002 — Google API key
    def test_sec002_positive(self):
        key = "AIza" + "A" * 35
        assert _ids(f'g = "{key}"') == ["SEC002"]

    def test_sec002_negative(self):
        assert _ids('g = "' + "AIza" + "A" * 34 + '"') == []

    # SEC005 — Slack token / webhook
    # (fixture halves are concatenated at runtime so the contiguous token
    #  literal never appears in this file — GitHub push protection)
    def test_sec005_positive(self):
        assert _ids('s = "xoxb-' + '1234567890-abcdefghijklmnop"') == ["SEC005"]

    def test_sec005_negative(self):
        assert _ids('s = "xoxb-short"') == []

    # SEC009 — Stripe live key
    def test_sec009_positive(self):
        assert _ids('k = "sk_live_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m"') == ["SEC009"]

    def test_sec009_negative(self):
        assert _ids('k = "sk_test_a1B2c3D4e5F6g7H8i9J0"') == []

    # SEC010 — SendGrid credential
    def test_sec010_positive(self):
        line = f's = "SG.{"a" * 22}.{"b" * 43}"'
        assert _ids(line) == ["SEC010"]

    def test_sec010_negative(self):
        assert _ids('s = "SG.aaaa.bbbb"') == []

    # SEC011 — Hugging Face token
    def test_sec011_positive(self):
        line = f't = "hf_{"aB3" * 10}"'
        assert _ids(line) == ["SEC011"]

    def test_sec011_negative(self):
        assert _ids('t = "hf_short"') == []

    # SEC012 — Telegram bot token
    def test_sec012_positive(self):
        line = f'b = "1234567890:{"a1" * 17}a"'
        assert _ids(line) == ["SEC012"]

    def test_sec012_negative(self):
        assert _ids('b = "123:abc"') == []

    # SEC015 — high-entropy string assignment
    def test_sec015_positive(self):
        tok = "Ab3xK9mQz7Wp2Ld5Rt8Yv4Nb6Hc1Jf0Gg5Ss2"
        assert _ids(f'token = "{tok}"') == ["SEC015"]

    def test_sec015_negative_low_entropy(self):
        assert _ids('token = "' + "a" * 32 + '"') == []
        assert _ids('token = "short"') == []


# --------------------------------------------------------------------------- #
# Integration round - shared post-match gates (scan_text == scan_history)      #
# --------------------------------------------------------------------------- #

class TestSharedGateRegressions:
    """FPs that appeared when the two secret scanners drifted apart:
    git history ran looser gates than scan_text (docs/type-annotation
    matches became CRITICAL SEC055 findings)."""

    def test_type_annotation_value_not_flagged(self):
        assert _ids("SECRET_RULES: list[SecretRule] = [") == []

    def test_bare_bracket_value_not_flagged(self):
        assert _ids("password = [abcdefghij]") == []
        assert _ids("api_key = abcdefgh[ij]") == []

    def test_function_call_value_not_flagged(self):
        assert _ids("password = get_password()") == []
        assert _ids("db_secret = load_secret_from_vault()") == []

    def test_docs_metasyntax_quoted_value_not_flagged(self):
        assert _ids('password = "<literal>"') == []
        assert _ids("secret = '{{TOKEN}}'") == []

    def test_unquoted_env_values_still_fire(self):
        assert _ids("API_KEY=Zx9Kp2LmQ7RvT4Wn8YbC1dFgH3j") == ["SEC014"]
        assert _ids("DB_PASSWORD=longsecret123") == ["SEC014"]

    def test_falsy_allow_entries_do_not_suppress(self):
        text = f"password = {_HIGH}"
        assert _ids(text, allow=[""]) == ["SEC014"]
        assert _ids(text, allow=[None]) == ["SEC014"]

    def test_extract_value_direct_gates(self):
        import re as _re

        from sentinel.rules.secrets import SECRET_RULES, extract_value

        sec014 = next(r for r in SECRET_RULES if r.rule_id == "SEC014")
        line = "password = get_password()"
        m = _re.search(sec014.pattern, line)
        assert m is not None
        assert extract_value(sec014, line, m) is None  # code call -> rejected

        real = f"password = {_HIGH}"
        m2 = _re.search(sec014.pattern, real)
        assert m2 is not None
        assert extract_value(sec014, real, m2) == _HIGH

    def test_scan_history_uses_shared_gates(self, tmp_path, monkeypatch):
        """Docs/code shapes in a patch must not become SEC055 findings;
        a real committed secret on the same patch still must."""
        from sentinel.rules import gitcheck

        patch = (
            "commit abc123def456 test commit\n"
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,0 +1,3 @@\n"
            "+password = get_password()  # docs example\n"
            "+SECRET_RULES: list[SecretRule] = [\n"
            f'+password = "{_HIGH}"\n'
        )
        monkeypatch.setattr(gitcheck, "_git", lambda *a, **k: patch)
        findings = gitcheck.scan_history(tmp_path, max_commits=5,
                                         exclude=lambda rel: False, allow=None)
        assert [f.rule_id for f in findings] == ["SEC055"]
        assert "SEC014" in findings[0].evidence
        assert _HIGH not in findings[0].evidence  # raw value never leaks
