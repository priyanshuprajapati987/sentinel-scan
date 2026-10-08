"""Secret detection rules — true positives, false positives, redaction."""

from sentinel.models import Severity
from sentinel.rules.secrets import (
    _PLACEHOLDER_RE,
    redact,
    scan_bytes,
    scan_text,
    shannon_entropy,
)


def _ids(text: str, path: str = "app.py") -> list[str]:
    return [f.rule_id for f in scan_text(path, text)]


class TestEntropy:
    def test_random_token_is_high(self):
        assert shannon_entropy("a8F3kQ9zX2mP7wR1") > 3.5

    def test_repetitive_is_low(self):
        assert shannon_entropy("aaaaaaaaaaaa") < 1.0

    def test_empty_is_zero(self):
        assert shannon_entropy("") == 0.0


class TestRedaction:
    def test_long_value_keeps_head_and_tail_only(self):
        out = redact("sk-proj-abcdefghijklmnopqrstuvwx1234")
        assert out.startswith("sk-pro")
        assert out.endswith("1234")
        assert "abcdefgh" not in out  # middle must be gone

    def test_short_value_fully_masked(self):
        out = redact("secret1")
        assert "secret1" not in out
        assert set(out) <= {"•"}

    def test_raw_secret_never_in_evidence(self):
        raw = "AKIA" + "A" * 16
        hits = scan_text("x.py", f'KEY = "{raw}"')
        assert any(h.rule_id == "SEC001" for h in hits)
        assert all(raw not in h.evidence for h in hits)
        assert all(raw not in h.message for h in hits)


class TestVendorPrefixes:
    def test_aws_key(self):
        hits = scan_text("x.py", 'k = "AKIA' + "A" * 16 + '"')
        assert [h.rule_id for h in hits] == ["SEC001"]
        assert hits[0].severity is Severity.CRITICAL

    def test_github_pat(self):
        hits = scan_text("cfg.yml", 'token: "github_pat_' + "a" * 22 + "_" + "b" * 20 + '"')
        assert "SEC003" in [h.rule_id for h in hits]

    def test_openai_key(self):
        hits = scan_text("x.py", 'client = "sk-proj-' + "x1Y2" * 8 + '"')
        assert "SEC004" in [h.rule_id for h in hits]

    def test_private_key_block(self):
        hits = scan_text("id_rsa.txt", "-----BEGIN RSA PRIVATE KEY-----")
        assert "SEC006" in [h.rule_id for h in hits]

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
        hits = scan_text("x.py", f'TOKEN = "{jwt}"')
        assert "SEC007" in [h.rule_id for h in hits]

    def test_database_url(self):
        url = "postgres://app:Sup3rSecret@db.internal:5432/prod"
        hits = scan_text("x.py", f'DB = "{url}"')
        assert "SEC008" in [h.rule_id for h in hits]

    def test_basic_auth_url_has_capture_group(self):
        # regression: SEC006/SEC013 once had no capture group and never fired
        hits = scan_text("x.py", 'u = "https://admin:s3cr3tpassw0rd@example.com/api"')
        assert "SEC013" in [h.rule_id for h in hits]
        assert any(h.scanner == "secrets" for h in hits)


class TestGenericAssignments:
    def test_high_entropy_password_fires(self):
        hits = scan_text("x.py", 'password = "kR8mZq2vXw9TfLp0BnY3"')
        assert "SEC014" in [h.rule_id for h in hits]

    def test_placeholder_password_ignored(self):
        for placeholder in ('password = "changeme"', 'api_key = "your-api-key-here"',
                            'secret = "{{SECRET}}"', 'password = "xxxxxxxx"'):
            assert "SEC014" not in _ids(placeholder), placeholder

    def test_low_entropy_password_ignored(self):
        assert "SEC014" not in _ids('password = "aaaaaaaaaaaa"')

    def test_human_password_just_above_floor_fires(self):
        # H = 3.19 bits — was rejected by the old 3.2 floor by 0.01
        hits = scan_text("x.py", 'password = "hunter2secret99"')
        assert "SEC014" in [h.rule_id for h in hits]


class TestDedupeAndCoverage:
    def test_vendor_rule_wins_over_generic_on_same_line(self):
        ids = _ids('API_KEY = "sk-proj-' + "z9Y8" * 8 + '"')
        assert "SEC004" in ids
        assert "SEC014" not in ids  # redundant generic suppressed

    def test_unrelated_code_is_clean(self):
        assert _ids("import json\nvalue = json.loads(data)\n") == []

    def test_bytes_input_scans_like_text(self):
        hits = scan_bytes("blob.bin", ('AKIA' + "B" * 16).encode())
        assert "SEC001" in [h.rule_id for h in hits]

    def test_multiple_secrets_multiple_findings(self):
        text = f'a = "AKIA{"C" * 16}"\nb = "ghp_{"d" * 36}"\n'
        assert set(_ids(text)) == {"SEC001", "SEC003"}

    def test_placeholder_regex_covers_common_cases(self):
        assert _PLACEHOLDER_RE.match("changeme")
        assert _PLACEHOLDER_RE.match("${API_KEY}")
        assert not _PLACEHOLDER_RE.match("kR8mZq2vXw9TfLp0BnY3")
