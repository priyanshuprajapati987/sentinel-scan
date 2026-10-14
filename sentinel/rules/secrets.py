"""Secret detection — known prefixes first, entropy second.

Design notes
------------
* Known vendor prefixes (AWS, GitHub, OpenAI, ...) are high confidence even
  without entropy (``ghp_...`` always starts with ``ghp_``).
* Generic ``password/api_key = "<literal>"`` assignments only fire when the
  value looks random (Shannon entropy + length) — this is what keeps the
  false-positive rate usable on ordinary codebases.
* ``redact()`` is applied to EVERY piece of evidence before it leaves this
  module; reports only ever see ``sk-ab…7f2c`` style stumps.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..models import Finding, Severity


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits/char (0..~8). Random tokens land near 4-5+.

    ``None`` is treated as the empty string (returns 0.0), matching ``""``.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep_head: int = 6, keep_tail: int = 4) -> str:
    """Render a secret safe for logs: first/last few chars + ellipsis.

    ``None`` → ``""``.  When the head+tail stump would expose more than 60%
    of the secret (``abcdef…hijk`` reveals 10/11 chars) nothing of the value
    is shown — only bullet masks, so the stump never leaks the bulk of it.
    """
    if not value:
        return ""
    value = value.strip()
    if not value:
        return ""
    visible = keep_head + keep_tail
    if len(value) <= visible or visible / len(value) > 0.6:
        return "•" * min(len(value), 16)
    return f"{value[:keep_head]}…{value[-keep_tail:]}"


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    cwe: str
    fix: str
    min_entropy: float = 0.0  # extra gate for generic assignments
    value_group: int = 1  # capture group holding the secret itself


def _r(rule_id: str, title: str, regex: str, severity: Severity, cwe: str, fix: str,
       min_entropy: float = 0.0, flags: int = re.IGNORECASE, value_group: int = 1) -> SecretRule:
    pattern = re.compile(regex, flags)
    if value_group > pattern.groups:
        # Rules are static — a misconfigured value_group must fail loudly at
        # import time instead of being silently swallowed per match later.
        raise ValueError(
            f"rule {rule_id}: value_group={value_group} but pattern has "
            f"{pattern.groups} capture group(s)"
        )
    return SecretRule(rule_id, title, pattern, severity, cwe, fix,
                      min_entropy, value_group)


SECRET_RULES: list[SecretRule] = [
    _r("SEC001", "AWS access key ID",
       r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b",
       Severity.CRITICAL, "CWE-798",
       "Rotate the key in IAM and load it from the environment / a secret manager."),
    _r("SEC002", "Google API key",
       r"\b(AIza[0-9A-Za-z_\-]{35})\b",
       Severity.HIGH, "CWE-798",
       "Restrict the key in Google Cloud console, then move it to an environment variable."),
    _r("SEC003", "GitHub token",
       r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|"
       r"ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
       Severity.CRITICAL, "CWE-798",
       "Revoke the token now (GitHub → Settings → Developer settings) and regenerate."),
    _r("SEC004", "OpenAI / Anthropic / provider API key",
       r"\b(sk-(?:proj|ant|or|live|test)?[\-_][A-Za-z0-9\-_]{20,}|sk-[A-Za-z0-9]{48})\b",
       Severity.CRITICAL, "CWE-798",
       "Rotate the key at the provider and inject via environment variable."),
    _r("SEC005", "Slack token / webhook",
       r"\b(xox[baprs]-[0-9A-Za-z\-]{10,}|https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
       Severity.HIGH, "CWE-798",
       "Revoke the token/webhook in the Slack app settings."),
    _r("SEC006", "Private key material",
       r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)",
       Severity.CRITICAL, "CWE-321",
       "Remove the key from the repo, purge it from history, and re-issue the keypair."),
    _r("SEC007", "Hardcoded JWT",
       r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
       Severity.HIGH, "CWE-798",
       "Never persist session tokens in source — issue them at runtime."),
    _r("SEC008", "Database URL with credentials",
       r"\b((?:postgres|postgresql|mysql|mongodb|redis|mssql|amqp)://[^\s:/'\"]+:[^\s@/'\"]{3,}@[\w.\-]+)",
       Severity.HIGH, "CWE-798",
       "Use a connection-string environment variable with the password removed."),
    _r("SEC009", "Stripe live key",
       r"\b([sr]k_live_[0-9a-zA-Z]{24,})\b",
       Severity.CRITICAL, "CWE-798",
       "Roll the key in the Stripe dashboard (developers → API keys)."),
    _r("SEC010", "SendGrid / Twilio credential",
       r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}|SK[0-9a-fA-F]{32})\b",
       Severity.CRITICAL, "CWE-798",
       "Rotate the credential in the provider console."),
    _r("SEC011", "Hugging Face / npm / PyPI token",
       r"\b(hf_[A-Za-z0-9]{30,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_\-]{50,})\b",
       Severity.HIGH, "CWE-798",
       "Revoke and regenerate the token; store it in CI secrets."),
    _r("SEC012", "Telegram bot token",
       r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b",
       Severity.HIGH, "CWE-798",
       "Revoke via @BotFather and re-issue."),
    _r("SEC013", "URL with basic-auth credentials",
       r"(\bhttps?://[^\s/:@\']+:[^\s/@\']{4,}@[^\s/:\'\"`]+)",
       Severity.HIGH, "CWE-798",
       "Strip credentials from the URL; authenticate with a header or token instead."),
    _r("SEC014", "Generic hardcoded secret",
       r"(?<![A-Za-z0-9_])((?:[A-Za-z0-9]+[_.])*(?:password|passwd|pwd|secret|api_?key|apikey|"
       r"access_?token|auth_?token|client_?secret|private_?key)(?:[_.][A-Za-z0-9]+)*\s*[:=]\s*"
       r"(\"[^\"\n]{8,}\"|'[^'\n]{8,}'|[^\s\"'();,\[\]]{8,}))",
       Severity.HIGH, "CWE-798",
       "Move the value to an environment variable / secret manager.",
        min_entropy=3.0, value_group=2),
    _r("SEC015", "High-entropy string assignment",
       r"(?<![A-Za-z0-9_])((?:[A-Za-z0-9]+[_.])*(?:key|token|credential|salt|seed)"
       r"(?:[_.][A-Za-z0-9]+)*\s*[:=]\s*[\"']?([A-Za-z0-9+/=_\-]{32,})[\"']?)",
       Severity.MEDIUM, "CWE-798",
       "Confirm this is not a live credential; prefer runtime generation.",
       min_entropy=4.0, value_group=2),
    _r("SEC016", "AWS secret access key",
       r"(?:aws)?[_\-]?secret[_\-]?access[_\-]?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?",
       Severity.CRITICAL, "CWE-798",
       "Rotate the secret in IAM; load it from the environment / a secret manager."),
    _r("SEC017", "Credential in URL query string",
       r"([?&](?:api[_\-]?key|access[_\-]?token|token|password|secret|auth)"
       r"=[A-Za-z0-9_\-\.%]{12,})",
       Severity.HIGH, "CWE-598",
       "Move the credential out of the URL into a header or env-injected config."),
    _r("SEC018", "Hardcoded Bearer token",
       r"\bBearer\s+([A-Za-z0-9_\-\.]{20,})",
       Severity.HIGH, "CWE-798",
       "Load the token from the environment at runtime; rotate if this one was live.",
       min_entropy=3.0),
    _r("SEC019", "Hardcoded application secret key",
       r"\b(?:SECRET_KEY|SECRET_KEY_BASE|JWT_SECRET|FLASK_SECRET|APP_SECRET)"
       r"\s*[:=]\s*(\"[^\"\n]{8,}\"|'[^'\n]{8,}'|[^\s\"'();,\[\]]{8,})",
       Severity.HIGH, "CWE-798",
       "Load the secret from the environment at boot; rotate any committed value.",
       min_entropy=3.0),
]

# Placeholders people legitimately commit — never flag these.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x{4,}|[\*\.]{4,}|changeme|change_?me|your[\-_]?(?:api[\-_]?)?(?:key|token|secret|password)"
    r"|example|placeholder|dummy|test|fake|sample|redacted|not[_\-]?a[_\-]?real"
    r"|<.*>|\{\{.*\}\}|\$\{.*\}|some[_\-]?secret|pass_?word|password_?here"
    r"|process\.env|os\.environ|getenv|env\()",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """True only when the value is a committed placeholder, not a real secret.

    The placeholder must match at the START of the value and the remainder
    must look non-secret (no digits, no uppercase) — so ``example``,
    ``changeme`` and ``your-api-key-here`` still suppress, while
    ``exampleREALKEY123``, ``testsecret999999`` and ``password12345678``
    (real weak secrets prefixed with a placeholder word) do not.
    """
    m = _PLACEHOLDER_RE.match(value)
    if not m:
        return False
    return re.search(r"[0-9A-Z]", value[m.end():]) is None


def extract_value(rule: SecretRule, line: str, match: re.Match[str],
                  allow: list[str] | None = None) -> str | None:
    """Post-match gates shared by ``scan_text`` and git history (SEC055).

    Returns the cleaned secret value when every gate passes, else ``None``.
    One implementation for both scanners — history previously ran its own
    looser copy (no code-context check, ``search`` instead of the anchored
    placeholder gate) which surfaced docs/type-annotation false positives
    (``list[SecretRule]``, ``password = get_password()``).
    """
    try:
        raw = match.group(rule.value_group)
    except IndexError:
        return None
    if allow and any(not a for a in allow):
        # Falsy entries ("" / None) would suppress EVERY finding
        # (``"" in value`` is always True) — drop them here for all callers.
        allow = [a for a in allow if a]
    if not raw:
        return None
    # Quoted captures keep their delimiters (quotes sit inside the group so
    # values may contain spaces); strip the matching pair so redaction /
    # allow / placeholder all see the secret itself.
    value = raw[1:-1] if (
        len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'"
    ) else raw
    if not value:
        return None
    # Unquoted value butted against "(" or "[" is code
    # (``password = get_secret()``), not a literal.
    if line[match.end():match.end() + 1] in ("(", "["):
        return None
    if allow and any(a in value.lower() for a in allow):
        return None
    if _is_placeholder(value):
        return None
    if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
        return None
    return value


# Extensions where line-scanning is worthwhile for secrets.
SECRET_EXTENSIONS = {
    ".env", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml",
    ".yaml", ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".tf", ".tfvars", ".hcl", ".properties", ".xml", ".sql", ".txt", ".md", ".rst",
    ".env.local", ".env.example",
}

_SECRET_FILENAMES = {".env", "credentials", "secrets", "id_rsa", "id_ed25519", ".npmrc", ".pypirc"}


def is_secret_candidate(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    name = lowered.rsplit("/", 1)[-1]
    if name in _SECRET_FILENAMES:
        return True
    # exact ".env" or a real ".env.*" variant — NOT a bare prefix, so
    # ".environment" / ".envrc" do not qualify as env files.
    if name == ".env" or name.startswith(".env."):
        return True
    dot = name.rfind(".")
    ext = name[dot:] if dot >= 0 else ""
    return bool(ext) and ext in SECRET_EXTENSIONS


def scan_text(path: str, text: str, allow: list[str] | None = None) -> list[Finding]:
    """Run every secret rule over one file's text.

    ``allow`` — lowercase value substrings that must never be flagged.
    Matched against the **raw** extracted value (redacted evidence would
    silently defeat a user's allowlist for any value longer than ~8 chars).
    Falsy entries (``""``, ``None``) are dropped — ``"" in value`` is always
    True and would suppress every finding.
    """
    if not text:
        return []
    allow = [a for a in allow if a] if allow else []
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line_hits: list[tuple[Finding, str]] = []
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(line):
                value = extract_value(rule, line, match, allow)
                if value is None:
                    continue
                line_hits.append(
                    (
                        Finding(
                            rule_id=rule.rule_id,
                            title=rule.title,
                            severity=rule.severity,
                            message=f"{rule.title} committed to source",
                            path=path,
                            line=lineno,
                            evidence=redact(value),
                            fix=rule.fix,
                            cwe=rule.cwe,
                            confidence="high" if not rule.min_entropy else "medium",
                            scanner="secrets",
                        ),
                        value,
                    )
                )
        # A vendor-specific rule on the same line (SEC001-013) already names
        # the leak — drop only generic (SEC014/015) hits whose captured value
        # is that same secret; unrelated generics (a password on a JWT line)
        # are independent leaks and must survive.
        vendor_values = [
            v.casefold() for h, v in line_hits if h.rule_id not in ("SEC014", "SEC015")
        ]
        if vendor_values:
            kept: list[tuple[Finding, str]] = []
            for h, v in line_hits:
                if h.rule_id in ("SEC014", "SEC015"):
                    lv = v.casefold()
                    if any(lv in vv or vv in lv for vv in vendor_values):
                        continue  # redundant restatement of the vendor secret
                kept.append((h, v))
            line_hits = kept
        findings.extend(h for h, _v in line_hits)
    return findings


def scan_bytes(path: str, blob: bytes) -> list[Finding]:
    """Scan raw bytes (git blobs, binary-ish files) as text.

    Strict UTF-8 first; on real ``UnicodeDecodeError`` fall back to latin-1
    (never raises). Non-bytes input is a programming error → TypeError.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("scan_bytes expects bytes")
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        text = blob.decode("latin-1")
    return scan_text(path, text)
