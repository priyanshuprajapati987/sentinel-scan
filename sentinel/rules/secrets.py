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
    """Shannon entropy in bits/char (0..~8). Random tokens land near 4-5+."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(value: str, keep_head: int = 6, keep_tail: int = 4) -> str:
    """Render a secret safe for logs: first/last few chars + ellipsis."""
    value = value.strip()
    if len(value) <= keep_head + keep_tail:
        return "•" * max(len(value), 4)
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
    return SecretRule(rule_id, title, re.compile(regex, flags), severity, cwe, fix,
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
       r"(?<![A-Za-z0-9_])((?:password|passwd|pwd|secret|api_?key|apikey|access_?token|"
       r"auth_?token|client_?secret|private_?key)\s*[:=]\s*[\"']([^\s\"']{8,})[\"'])",
       Severity.HIGH, "CWE-798",
       "Move the value to an environment variable / secret manager.",
        min_entropy=3.0, value_group=2),
    _r("SEC015", "High-entropy string assignment",
       r"(?<![A-Za-z0-9_])((?:key|token|credential|salt|seed)\s*[:=]\s*[\"']([A-Za-z0-9+/=_\-]{32,})[\"'])",
       Severity.MEDIUM, "CWE-798",
       "Confirm this is not a live credential; prefer runtime generation.",
       min_entropy=4.0, value_group=2),
]

# Placeholders people legitimately commit — never flag these.
_PLACEHOLDER_RE = re.compile(
    r"^(?:x{4,}|[\*\.]{4,}|changeme|change_?me|your[\-_]?(?:api[\-_]?)?(?:key|token|secret|password)"
    r"|example|placeholder|dummy|test|fake|sample|redacted|not[_\-]?a[_\-]?real"
    r"|<.*>|\{\{.*\}\}|\$\{.*\}|some[_\-]?secret|pass_?word|password_?here"
    r"|process\.env|os\.environ|getenv|env\()",
    re.IGNORECASE,
)

# Extensions where line-scanning is worthwhile for secrets.
SECRET_EXTENSIONS = {
    "", ".env", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml",
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
    if name.startswith(".env"):
        return True
    dot = name.rfind(".")
    ext = name[dot:] if dot >= 0 else ""
    return ext in SECRET_EXTENSIONS


def scan_text(path: str, text: str, allow: list[str] | None = None) -> list[Finding]:
    """Run every secret rule over one file's text.

    ``allow`` — lowercase value substrings that must never be flagged.
    Matched against the **raw** extracted value (redacted evidence would
    silently defeat a user's allowlist for any value longer than ~8 chars).
    """
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        line_hits: list[Finding] = []
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(line):
                try:
                    value = match.group(rule.value_group)
                except IndexError:
                    continue
                if not value:
                    continue
                if allow and any(a in value.lower() for a in allow):
                    continue
                if _PLACEHOLDER_RE.search(value):
                    continue
                if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                    continue
                line_hits.append(
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
                    )
                )
        # A vendor-specific rule on the same line (SEC001-013) already names the
        # leak — drop redundant generic assignment hits for a clean report.
        if any(h.rule_id not in ("SEC014", "SEC015") for h in line_hits):
            line_hits = [h for h in line_hits if h.rule_id not in ("SEC014", "SEC015")]
        findings.extend(line_hits)
    return findings


def scan_bytes(path: str, blob: bytes) -> list[Finding]:
    """Scan raw bytes (git blobs, binary-ish files) as latin-1 text."""
    try:
        text = blob.decode("utf-8", errors="replace")
    except Exception:
        text = blob.decode("latin-1", errors="replace")
    return scan_text(path, text)
