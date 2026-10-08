"""Code vulnerability rules (lightweight SAST).

Line-oriented regular expressions per language — deliberately conservative:
every rule fires on a single unambiguous line so the report can point at an
exact ``path:line``. File-level rules (workflow context) are handled
separately in ``FILE_RULES``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, Severity

PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
WEB = frozenset({".js", ".jsx", ".ts", ".tsx", ".html", ".vue"})
SHELL = frozenset({".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"})
YAML = frozenset({".yml", ".yaml"})
CONFIG = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".toml"})
ALL = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".sh", ".bash",
                 ".yml", ".yaml", ".env", ".ini", ".cfg", ".conf", ".html", ".vue"})


@dataclass(frozen=True, slots=True)
class CodeRule:
    rule_id: str
    title: str
    regex: re.Pattern
    severity: Severity
    cwe: str
    fix: str
    langs: frozenset
    confidence: str = "high"
    negate: re.Pattern | None = None  # skip line when this matches (e.g. usedforsecurity=False)
    message: str = ""


def _c(rule_id, title, regex, severity, cwe, fix, langs, confidence="high",
       negate=None, flags=re.IGNORECASE, message="") -> CodeRule:
    return CodeRule(rule_id, title, re.compile(regex, flags), severity, cwe, fix,
                    frozenset(langs), confidence, negate, message)


CODE_RULES: list[CodeRule] = [
    _c("SEC020", "eval() on dynamic input",
       r"(?<![\w.])eval\s*\(", Severity.HIGH, "CWE-95",
       "Replace eval with explicit parsing (json.loads, int(), ast.literal_eval).",
       PY | JS),
    _c("SEC021", "exec() / new Function() code execution",
       r"(?<![\w.])(?:exec\s*\(|new\s+Function\s*\()", Severity.HIGH, "CWE-94",
       "Never build code from strings — use data-driven dispatch instead.",
       PY | JS),
    _c("SEC022", "Shell invocation with shell=True",
       r"shell\s*=\s*True|shell\s*:\s*true", Severity.HIGH, "CWE-78",
       "Pass an argument list without shell=True; validate/allowlist inputs.",
       PY | JS | YAML),
    _c("SEC023", "Direct OS command execution",
       r"(?<![\w.])(?:os\.system|os\.popen|commands\.getoutput)\s*\(", Severity.HIGH, "CWE-78",
       "Use subprocess.run([...], shell=False) with an argument list.",
       PY),
    _c("SEC024", "Unsafe deserialization (pickle)",
       r"(?<![\w.])(?:pickle|cPickle)\.(?:load|loads|Unpickler)\s*\(|marshal\.(?:load|loads)\s*\(",
       Severity.HIGH, "CWE-502",
       "Do not unpickle untrusted data — use json or a schema-validated format.",
       PY),
    _c("SEC025", "Unsafe yaml.load()",
       r"yaml\.(?:load|full_load)\s*\(", Severity.HIGH, "CWE-502",
       "Use yaml.safe_load() / SafeLoader.",
       PY | JS,
       negate=re.compile(r"SafeLoader|safe_load|Loader\s*=\s*Safe", re.IGNORECASE)),
    _c("SEC026", "Weak hash (MD5/SHA1)",
       r"hashlib\.(?:md5|sha1)\s*\(|crypto\.createHash\(\s*['\"](?:md5|sha1)", Severity.MEDIUM, "CWE-327",
       "Use SHA-256+ for integrity, or hashlib.md5(..., usedforsecurity=False) for checksums.",
       PY | JS,
       confidence="medium",
       negate=re.compile(r"usedforsecurity\s*=\s*False", re.IGNORECASE)),
    _c("SEC027", "TLS certificate verification disabled",
       r"verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false",
       Severity.HIGH, "CWE-295",
       "Verify certificates — pin a CA bundle instead of disabling verification.",
       PY | JS),
    _c("SEC028", "Debug mode enabled",
       r"debug\s*=\s*True|debug\s*:\s*true|(?:FLASK|DJANGO|NODE)_DEBUG\s*=\s*1|\bDEBUG\s*=\s*True",
       Severity.MEDIUM, "CWE-489",
       "Never ship debug mode — debug consoles expose arbitrary code execution.",
       PY | YAML | CONFIG | frozenset({".env"}),
       confidence="medium"),
    _c("SEC029", "CORS wildcard origin",
       r"CORS\s*\([^)]{0,300}\*|Access-Control-Allow-Origin['\"]?\s*[,:)]\s*['\"]?\*",
       Severity.HIGH, "CWE-942",
       "Allowlist trusted origins instead of '*'.",
       PY | JS | YAML | frozenset({".cs", ".go", ".java", ".rb"}),
       confidence="medium"),
    _c("SEC030", "SQL built by string interpolation",
       r"(?:f\"[^\"]*\{[^}]+\}[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b"
       r"|f\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^\"]*\{"
       r"|f'[^']*\{[^}]+\}[^']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b"
       r"|f'[^']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^']*\{"
       r"|['\"](?:SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP TABLE)[^'\"]*['\"]\s*\+"
       r"|\+\s*['\"][^'\"]*(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b)",
       Severity.HIGH, "CWE-89",
       "Use parameterized queries / bound parameters — never format SQL.",
       PY | JS),
    _c("SEC031", "DOM XSS sink (innerHTML)",
       r"\.innerHTML\s*=|insertAdjacentHTML\s*\(", Severity.HIGH, "CWE-79",
       "Set text via textContent, or sanitize with DOMPurify before innerHTML.",
       WEB),
    _c("SEC032", "child_process code execution",
       r"child_process.*\b(?:exec|execSync)\s*\(|\b(?:execSync|exec)\s*\(\s*[`'\"]",
       Severity.HIGH, "CWE-78",
       "Use execFile/spawn with an argument array and no shell.",
       JS),
    _c("SEC033", "dangerouslySetInnerHTML without sanitization",
       r"dangerouslySetInnerHTML", Severity.HIGH, "CWE-79",
       "Sanitize with DOMPurify (or use text-only rendering) before raw HTML injection.",
       JS),
    _c("SEC034", "Remote script piped to shell",
       r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", Severity.HIGH, "CWE-494",
       "Download first, inspect checksum, then execute — never pipe remote bytes to a shell.",
       SHELL | frozenset({".md", ".yml", ".yaml"})),
    _c("SEC035", "XXE-prone XML parsing",
       r"(?:xml\.etree\.ElementTree|ET)\.(?:fromstring|parse)\s*\(|expat\.(?:ParserCreate|Parse)\s*\(",
       Severity.MEDIUM, "CWE-611",
       "Use defusedxml (defusedxml.ElementTree) to block external entity expansion.",
       PY,
       confidence="medium"),
    _c("SEC036", "Insecure temporary file (mktemp)",
       r"tempfile\.mktemp\s*\(", Severity.LOW, "CWE-377",
       "Use tempfile.NamedTemporaryFile / mkstemp (atomic create).",
       PY),
    _c("SEC037", "Dynamic import of non-literal module",
       r"(?<![\w.])(__import__\s*\(\s*(?!['\"])|importlib\.import_module\s*\(\s*(?!['\"]))",
       Severity.MEDIUM, "CWE-470",
       "Import from an allowlisted literal — dynamic module names enable code loading.",
       PY,
       confidence="medium"),
    _c("SEC040", "World-writable / full-permission file mode",
       r"chmod\s+(?:-R\s+)?777|chmod\s+a\+rwx|icacls\s+\S+\s+/grant\s+\S+:F\b",
       Severity.MEDIUM, "CWE-732",
       "Grant the minimum required permission (e.g. 750/640).",
       SHELL | YAML,
       confidence="medium"),
]

# --- file-level rules (need context across >1 line) -------------------------


@dataclass(frozen=True, slots=True)
class FileRule:
    rule_id: str
    title: str
    severity: Severity
    cwe: str
    fix: str
    require: tuple[re.Pattern, ...]  # ALL must match the file
    langs: frozenset
    confidence: str = "high"
    message: str = ""


FILE_RULES: list[FileRule] = [
    FileRule(
        "SEC038",
        "pull_request_target with checkout (PR-head code execution)",
        Severity.CRITICAL,
        "CWE-829",
        "Avoid pull_request_target for untrusted PRs; if needed never checkout the PR head with write permissions.",
        (re.compile(r"pull_request_target", re.IGNORECASE),
         re.compile(r"uses:\s*\S*actions/checkout", re.IGNORECASE)),
        YAML,
        message="Workflow combines pull_request_target + actions/checkout — a malicious PR can run code with secrets.",
    ),
    FileRule(
        "SEC039",
        "GitHub Action not pinned to a commit SHA",
        Severity.MEDIUM,
        "CWE-829",
        "Pin third-party actions to a full 40-char commit SHA (tagging is mutable).",
        (re.compile(r"uses:\s*(?!actions/|github/)[\w.\-]+/[\w.\-]+@[^\s`]*?(?<!\b[0-9a-f]{40})\s*$",
                    re.IGNORECASE | re.MULTILINE),),
        YAML,
        confidence="medium",
        message="Action referenced by tag/branch — a compromised upstream can silently change the code you run.",
    ),
]


def _ext_of(path: str) -> str:
    name = Path(path).name.lower()
    if name == ".env" or name.startswith(".env"):
        return ".env"
    return Path(name).suffix


def scan_text(path: str, text: str) -> list[Finding]:
    """Run line rules + file rules over one file."""
    findings: list[Finding] = []
    ext = _ext_of(path)
    lines = text.splitlines()

    for rule in CODE_RULES:
        if ext not in rule.langs:
            continue
        for lineno, line in enumerate(lines, 1):
            if not rule.regex.search(line):
                continue
            if rule.negate is not None and rule.negate.search(line):
                continue
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    message=rule.message or f"{rule.title}: {line.strip()[:120]}",
                    path=path,
                    line=lineno,
                    evidence=line.strip()[:160],
                    fix=rule.fix,
                    cwe=rule.cwe,
                    confidence=rule.confidence,
                    scanner="code",
                )
            )

    for frule in FILE_RULES:
        if ext not in frule.langs:
            continue
        if all(rx.search(text) for rx in frule.require):
            findings.append(
                Finding(
                    rule_id=frule.rule_id,
                    title=frule.title,
                    severity=frule.severity,
                    message=frule.message or frule.title,
                    path=path,
                    line=0,
                    evidence="",
                    fix=frule.fix,
                    cwe=frule.cwe,
                    confidence=frule.confidence,
                    scanner="code",
                )
            )
    return findings


def all_rules() -> list[tuple[str, str, Severity]]:
    """Rule catalog for ``sentinel rules``: (id, title, severity)."""
    catalog = [(r.rule_id, r.title, r.severity) for r in CODE_RULES]
    catalog += [(r.rule_id, r.title, r.severity) for r in FILE_RULES]
    return catalog
