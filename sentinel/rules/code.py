"""Code vulnerability rules (lightweight SAST).

Line-oriented regular expressions per language — deliberately conservative:
every rule fires on a single unambiguous (logical) line so the report can
point at an exact ``path:line``. Bracket/comma continuations are collapsed
into logical lines first (see ``_logical_lines``) so multi-line calls are
matched (and their safe-kwarg negations seen) while findings still report the
FIRST physical line. Each regex probe is capped at ``_PROBE_MAX`` characters
so pathological 100KB+ lines cannot hang the scan (ReDoS guard). File-level
rules (workflow context) are handled separately in ``FILE_RULES``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ..models import Finding, Severity
from .secrets import redact

PY = frozenset({".py"})
JS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"})
WEB = frozenset({".js", ".jsx", ".ts", ".tsx", ".html", ".vue"})
SHELL = frozenset({".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"})
YAML = frozenset({".yml", ".yaml"})
CONFIG = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".toml"})
DOCKER = frozenset({".dockerfile"})  # Dockerfile / dockerfile.dev via _ext_of()
GO = frozenset({".go"})
JAVA = frozenset({".java"})
RB = frozenset({".rb", ".rake"})
PHP = frozenset({".php", ".phtml", ".php3", ".php4", ".php5"})
CS = frozenset({".cs"})
NATIVE = frozenset({".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".c++", ".h++"})
ALL = frozenset({".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".sh", ".bash",
                 ".yml", ".yaml", ".env", ".ini", ".cfg", ".conf", ".html", ".vue",
                 ".dockerfile", ".go", ".java", ".rb", ".rake", ".php", ".phtml",
                 ".php3", ".php4", ".php5", ".cs", ".c", ".h", ".cpp", ".hpp",
                 ".cc", ".cxx", ".c++", ".h++"})


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
       PY | JS | RB | PHP),
    _c("SEC021", "exec() / new Function() code execution",
       r"(?<![\w.])(?:exec\s*\(|new\s+Function\s*\()", Severity.HIGH, "CWE-94",
       "Never build code from strings — use data-driven dispatch instead.",
       PY | JS | RB),
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
       # '*' must sit in an origin VALUE position — a route glob like
       # resources={r"/api/*": ...} is not a wildcard origin.
       r"origins?\s*['\"]?\s*[:=]\s*['\"]\*"
       r"|Access-Control-Allow-Origin['\"]?\s*[,:)]\s*['\"]?\*",
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
        SHELL | frozenset({".md", ".yml", ".yaml"}) | DOCKER,
        negate=re.compile(r"^\s*#")),
    _c("SEC035", "XXE-prone XML parsing",
       r"(?:xml\.etree\.ElementTree|ET)\.(?:fromstring|parse)\s*\(|expat\.(?:ParserCreate|Parse)\s*\(",
       Severity.MEDIUM, "CWE-611",
       "Use defusedxml (defusedxml.ElementTree) to block external entity expansion.",
       PY,
       confidence="medium"),
    _c("SEC036", "Insecure temporary file (mktemp/tmpnam)",
       r"tempfile\.mktemp\s*\(|(?<![\w.])(?:mktemp|tmpnam|tempnam)\s*\(",
       Severity.LOW, "CWE-377",
       "Use NamedTemporaryFile / mkstemp (or mkstemp-equivalent) — predictable "
       "names are raceable (symlink attacks).",
       PY | NATIVE),
    _c("SEC037", "Dynamic import of non-literal module",
       # (?!\s*['"]) form: the lookahead consumes leading whitespace itself, so
       # \s* can't backtrack to a zero-width match that then sees a space.
       r"(?<![\w.])(__import__\s*\((?!\s*['\"])|importlib\.import_module\s*\((?!\s*['\"]))",
       Severity.MEDIUM, "CWE-470",
       "Import from an allowlisted literal — dynamic module names enable code loading.",
       PY,
       confidence="medium"),
    _c("SEC040", "World-writable / full-permission file mode",
       # [0-7]{0,3}777 covers chmod 0777 / 1777 / -R 0777; (?![0-9]) stops
       # "chmod 7770"-style modes from matching the leading 777.
       r"chmod\s+(?:-R\s+)?[0-7]{0,3}777(?![0-9])|chmod\s+a\+rwx|icacls\s+\S+\s+/grant\s+\S+:F\b|0o777\b",
       Severity.MEDIUM, "CWE-732",
       "Grant the minimum required permission (e.g. 750/640).",
       SHELL | YAML | PY,
       confidence="medium"),
    _c("SEC042", "Workflow token permissions: write-all",
       r"permissions\s*:\s*write-all", Severity.MEDIUM, "CWE-250",
       "Declare least-privilege permissions per job (e.g. contents: read).",
       YAML),
    _c("SEC043", "Open redirect (user input into redirect target)",
       r"redirect\s*\(\s*request\.(?:args|form|GET|POST)"
       r"|res\.redirect\s*\(\s*(?:req\.(?:query|params|body)|request\.query)",
       Severity.MEDIUM, "CWE-601",
       "Allowlist redirect targets or map user input through a fixed lookup table.",
       PY | JS,
       confidence="medium"),
    _c("SEC044", "Server-side template from dynamic string (SSTI)",
       r"render_template_string\s*\(|from_string\s*\([^)]*(?:\+|request|input|params)",
       Severity.MEDIUM, "CWE-1336",
       "Render from template files with a fixed name, never from user-controlled strings.",
       PY,
       confidence="medium"),
    _c("SEC045", "Unsafe archive extraction (extractall)",
       r"\.extractall\s*\(",
        Severity.MEDIUM, "CWE-22",
        "Filter members (tarfile data_filter / safe extraction) to block path traversal.",
        PY,
        confidence="medium",
        negate=re.compile(r"\bfilter\s*=", re.IGNORECASE)),
    _c("SEC046", "HTTP call without a timeout",
       r"(?<![\w.])(?:requests|httpx)\.(?:get|post|put|delete|head|patch|request)\s*\("
       r"(?!.*\btimeout\s*=)",
       Severity.LOW, "CWE-400",
       "Always pass timeout= — an unbounded request hangs the process.",
       PY,
       confidence="low"),
    _c("SEC047", "TLS verification disabled in download (-k / --insecure)",
       r"(?:curl|wget)\s[^|\n]*?(?:-k|--insecure)\b",
       Severity.MEDIUM, "CWE-295",
       "Drop -k/--insecure; fix the trust store instead.",
       SHELL | YAML | frozenset({".md"}) | DOCKER,
       confidence="medium"),
    _c("SEC048", "Security check implemented with assert",
       r"(?<![\w.])assert\s+[^\n#]*(?:is_admin|is_authenticated|is_superuser"
       r"|has_perm|check_password|verify_token|is_authorized|csrf"
       r"|is_valid_user|logged_in)",
       Severity.HIGH, "CWE-617",
       "Use an explicit if/raise — asserts are stripped under python -O, "
       "silently disabling the check.",
       PY,
       confidence="medium"),
    _c("SEC049", "Deprecated crypto.createCipher / createDecipher",
       r"crypto\.create(?:Decipher|Cipher)(?:Sync)?\s*\(",
       Severity.MEDIUM, "CWE-327",
       "Use createCipheriv/createDecipheriv with an explicit IV and algorithm.",
       JS),
    _c("SEC056", "DOM XSS sink (document.write)",
       r"document\.write(?:ln)?\s*\(",
       Severity.MEDIUM, "CWE-79",
       "Build the DOM with textContent/createElement — never write raw HTML from strings.",
       WEB,
       confidence="medium"),
    _c("SEC057", "jwt.decode without an explicit algorithms allowlist",
       r"(?<![\w.])(?:jwt|jsonwebtoken)\.decode\s*\((?![^)]{0,400}\balgorithms\s*=)",
       Severity.HIGH, "CWE-347",
       "Pass algorithms=['HS256'] (your exact set) to block algorithm-confusion attacks.",
       PY | JS,
       confidence="medium"),
    # --- Go -----------------------------------------------------------------
    _c("SEC058", "SQL built with fmt.Sprintf (Go)",
       r"fmt\.Sprintf\s*\(\s*[\"`][^\"`]*\b(?:SELECT|INSERT INTO|UPDATE|DELETE FROM|DROP TABLE)\b"
       r"|db\.(?:Query|Exec|QueryRow)\w*\s*\(\s*(?:fmt\.Sprintf|[^\n]*?\+\s*\w)",
       Severity.HIGH, "CWE-89",
       "Use database/sql parameterized queries (db.Query(q, args...)) — never format SQL.",
       GO,
       confidence="medium"),
    _c("SEC059", "TLS InsecureSkipVerify enabled (Go)",
       r"InsecureSkipVerify\s*:\s*true",
       Severity.HIGH, "CWE-295",
       "Verify certificates — pin a CA bundle instead of skipping verification.",
       GO),
    _c("SEC063", "Shell invocation via sh/bash -c (Go/Java/Ruby)",
       r"exec\.Command\s*\(\s*\"(?:sh|bash|zsh|cmd|powershell)\"\s*,\s*\"-c\""
       r"|Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(\s*new\s+String\[\]\s*\{\s*\"(?:sh|bash|zsh|cmd|powershell)\"\s*,\s*\"-c\""
       r"|(?<![\w.])(?:system|exec)\s*\(\s*\"(?:sh|bash|zsh|cmd|powershell)\"\s*,\s*\"-c\"",
       Severity.HIGH, "CWE-78",
       "Call the binary directly with an argument list — no shell, no string building.",
       GO | JAVA | RB),
    # --- Java ---------------------------------------------------------------
    _c("SEC064", "Runtime.exec / ProcessBuilder shell execution (Java)",
       r"Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|new\s+ProcessBuilder\s*\(",
       Severity.HIGH, "CWE-78",
       "Avoid shelling out; if required, validate inputs and never pass a single shell string.",
       JAVA,
       confidence="medium"),
    _c("SEC065", "Weak message digest (MD5 / SHA-1) in Java",
       # [^)]* after the quote allows trailing args: getInstance("MD5", provider).
       r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1)\"[^)]*\)",
       Severity.MEDIUM, "CWE-327",
       "Use SHA-256+ (or HMAC) — MD5/SHA-1 are broken for security purposes.",
       JAVA,
       confidence="medium"),
    _c("SEC066", "Weak cipher algorithm (DES / RC4 / Blowfish) in Java",
       r"Cipher\.getInstance\s*\(\s*\"(?:DES|DESede|RC4|RC2|Blowfish|PBEWithMD5And)",
       Severity.HIGH, "CWE-327",
       "Use AES-GCM (e.g. \"AES/GCM/NoPadding\") with a random IV.",
       JAVA),
    _c("SEC067", "Java native deserialization (ObjectInputStream)",
       r"(?<![\w.])new\s+ObjectInputStream\s*\(|\.readObject\s*\(",
       Severity.HIGH, "CWE-502",
       "Do not deserialize untrusted bytes — use JSON with a schema, or a safe format.",
       JAVA,
       confidence="medium"),
    # --- Ruby ---------------------------------------------------------------
    _c("SEC068", "Unsafe YAML.load (Ruby Psych)",
       r"(?<![\w.])YAML\.load\s*\(",
       Severity.HIGH, "CWE-502",
       "Use YAML.safe_load (Psych.safe_load) — plain load instantiates arbitrary objects.",
       RB,
       negate=re.compile(r"safe_load", re.IGNORECASE)),
    _c("SEC069", "Shell command with interpolation (Ruby)",
       r"(?<![\w.])(?:system|exec)\s*(?:\([^\n]*?#\{|\s+[\"'][^\n]*?#\{)"
       r"|(?<![\w.])(?:Open3\.(?:capture2?|popen)|IO\.popen)\s*(?:\([^\n]*?#\{|\s+[\"'][^\n]*?#\{)"
       r"|`[^`\n]*#\{",
       Severity.HIGH, "CWE-78",
       "Pass argv arrays without a shell (system([\"bin\", \"arg\"])) — never interpolate into a shell string.",
        RB,
        confidence="medium"),
    # --- C / C++ --------------------------------------------------------------
    _c("SEC087", "gets() banned function (C/C++)",
       r"(?<![\w.])gets\s*\(",
       Severity.HIGH, "CWE-242",
       "gets() cannot bound input — use fgets(buf, sizeof(buf), stdin) or std::getline.",
       NATIVE),
    _c("SEC088", "Unbounded string copy strcpy/strcat (C/C++)",
       r"(?<![\w.])str(?:cpy|cat)\s*\(",
       Severity.HIGH, "CWE-120",
       "Use strncpy/strlcpy/strlcat (or std::string in C++) and always bound the copy.",
       NATIVE),
    _c("SEC089", "sprintf() without bounds (C/C++)",
       r"(?<![\w.])(?:sprintf|vsprintf)\s*\(",
       Severity.HIGH, "CWE-120",
       "Use snprintf(dst, size, fmt, ...) — bound the output buffer. "
       "snprintf/vsnprintf do not match this rule.",
       NATIVE),
    _c("SEC090", "Shell via system()/popen() (C/C++)",
       r"(?<![\w.])(?:system|popen)\s*\(",
       Severity.HIGH, "CWE-78",
       "Avoid the shell — use fork+execv/execve with an argv array and a fixed binary path.",
       NATIVE,
       confidence="medium"),
    _c("SEC091", "printf with non-literal format string (C/C++)",
       r"(?<![\w.])(?:v?printf)\s*\(\s*[A-Za-z_]\w*\s*[,)]",
       Severity.HIGH, "CWE-134",
       "Hardcode the format string: printf(\"%s\", buf) — never pass user data as the format.",
       NATIVE,
       confidence="medium"),
    # --- PHP ----------------------------------------------------------------
    _c("SEC077", "Unsafe unserialize() (PHP)",
       r"(?<![\w.])unserialize\s*\(",
       Severity.HIGH, "CWE-502",
       "Never unserialize untrusted data — use json_decode with an explicit schema.",
       PHP,
       confidence="medium"),
    _c("SEC078", "Shell command execution (PHP)",
       # (?<!->) keeps $pdo->exec($sql) (a PDO method) from counting while
       # bare exec(...) / system(...) still fire.
       r"(?<!->)(?<![\w.])(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(",
       Severity.HIGH, "CWE-78",
       "Avoid shelling out; validate/allowlist inputs and use escapeshellarg per argument.",
       PHP,
       confidence="medium"),
    _c("SEC079", "Deprecated mysql_query() API (PHP)",
       r"(?<![\w.])mysql_query\s*\(",
       Severity.HIGH, "CWE-89",
       "mysql_* was removed in PHP 7 — use mysqli/PDO with parameterized queries.",
       PHP),
    _c("SEC080", "preg_replace() with /e code-execution modifier (PHP)",
       # Two delimiters required (/pattern/e) — a pattern string merely ending
       # in 'e' ("/abcde") is not the /e modifier.
       r"preg_replace\s*\(\s*[\"'][^\"'\n]*/[^\"'\n]*/[a-zA-Z]*e[a-zA-Z]*['\"]",
       Severity.HIGH, "CWE-94",
       "Use preg_replace_callback with a real callback — the /e modifier evals the replacement.",
       PHP),
    _c("SEC081", "extract() on request superglobals (PHP)",
       r"(?<![\w.])extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b",
       Severity.MEDIUM, "CWE-915",
       "Never extract() request data into scope — it overwrites arbitrary variables.",
       PHP,
       confidence="medium"),
    _c("SEC082", "Weak password hash md5()/sha1() (PHP)",
       r"(?<![\w.$])(?:md5|sha1)\s*\(",
       Severity.MEDIUM, "CWE-916",
       "Use password_hash()/password_verify() (bcrypt/argon2) — md5/sha1 are not password KDFs.",
       PHP,
       confidence="medium"),
    # --- C# -----------------------------------------------------------------
    _c("SEC083", "SQL built by string concatenation (C#)",
       r"(?:SqlCommand|OleDbCommand|MySqlCommand|SqliteCommand)\s*\([^)]*\+|"
       r"(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar)\s*\(\s*[^\n;]*\+",
       Severity.HIGH, "CWE-89",
       "Use parameterized commands (cmd.Parameters.AddWithValue / SqlParameter).",
       CS,
       confidence="medium"),
    _c("SEC084", "Shell launched via Process.Start (C#)",
       r"Process\.Start\s*\(\s*(?:@?\"(?:cmd|powershell|bash)|\"cmd\.exe\"|\"powershell\.exe\")|"
       r"FileName\s*=\s*\"(?:cmd\.exe|powershell\.exe|bash)\"",
       Severity.HIGH, "CWE-78",
       "Start the target binary directly with an argument list — no shell wrapper.",
       CS),
    _c("SEC085", "Weak crypto algorithm (C#)",
       r"(?:DESCryptoServiceProvider|RC2CryptoServiceProvider|"
       r"new\s+MD5CryptoServiceProvider|SHA1CryptoServiceProvider)",
       Severity.HIGH, "CWE-327",
       "Use AES-GCM (AesGcm) or SHA-256+ — DES/RC2/MD5/SHA-1 are broken.",
       CS),
    _c("SEC086", "BinaryFormatter / SoapFormatter deserialization (C#)",
       r"(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer)\b",
       Severity.HIGH, "CWE-502",
       "Do not deserialize untrusted bytes with BinaryFormatter — use System.Text.Json with a schema.",
       CS,
       confidence="medium"),
    _c("SEC071", "Dockerfile base image pinned to :latest",
       r"^\s*FROM\s+\S+:latest\b", Severity.MEDIUM, "CWE-829",
       "Pin an explicit immutable version (e.g. :3.19) or a digest.",
       DOCKER),
    _c("SEC072", "Secret baked into Dockerfile ENV/ARG",
       # Whole-token credential names only: the keyword must be a delimited
       # token of the variable (API_KEY, GITHUB_TOKEN, DB_PASSWORD) so
       # KEYBOARD_LAYOUT / SECRETS_DIR / TOKENIZER_FILE never match; PWD only
       # counts with a prefix (MYSQL_PWD), never bare `ENV PWD=` (workdir).
       r"^\s*(?:ENV|ARG)\s+"
       r"(?:(?:[A-Za-z0-9]+_)+(?:KEY|TOKEN|SECRET|PASSW(?:OR)?D|PWD|CREDENTIALS?)"
       r"|(?:KEY|TOKEN|SECRET|PASSW(?:OR)?D|CREDENTIALS?)(?:_[A-Za-z0-9]+)*)"
       r"\s*=",
        Severity.HIGH, "CWE-798",
        "Pass secrets at run time (orchestrator secrets / docker run -e), "
        "never bake them into the image.",
        DOCKER,
        confidence="medium"),
    _c("SEC073", "Container escape vector (privileged / docker.sock mount)",
       r"privileged\s*:\s*true|docker\.sock", Severity.HIGH, "CWE-250",
       "Drop privileged mode; never mount the docker socket into a container.",
       YAML | DOCKER,
       confidence="medium"),
    _c("SEC075", "Dockerfile ADD from remote URL",
       r"^\s*ADD\s+https?://", Severity.MEDIUM, "CWE-494",
       "Use COPY with a locally fetched artifact — remote ADD is unverified and can change under you.",
       DOCKER),
    _c("SEC076", "Container explicitly running as root",
       r"^\s*USER\s+root\b", Severity.MEDIUM, "CWE-250",
       "Create a dedicated non-root user and switch to it before CMD/ENTRYPOINT.",
       DOCKER),
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
        # Key form only: a comment mentioning pull_request_target plus any
        # checkout must not escalate to CRITICAL.
        (re.compile(r"^\s*pull_request_target\s*:", re.IGNORECASE | re.MULTILINE),
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
    if name == "dockerfile" or name.startswith("dockerfile."):
        return ".dockerfile"
    return Path(name).suffix


# --- stateful scanners (need >1 line of context) ----------------------------
# SEC041: `${{ github.event.* }}` / `${{ github.head_ref }}` interpolated into a
# `run:` step is shell script injection (GitHub's own hardening guide). `if:`
# and `env:` contexts are expression/data positions — not flagged.
_UNTRUSTED_CTX = re.compile(r"\$\{\{\s*(?:github\.event\.[A-Za-z0-9_.]+|github\.head_ref)\b")
# `run:` must be the YAML KEY (optional `- ` list dash) — not a `run:` mention
# inside a description/string value.
_RUN_BLOCK_RE = re.compile(r"^\s*-?\s*run\s*:\s*[|>][-+]?\s*$")
_RUN_INLINE_RE = re.compile(r"^\s*-?\s*run\s*:")


def _scan_actions(path: str, text: str) -> list[Finding]:
    """SEC041 — untrusted context inside a ``run:`` step (inline or block)."""
    findings: list[Finding] = []
    in_run_block = False
    run_indent = -1
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            # YAML/shell comment — never a run step, and a commented-out
            # expression cannot inject (the shell never executes it).
            continue
        indent = len(line) - len(line.lstrip())
        if in_run_block:
            if stripped and indent <= run_indent:
                in_run_block = False  # block ended — fall through to normal handling
            elif _UNTRUSTED_CTX.search(line):
                findings.append(_action_finding(path, lineno, line))
                continue
        if _RUN_BLOCK_RE.match(line):
            in_run_block = True
            run_indent = indent
            continue
        if _RUN_INLINE_RE.search(line) and _UNTRUSTED_CTX.search(line):
            findings.append(_action_finding(path, lineno, line))
    return findings


def _action_finding(path: str, lineno: int, line: str) -> Finding:
    return Finding(
        rule_id="SEC041",
        title="Script injection via untrusted context in run:",
        severity=Severity.HIGH,
        message="Untrusted GitHub context interpolated into a shell run step — "
                "a malicious PR/issue title becomes arbitrary code.",
        path=path,
        line=lineno,
        evidence=line.strip()[:160],
        fix="Pass the value via an intermediate env var and quote it in the shell "
            "($VAR), or sanitize before use — see GitHub script-injection hardening.",
        cwe="CWE-94",
        confidence="high",
        scanner="code",
    )


# SEC070: untagged FROM — needs stage tracking so `FROM builder` (a prior
# `FROM x AS builder`) is not flagged while `FROM alpine` (implicit latest) is.
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?\s*$", re.IGNORECASE)


def _image_has_tag(image: str) -> bool:
    """True when the image ref pins a tag or digest (port colons don't count)."""
    if "@" in image:
        return True
    return ":" in image.rsplit("/", 1)[-1]


def _scan_dockerfile(path: str, text: str) -> list[Finding]:
    """SEC070 — FROM without a tag/digest, skipping named stages and ARG refs."""
    findings: list[Finding] = []
    stages: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _FROM_RE.match(line)
        if not m:
            continue
        image, stage = m.group(1), m.group(2)
        if stage:
            stages.add(stage.lower())
        if image.lower() == "scratch":
            continue  # empty scratch image — has no tag/digest by design
        if "$" in image:  # ARG-templated tag — cannot evaluate statically
            continue
        if image.lower() in stages:
            continue  # re-entering a previously built stage, not a registry pull
        if _image_has_tag(image):
            continue
        findings.append(Finding(
            rule_id="SEC070",
            title="Dockerfile base image without a pinned tag",
            severity=Severity.MEDIUM,
            message=f"FROM {image} resolves to a moving target (implicit :latest) — "
                    "builds are not reproducible.",
            path=path,
            line=lineno,
            evidence=line.strip()[:160],
            fix="Pin an explicit immutable version (e.g. :3.19) or a digest.",
            cwe="CWE-829",
            confidence="high",
            scanner="code",
        ))
    return findings


# Cap on the text any single regex probe may see (ReDoS / pathological-line
# guard — measured 3-69s hangs on 120-210KB lines before this).
_PROBE_MAX = 10_000


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Collapse bracket/comma continuations into logical lines.

    Returns ``(first_physical_line, text)`` pairs so findings still point at
    the line where the construct STARTS. The joined text stays raw — trailing
    comments are deliberately NOT stripped (``#`` inside C# paths / shell
    strings / regexes would be mangled). Each emitted buffer is capped at
    ``_PROBE_MAX`` characters, so a pathological line (or an unclosed-bracket
    run) can never build an unbounded buffer.
    """
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, ln in enumerate(lines):
        if not buf:
            start = i
        piece = ln.strip()
        buf += (" " if buf else "") + piece
        if len(buf) >= _PROBE_MAX:  # hard cap — flush, keep going
            out.append((start + 1, buf[:_PROBE_MAX]))
            buf = ""
            continue
        if buf.count("(") > buf.count(")") or piece.endswith((",", "(")):
            if i < len(lines) - 1:
                continue
        out.append((start + 1, buf))
        buf = ""
    if buf:
        out.append((start + 1, buf))
    return out


# SEC072 evidence/message carry a credential — mask the value half before the
# Finding is built so raw secrets never reach reports/SARIF.
_DOCKER_ASSIGN_RE = re.compile(r"^(\s*(?:ENV|ARG)\s+[A-Za-z0-9_]+\s*=\s*)(.*)$")
_REDACT_RULES = frozenset({"SEC072"})


def _redact_credential(text: str) -> str:
    """Mask the value of an ``ENV|ARG name=value`` line (keeps the name)."""
    m = _DOCKER_ASSIGN_RE.match(text)
    if not m:
        return redact(text)  # unexpected shape — over-redact, never leak
    prefix, value = m.group(1), m.group(2).strip()
    if not value:
        return text
    quote = ""
    if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
        quote, inner = value[0], value[1:-1]
    else:
        inner = value
    if not inner:
        return text
    return f"{prefix}{quote}{redact(inner)}{quote}"


def scan_text(path: str, text: str) -> list[Finding]:
    """Run line rules + file rules over one file."""
    findings: list[Finding] = []
    ext = _ext_of(path)
    logical = _logical_lines(text.splitlines())

    for rule in CODE_RULES:
        if ext not in rule.langs:
            continue
        redact_hit = rule.rule_id in _REDACT_RULES
        for lineno, buf in logical:
            probe = buf[:_PROBE_MAX]  # ReDoS/line-length cap: regex only sees this
            if not rule.regex.search(probe):
                continue
            if rule.negate is not None and rule.negate.search(probe):
                continue
            shown = _redact_credential(probe) if redact_hit else probe
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    message=rule.message or f"{rule.title}: {shown.strip()[:120]}",
                    path=path,
                    line=lineno,
                    evidence=shown.strip()[:160],
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

    if ext in YAML:
        findings.extend(_scan_actions(path, text))
    if ext in DOCKER:
        findings.extend(_scan_dockerfile(path, text))
    return findings


def all_rules() -> list[tuple[str, str, Severity]]:
    """Rule catalog for ``sentinel rules``: (id, title, severity)."""
    catalog = [(r.rule_id, r.title, r.severity) for r in CODE_RULES]
    catalog += [(r.rule_id, r.title, r.severity) for r in FILE_RULES]
    catalog += [
        ("SEC041", "Script injection via untrusted context in run:", Severity.HIGH),
        ("SEC070", "Dockerfile base image without a pinned tag", Severity.MEDIUM),
    ]
    return catalog
