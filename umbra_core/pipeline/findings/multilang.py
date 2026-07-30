"""Multi-language regex rules (Go, Java, Ruby, PHP, C#), dependency-free.

The Python AST engine gives precise, low-FP coverage for Python; JavaScript/TS get
targeted regex rules. This module extends breadth to the other common server
languages so Umbra can scan polyglot real-world repos (the axis where LLM scanners
otherwise had an edge). Each rule is written narrowly — it requires a user-input or
concatenation/interpolation signal — so a compiled-in constant does not trip it.

Rules are grouped by file extension. A rule is
``(rule_id, category, severity, cwe, pattern, title, detail, remediation, confidence)``.
"""
from __future__ import annotations

import re

from .model import Finding, Severity, Source

# User-input signals per language family (for the "requires taint" rules).
# Kept broad but each rule pattern also encodes a concat/interpolation shape.

_GO_RULES: list[tuple] = [
    ("go.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"exec\.Command\s*\(\s*\"(?:sh|bash|cmd)\"|exec\.Command\([^)]*\+"),
     "Command injection via exec.Command",
     "A shell/command is built with concatenation or invoked via a shell.",
     "Pass arguments as separate exec.Command params; avoid a shell.", 0.8),
    ("go.sql_injection", "sql_injection", Severity.HIGH, "CWE-89",
     re.compile(r'(?i)(Query|Exec|QueryRow)\s*\(\s*(?:"[^"]*"\s*\+|fmt\.Sprintf\s*\(\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE))'),
     "SQL built with string concatenation/Sprintf",
     "A SQL statement is assembled with + or fmt.Sprintf instead of placeholders.",
     "Use parameterised queries (db.Query(\"... WHERE x=$1\", v)).", 0.8),
    ("go.weak_hash", "weak_crypto", Severity.MEDIUM, "CWE-327",
     re.compile(r"\b(md5|sha1)\.New\s*\(|\b(md5|sha1)\.Sum\s*\("),
     "Weak hash algorithm (md5/sha1)",
     "md5/sha1 are broken for security use.",
     "Use sha256+ or a password KDF (bcrypt/scrypt/argon2).", 0.72),
    ("go.tls_skip_verify", "tls_disabled", Severity.HIGH, "CWE-295",
     re.compile(r"InsecureSkipVerify\s*:\s*true"),
     "TLS verification disabled (InsecureSkipVerify: true)",
     "Disabling certificate verification enables MITM.",
     "Keep verification on; fix the trust chain.", 0.85),
]

_JAVA_RULES: list[tuple] = [
    ("java.sql_injection", "sql_injection", Severity.HIGH, "CWE-89",
     re.compile(r"(?i)(executeQuery|executeUpdate|execute|createQuery)\s*\(\s*\"[^\"]*\"\s*\+|"
                r"Statement[^;]*\.\s*execute\w*\([^)]*\+"),
     "SQL built with string concatenation",
     "A JDBC/JPA query is concatenated with a variable instead of using a prepared statement.",
     "Use PreparedStatement with bound parameters.", 0.8),
    ("java.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+|ProcessBuilder\s*\([^)]*\+"),
     "Command injection via Runtime.exec/ProcessBuilder",
     "A command is built with concatenation and executed.",
     "Pass arguments as a list; validate/allowlist inputs.", 0.8),
    ("java.weak_hash", "weak_crypto", Severity.MEDIUM, "CWE-327",
     re.compile(r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1)"'),
     "Weak hash algorithm (MD5/SHA-1)",
     "MD5/SHA-1 are broken for security use.",
     "Use SHA-256+ or a password hash (bcrypt/PBKDF2/Argon2).", 0.72),
    ("java.deserialization", "insecure_deserialization", Severity.HIGH, "CWE-502",
     re.compile(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
     "Java native deserialization",
     "ObjectInputStream.readObject on untrusted data enables RCE gadget chains.",
     "Avoid native serialization for untrusted data; use a safe format + allowlist.", 0.7),
    ("java.xxe", "xxe", Severity.HIGH, "CWE-611",
     re.compile(r"DocumentBuilderFactory\.newInstance\s*\(\s*\)|SAXParserFactory\.newInstance\s*\(\s*\)"),
     "XML parser created without XXE hardening",
     "Default DocumentBuilder/SAXParser factories may resolve external entities (XXE).",
     "Disable DOCTYPE/external entities on the factory before parsing.", 0.6),
]

_RUBY_RULES: list[tuple] = [
    ("ruby.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"(?:system|exec|`|%x)\s*\(?\s*[\"'][^\"']*#\{|Open3\.[a-z_]+\([^)]*#\{"),
     "Command injection via interpolation",
     "A shell command interpolates a variable (#{...}).",
     "Use system with separate args; validate inputs.", 0.78),
    ("ruby.sql_injection", "sql_injection", Severity.HIGH, "CWE-89",
     re.compile(r"(?i)(where|find_by_sql|execute)\s*\(?\s*[\"'][^\"']*#\{"),
     "SQL built with string interpolation",
     "An ActiveRecord query interpolates a variable directly into SQL.",
     "Use parameterised queries: where(\"x = ?\", val).", 0.78),
    ("ruby.eval", "code_injection", Severity.HIGH, "CWE-95",
     re.compile(r"(?<![.\w])(eval|instance_eval|class_eval)\s*\("),
     "Dynamic code execution via eval",
     "eval/instance_eval on user input is RCE.",
     "Remove eval; use explicit dispatch.", 0.75),
    ("ruby.yaml_load", "insecure_deserialization", Severity.HIGH, "CWE-502",
     re.compile(r"YAML\.load\s*\(|Marshal\.load\s*\("),
     "Unsafe YAML/Marshal load",
     "YAML.load/Marshal.load on untrusted data can instantiate arbitrary objects.",
     "Use YAML.safe_load; never Marshal.load untrusted data.", 0.72),
]

_PHP_RULES: list[tuple] = [
    ("php.sql_injection", "sql_injection", Severity.HIGH, "CWE-89",
     re.compile(r"(?i)(mysqli_query|->query|mysql_query|->exec)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"),
     "SQL built directly from a superglobal",
     "A query embeds $_GET/$_POST/etc without a prepared statement.",
     "Use prepared statements (PDO/mysqli with bound params).", 0.82),
    ("php.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"),
     "Command injection from a superglobal",
     "A shell command includes $_GET/$_POST/etc.",
     "Avoid shell calls on user input; use escapeshellarg + allowlist.", 0.82),
    ("php.code_injection", "code_injection", Severity.HIGH, "CWE-95",
     re.compile(r"(?i)\beval\s*\(\s*\$|assert\s*\(\s*\$_"),
     "Dynamic code execution via eval",
     "eval() on a variable/superglobal is RCE.",
     "Remove eval; use explicit logic.", 0.8),
    ("php.file_inclusion", "path_traversal", Severity.HIGH, "CWE-98",
     re.compile(r"(?i)(include|include_once|require|require_once|fopen|file_get_contents)\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)"),
     "File inclusion / path from a superglobal",
     "A file path/include uses user input, enabling LFI/RFI or traversal.",
     "Allowlist filenames; never pass user input to include/require.", 0.8),
    ("php.deserialization", "insecure_deserialization", Severity.HIGH, "CWE-502",
     re.compile(r"(?i)unserialize\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)"),
     "PHP object injection via unserialize",
     "unserialize() on user input enables PHP object injection.",
     "Use json_decode for untrusted data; never unserialize it.", 0.8),
    ("php.weak_hash", "weak_crypto", Severity.MEDIUM, "CWE-327",
     re.compile(r"(?i)\b(md5|sha1)\s*\(\s*\$(pass|pwd|password|secret)"),
     "Weak hash for a password/secret",
     "md5()/sha1() for passwords is broken.",
     "Use password_hash() (bcrypt/argon2).", 0.72),
]

_CSHARP_RULES: list[tuple] = [
    ("csharp.sql_injection", "sql_injection", Severity.HIGH, "CWE-89",
     re.compile(r'(?i)(SqlCommand|CommandText)\s*[=(]\s*[$@]?"[^"]*"\s*\+|"\s*\+\s*\w+\s*\+\s*"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)'),
     "SQL built with string concatenation",
     "A SqlCommand text is concatenated with a variable.",
     "Use parameterised SqlCommand with SqlParameter.", 0.78),
    ("csharp.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"Process\.Start\s*\([^)]*\+|ProcessStartInfo[^;]*Arguments\s*=\s*[^;]*\+"),
     "Command injection via Process.Start",
     "A process is started with a concatenated command/arguments.",
     "Pass arguments via ArgumentList; validate inputs.", 0.78),
    ("csharp.weak_hash", "weak_crypto", Severity.MEDIUM, "CWE-327",
     re.compile(r"\b(MD5|SHA1)\.Create\s*\(\s*\)"),
     "Weak hash algorithm (MD5/SHA1)",
     "MD5/SHA1 are broken for security use.",
     "Use SHA256+ or a password hash (PBKDF2/bcrypt/Argon2).", 0.72),
]

_EXT_RULES: dict[str, list[tuple]] = {
    ".go": _GO_RULES,
    ".java": _JAVA_RULES,
    ".rb": _RUBY_RULES,
    ".php": _PHP_RULES,
    ".cs": _CSHARP_RULES,
}

# Language families for which this module provides coverage (used by the walker).
MULTI_LANG_EXTS = frozenset(_EXT_RULES)


def scan_multilang(file: str, text: str) -> list[Finding]:
    """Run the regex rules for ``file``'s language (by extension). Empty for
    unsupported extensions (Python/JS are handled by the AST/JS engine)."""
    import os

    ext = os.path.splitext(file.lower())[1]
    rules = _EXT_RULES.get(ext)
    if not rules:
        return []
    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        for (rid, cat, sev, cwe, pat, title, detail, rem, conf) in rules:
            if pat.search(line):
                findings.append(Finding(
                    rule_id=rid, category=cat, severity=sev, file=file, line=idx,
                    title=title, detail=detail, remediation=rem, confidence=conf,
                    source=Source.DETERMINISTIC, cwe=cwe,
                ))
    # Dedup identical (file, line, category).
    seen: set[tuple[str, int, str]] = set()
    out: list[Finding] = []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            out.append(f)
    return out
