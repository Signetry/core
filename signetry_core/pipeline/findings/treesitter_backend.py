"""Optional tree-sitter AST backend for higher-precision multi-language taint.

The line-based ``lang_taint`` / ``lang_crossfile`` modules are dependency-free and
zero-FP oriented, but being line-based they can miss deeply nested or multi-line
expressions in Go/Java/PHP/Ruby/C#. When the optional ``tree_sitter`` +
``tree_sitter_language_pack`` packages are installed, this backend parses those
languages into real ASTs and finds source→sink flows structurally.

It is **strictly optional and non-fatal**: if the packages are absent (the default),
``treesitter_available()`` returns False and the engine records the layer as
unavailable — exactly like the Semgrep layer. Nothing here is imported at module
load beyond a guarded probe, so the core stays dependency-free.
"""
from __future__ import annotations

import os

from .model import Finding, Severity, Source

# Grammar module name per extension in tree_sitter_language_pack.
_EXT_TO_LANG = {
    ".go": "go", ".java": "java", ".php": "php", ".rb": "ruby", ".cs": "c_sharp",
}

# Node types (per grammar) that denote a call, plus source/sink text markers reused
# from the line-based specs. We match on the *text* of call nodes so the rule set
# stays shared with the deterministic tier.
_SOURCE_MARKERS = (
    "URL.Query", "FormValue", "getParameter", "getHeader", "$_GET", "$_POST",
    "$_REQUEST", "$_COOKIE", "params[", "request.query", "Request.Query", "Request[",
)
_SINK_MARKERS = {
    "sql_injection": ("db.Query", ".Query(", ".Exec(", "executeQuery", "executeUpdate",
                      "createQuery", "mysqli_query", "->query", "SqlCommand"),
    "command_injection": ("exec.Command", "Runtime.getRuntime", "ProcessBuilder",
                          "system(", "shell_exec", "passthru", "Process.Start"),
}
_SINK_CWE = {"sql_injection": "CWE-89", "command_injection": "CWE-78"}


def treesitter_available() -> bool:
    """True only if both tree_sitter and a language pack are importable."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_language_pack  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 - any import failure = unavailable
        return False


def _iter_call_nodes(root, source: bytes):
    """Yield (node, text) for call-expression nodes in a parsed tree."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type in ("call_expression", "method_invocation", "function_call_expression",
                          "call", "invocation_expression", "method_call", "object_creation_expression"):
            yield node, source[node.start_byte:node.end_byte].decode("utf-8", "replace")
        stack.extend(node.children)


def scan_with_treesitter(files: dict[str, str]) -> list[Finding]:
    """Parse supported non-Python files with tree-sitter and flag call nodes that
    both build from a user source and hit a dangerous sink. Returns [] if the
    optional packages are unavailable (caller records the layer as unavailable)."""
    if not treesitter_available():
        return []
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:  # noqa: BLE001
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()
    for file, text in files.items():
        lang = _EXT_TO_LANG.get(os.path.splitext(file.lower())[1])
        if lang is None:
            continue
        try:
            parser = get_parser(lang)
            src = text.encode("utf-8", "replace")
            tree = parser.parse(src)
        except Exception:  # noqa: BLE001 - a grammar hiccup is never fatal
            continue
        for node, node_text in _iter_call_nodes(tree.root_node, src):
            has_source = any(m in node_text for m in _SOURCE_MARKERS)
            if not has_source:
                continue
            for cat, markers in _SINK_MARKERS.items():
                if any(m in node_text for m in markers):
                    line = node.start_point[0] + 1
                    key = (file, line, cat)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        rule_id=f"treesitter.{cat}", category=cat, severity=Severity.HIGH,
                        file=file, line=line,
                        title=f"{cat.replace('_', ' ').title()} (tree-sitter AST)",
                        detail="A parsed call expression both reads user input and reaches a "
                               "dangerous sink within the same expression tree.",
                        remediation="Parameterise / sanitise the user input before the sink.",
                        confidence=0.82, source=Source.DETERMINISTIC, cwe=_SINK_CWE[cat],
                    ))
                    break
    return findings
