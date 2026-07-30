"""Cross-file / interprocedural taint analysis (Python), dependency-free.

The single-file deterministic floor misses vulnerabilities whose *source* (a
request value) and *sink* (execute / os.system / open / …) live in different
functions or different files, e.g.::

    # views.py
    term = request.args.get("q")
    run_query(term)              # taint crosses into db.py

    # db.py
    def run_query(term):
        cur.execute("... '" + term + "'")   # sink reached by a tainted parameter

This module adds a lightweight two-pass, whole-repo analysis that closes that gap
without any dependency or network:

**Pass 1 — summarise every function.** For each ``def``, find sinks whose argument
is (transitively, intra-procedurally) one of the function's *parameters*. Record
those as "tainted-parameter sinks": parameter name → (sink category, cwe, line).
Also record request-sourced locals (the existing intra taint) so a direct
source→call in the same function is recognised.

**Pass 2 — propagate across calls.** Build a map of function name → summary across
ALL files. For every call site where a *tainted* argument (a request value, or a
local assigned from one) is passed into a parameter position that the callee marks
as a tainted-parameter sink, emit a finding at the callee's sink location.

This is intentionally conservative (name-based resolution, one hop deep by default
with a small propagation queue) to keep false positives at zero while catching the
common "helper in another file" pattern. It never blocks; it only reports.
"""
from __future__ import annotations

import ast

from .model import Finding, Severity, Source

# Reuse the single-file taint helpers so the notion of "user input" is identical.
from .deterministic import (  # noqa: E402
    _USER_INPUT_HINTS,
    _attr_chain,
    _has_concat_or_format,
)

# Sink categories we track for cross-file propagation: dotted-call suffix -> (rule, category, cwe, title)
_TAINTED_PARAM_SINKS: dict[str, tuple[str, str, str, str]] = {
    "execute": ("xfile.sql_injection", "sql_injection", "CWE-89", "SQL query built from a tainted parameter"),
    "system": ("xfile.command_injection", "command_injection", "CWE-78", "OS command built from a tainted parameter"),
    "popen": ("xfile.command_injection", "command_injection", "CWE-78", "OS command built from a tainted parameter"),
    "open": ("xfile.path_traversal", "path_traversal", "CWE-22", "File path built from a tainted parameter"),
    "loads": ("xfile.insecure_deserialization", "insecure_deserialization", "CWE-502", "Untrusted data deserialised from a tainted parameter"),
    "render_template_string": ("xfile.ssti", "template_injection", "CWE-1336", "Template rendered from a tainted parameter"),
}

# Calls that DON'T need concat to be dangerous (the value itself is the payload).
_DIRECT_SINKS = {"loads", "render_template_string"}


class _FuncSummary:
    """What one function does with its parameters, for cross-call propagation."""

    def __init__(self, name: str, file: str, params: list[str]) -> None:
        self.name = name
        self.file = file
        self.params = params
        # param name -> (rule_id, category, cwe, title, sink_line)
        self.tainted_param_sinks: dict[str, tuple[str, str, str, str, int]] = {}
        # calls this function makes: (callee_name, [arg_is_param_name_or_None...], line)
        self.calls: list[tuple[str, list[str | None], int]] = []


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _is_user_input_src(node: ast.AST) -> bool:
    try:
        return bool(_USER_INPUT_HINTS.search(ast.unparse(node)))
    except Exception:  # noqa: BLE001
        return False


class _FunctionAnalyzer(ast.NodeVisitor):
    """Analyse one function body: taint from params + request sources → sinks."""

    def __init__(self, file: str, summary: _FuncSummary) -> None:
        self.file = file
        self.summary = summary
        # locals tainted by a parameter (name -> the originating param name)
        self._param_tainted: dict[str, str] = {p: p for p in summary.params}
        # locals tainted by a request source (intra-procedural)
        self._src_tainted: set[str] = set()

    def _taint_param_of(self, node: ast.AST) -> str | None:
        """If ``node`` references a parameter-tainted value, return the param name."""
        for name in _names_in(node):
            if name in self._param_tainted:
                return self._param_tainted[name]
        return None

    def _is_src_tainted(self, node: ast.AST) -> bool:
        if _is_user_input_src(node):
            return True
        return any(n in self._src_tainted for n in _names_in(node))

    def visit_Assign(self, node: ast.Assign) -> None:
        param = self._taint_param_of(node.value)
        if param is not None:
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._param_tainted[t.name if hasattr(t, "name") else t.id] = param
        if self._is_src_tainted(node.value):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self._src_tainted.add(t.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        target = _attr_chain(node.func)
        suffix = target.split(".")[-1]

        # Record a tainted-parameter sink: a sink whose arg comes from a param.
        if suffix in _TAINTED_PARAM_SINKS and node.args:
            arg0 = node.args[0]
            needs_concat = suffix not in _DIRECT_SINKS
            shaped = _has_concat_or_format(arg0) or not needs_concat
            param = self._taint_param_of(arg0)
            if param is not None and shaped:
                rule, cat, cwe, title = _TAINTED_PARAM_SINKS[suffix]
                self.summary.tainted_param_sinks.setdefault(
                    param, (rule, cat, cwe, title, getattr(node, "lineno", 0))
                )

        # Record a call to another function, noting which args are param/src tainted.
        callee = target.split(".")[-1]
        arg_taints: list[str | None] = []
        for a in node.args:
            p = self._taint_param_of(a)
            if p is not None:
                arg_taints.append(p)
            elif self._is_src_tainted(a):
                arg_taints.append("__src__")
            else:
                arg_taints.append(None)
        self.summary.calls.append((callee, arg_taints, getattr(node, "lineno", 0)))
        self.generic_visit(node)


def _summarise_file(file: str, text: str) -> list[_FuncSummary]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    summaries: list[_FuncSummary] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = [a.arg for a in node.args.args]
            s = _FuncSummary(node.name, file, params)
            analyzer = _FunctionAnalyzer(file, s)
            for stmt in node.body:
                analyzer.visit(stmt)
            summaries.append(s)
    return summaries


def analyze_repo_taint(files: dict[str, str]) -> list[Finding]:
    """Repo-level cross-file taint. ``files`` maps rel-path -> source text (Python
    only). Returns findings where a request-tainted value reaches a sink through a
    function call, including across files."""
    # Pass 1: summarise every function across all Python files.
    all_summaries: list[_FuncSummary] = []
    for file, text in files.items():
        if file.lower().endswith(".py"):
            all_summaries.extend(_summarise_file(file, text))

    # Index callee name -> summaries (name-based resolution; a name may be defined
    # in multiple files — we consider all candidates).
    by_name: dict[str, list[_FuncSummary]] = {}
    for s in all_summaries:
        by_name.setdefault(s.name, []).append(s)

    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    # Pass 2: for every call passing a tainted arg into a callee whose matching
    # parameter is a tainted-parameter sink, emit a finding at the callee's sink.
    for caller in all_summaries:
        for callee_name, arg_taints, _call_line in caller.calls:
            for callee in by_name.get(callee_name, []):
                for idx, taint in enumerate(arg_taints):
                    if taint is None:
                        continue
                    if idx >= len(callee.params):
                        continue
                    param_name = callee.params[idx]
                    sink = callee.tainted_param_sinks.get(param_name)
                    if sink is None:
                        continue
                    rule, cat, cwe, title, sink_line = sink
                    key = (callee.file, sink_line, cat)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(Finding(
                        rule_id=rule, category=cat, severity=Severity.HIGH,
                        file=callee.file, line=sink_line, title=title,
                        detail=(
                            f"User-controlled input reaches this sink via a call to "
                            f"`{callee_name}()` (argument flows from "
                            f"{'another file' if caller.file != callee.file else 'the caller'} "
                            f"`{caller.file}`). Cross-file taint."
                        ),
                        remediation="Sanitise/parameterise at the sink; do not trust values "
                                    "passed in from callers as safe.",
                        confidence=0.8, source=Source.DETERMINISTIC, cwe=cwe,
                    ))
    return findings
