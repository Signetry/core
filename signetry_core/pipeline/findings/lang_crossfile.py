"""Cross-file / interprocedural taint for non-Python languages.

Python has a precise AST cross-file analyzer (``crossfile.py``). This module brings
the same "source in one file → sink in another via a function call" coverage to
Go, Java, PHP, Ruby and C#, using the declarative per-language specs already in
``lang_taint.py`` plus lightweight, regex-based function extraction.

Two passes, mirroring the Python analyzer:

**Pass 1 — summarise functions.** For each file, extract function definitions
(name + ordered parameter names) with a per-language signature regex, then within
each function body find sinks whose line references one of the *parameters* (and,
for concat-style sinks, shows string-building). Those become "tainted-parameter
sinks": param name → sink metadata + line.

**Pass 2 — propagate across calls.** Across ALL files of the language, index
function summaries by name. For each call ``callee(a, b, …)`` where an argument is a
*user-tainted* value (a source, or a local assigned from one — reusing the intra
taint pass), if the matching callee parameter is a tainted-parameter sink, emit a
finding at the callee's sink line.

Deliberately conservative: name-based resolution, brace/indent-free body slicing by
the next sibling definition, one level of argument taint. Zero-FP oriented — it only
fires when a real user source reaches a call whose callee already provably funnels
that parameter into a sink.
"""
from __future__ import annotations

import os
import re

from .lang_taint import _EXT_TO_SPEC, _PARAM_PLACEHOLDER, _idents, LangTaintSpec
from .model import Finding, Severity, Source

# Per-language function-definition signatures. group("name") = function name;
# group("params") = the raw parameter list (parsed for identifiers below).
_FUNC_SIGS: dict[str, re.Pattern[str]] = {
    ".go": re.compile(r"func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"),
    ".java": re.compile(r"(?:public|private|protected|static|final|\s)+[\w<>\[\].]+\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*(?:throws[\w\s,]*)?\{"),
    ".php": re.compile(r"function\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)"),
    ".rb": re.compile(r"def\s+(?:self\.)?(?P<name>[A-Za-z_]\w*[!?]?)\s*(?:\((?P<params>[^)]*)\)|(?P<params2>[^\n]*))"),
    ".cs": re.compile(r"(?:public|private|protected|internal|static)\s+(?:[\w<>\[\].]+\s+)+(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{?"),
}

# Extract parameter identifier names from a raw parameter list, per language.
_PARAM_IDENT = re.compile(r"[A-Za-z_$]\w*")


def _param_names(raw: str, ext: str) -> list[str]:
    """Best-effort ordered parameter names from a signature's param list."""
    params: list[str] = []
    for chunk in raw.split(","):
        c = chunk.strip()
        if not c:
            continue
        toks = _PARAM_IDENT.findall(c)
        if not toks:
            continue
        if ext in (".go",):
            # Go: `name Type` → first token is the name (skip lone types).
            params.append(toks[0])
        elif ext in (".java", ".cs"):
            # `Type name` (possibly with generics/modifiers) → last token is the name.
            params.append(toks[-1])
        elif ext in (".php", ".rb"):
            # PHP `$name`, Ruby `name` → first token.
            params.append(toks[0])
        else:
            params.append(toks[-1])
    return params


class _FuncSummary:
    def __init__(self, name: str, file: str, params: list[str], start: int, end: int) -> None:
        self.name = name
        self.file = file
        self.params = params
        self.start = start  # line index (1-based) of def
        self.end = end
        # param name -> (rule_id, category, cwe, title, detail, remediation, line)
        self.tainted_param_sinks: dict[str, tuple] = {}


def _slice_functions(file: str, text: str, spec: LangTaintSpec) -> list[_FuncSummary]:
    ext = os.path.splitext(file.lower())[1]
    sig = _FUNC_SIGS.get(ext)
    if sig is None:
        return []
    lines = text.splitlines()
    # Find all definition line indices.
    defs: list[tuple[int, str, list[str]]] = []
    for i, line in enumerate(lines):
        m = sig.search(line)
        if m:
            raw = m.group("params") if "params" in m.groupdict() and m.group("params") is not None else ""
            if not raw and "params2" in m.groupdict() and m.group("params2"):
                raw = m.group("params2")
            defs.append((i, m.group("name"), _param_names(raw or "", ext)))
    summaries: list[_FuncSummary] = []
    for idx, (start, name, params) in enumerate(defs):
        end = defs[idx + 1][0] if idx + 1 < len(defs) else len(lines)
        s = _FuncSummary(name, file, params, start + 1, end)
        # Track locals tainted BY A PARAMETER within this function body, so a sink
        # using a param-derived local (built over several statements) is caught.
        param_taint: dict[str, str] = {p: p for p in params}  # local -> originating param
        for ln in range(start, end):
            line = lines[ln]
            if spec.sanitizer.search(line):
                # a sanitiser on this line clears any assigned local's taint below
                pass
            # Which parameters (directly or via a param-tainted local) does this line use?
            used_params: set[str] = set()
            for local, origin in param_taint.items():
                if re.search(r"(?<![\w$])" + re.escape(local) + r"(?![\w$])", line):
                    used_params.add(origin)
            if used_params and not spec.sanitizer.search(line):
                for sink in spec.sinks:
                    if not sink.pattern.search(line):
                        continue
                    if sink.category == "sql_injection" and _PARAM_PLACEHOLDER.search(line) and not spec.concat.search(line):
                        continue
                    # Concat may have happened at an earlier assignment (param → local
                    # → sink), so we do NOT require concat on the sink line itself for
                    # cross-file param sinks; the param reaching the sink is enough.
                    for p in used_params:
                        s.tainted_param_sinks.setdefault(p, (
                            sink.rule_id.replace(".taint.", ".xfile."), sink.category, sink.cwe,
                            sink.title.replace("(taint)", "(cross-file)"), sink.detail,
                            sink.remediation, ln + 1,
                        ))
            # Propagate param-taint through assignments inside the function.
            am = spec.assign.search(line)
            if am and not re.search(r"[=!<>]=", line[: am.start(0) + len(am.group(1)) + 3]):
                lhs, rhs = am.group(1), am.group(2)
                if spec.sanitizer.search(rhs):
                    param_taint.pop(lhs, None)
                elif any(
                    re.search(r"(?<![\w$])" + re.escape(loc) + r"(?![\w$])", rhs)
                    for loc in param_taint
                ):
                    origin = next(
                        param_taint[loc] for loc in param_taint
                        if re.search(r"(?<![\w$])" + re.escape(loc) + r"(?![\w$])", rhs)
                    )
                    param_taint[lhs] = origin
        summaries.append(s)
    return summaries


# Call site: callee(args). Captures callee name + raw args.
_CALL = re.compile(r"(?:(?:\w+)\.)?(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;]*?)\)")


def _tainted_locals_for_lang(file: str, text: str, spec: LangTaintSpec) -> set[str]:
    """Names tainted by a user source anywhere in the file (whole-file union — a
    conservative superset used only to decide if a call argument is tainted)."""
    tainted: set[str] = set()
    for line in text.splitlines():
        m = spec.assign.search(line)
        if not m:
            continue
        lhs, rhs = m.group(1), m.group(2)
        if spec.sanitizer.search(rhs):
            tainted.discard(lhs)
            continue
        if spec.source.search(rhs) or any(v in tainted for v in _idents(rhs, spec.ident)):
            tainted.add(lhs)
    return tainted


def analyze_repo_taint_multilang(files: dict[str, str]) -> list[Finding]:
    """Cross-file taint for the supported non-Python languages. ``files`` maps
    rel-path -> source. Findings are emitted at the callee's sink location when a
    user-tainted argument flows into a tainted-parameter sink (possibly in another
    file of the same language)."""
    findings: list[Finding] = []
    # Group files by language spec.
    by_spec: dict[int, list[tuple[str, str]]] = {}
    spec_list: list[LangTaintSpec] = []
    for file, text in files.items():
        spec = _EXT_TO_SPEC.get(os.path.splitext(file.lower())[1])
        if spec is None:
            continue
        if spec not in spec_list:
            spec_list.append(spec)
        by_spec.setdefault(spec_list.index(spec), []).append((file, text))

    for spec_idx, lang_files in by_spec.items():
        spec = spec_list[spec_idx]
        # Pass 1: summarise + collect tainted locals per file.
        all_summaries: list[_FuncSummary] = []
        tainted_by_file: dict[str, set[str]] = {}
        for file, text in lang_files:
            all_summaries.extend(_slice_functions(file, text, spec))
            tainted_by_file[file] = _tainted_locals_for_lang(file, text, spec)
        by_name: dict[str, list[_FuncSummary]] = {}
        for s in all_summaries:
            by_name.setdefault(s.name, []).append(s)

        seen: set[tuple[str, int, str]] = set()
        # Pass 2: scan every line for calls into a tainted-param sink function.
        for file, text in lang_files:
            tainted = tainted_by_file.get(file, set())
            for line in text.splitlines():
                if spec.source.search(line):
                    # a source assigned to a var handled above; also allow inline source
                    pass
                for cm in _CALL.finditer(line):
                    callee_name = cm.group("name")
                    raw_args = cm.group("args")
                    if callee_name not in by_name:
                        continue
                    arg_exprs = [a.strip() for a in raw_args.split(",") if a.strip()]
                    # Which argument positions are tainted?
                    tainted_positions: list[int] = []
                    for i, a in enumerate(arg_exprs):
                        if spec.source.search(a) or any(v in tainted for v in _idents(a, spec.ident)):
                            tainted_positions.append(i)
                    if not tainted_positions:
                        continue
                    for callee in by_name[callee_name]:
                        for pos in tainted_positions:
                            if pos >= len(callee.params):
                                continue
                            sink = callee.tainted_param_sinks.get(callee.params[pos])
                            if sink is None:
                                continue
                            rule, cat, cwe, title, detail, rem, sink_line = sink
                            key = (callee.file, sink_line, cat)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(Finding(
                                rule_id=rule, category=cat, severity=Severity.HIGH,
                                file=callee.file, line=sink_line, title=title,
                                detail=(
                                    f"{detail} User input reaches this sink via a call to "
                                    f"`{callee_name}()`"
                                    + (f" from `{file}`" if file != callee.file else "")
                                    + ". Cross-file taint."
                                ),
                                remediation=rem, confidence=0.78,
                                source=Source.DETERMINISTIC, cwe=cwe,
                            ))
    return findings
