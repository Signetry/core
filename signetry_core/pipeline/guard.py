"""Real-time guard — fast, single-action contract check for editor/agent hooks.

Full admission (`run_admission`) governs a completed changeset. A guard is the
*pre-action* check an editor hook (e.g. Claude Code's ``PreToolUse``) calls before
the agent writes a file or runs a command: given ONE proposed path or command,
decide allow/deny against the repository's ``.signetry/admission.yaml`` — instantly,
deterministically, with no model and no network.

This lets Umbra govern an agent from *inside* the editor without the agent
governing itself: the hook runs this deterministic code, not the model.

It is a *pre-flight* check, not a replacement for admission — the full pipeline
(checks, verifier, earned authority, signed receipt) still runs on the PR. The
guard's job is to stop an obviously out-of-scope or forbidden action early.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contract import Contract, is_malformed_path, load_contract, _matches_any


@dataclass
class GuardDecision:
    allowed: bool
    reason: str
    path: str | None = None
    command: str | None = None
    tool: str | None = None
    mcp: str | None = None
    skill: str | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "path": self.path,
            "command": self.command,
            "tool": self.tool,
            "mcp": self.mcp,
            "skill": self.skill,
        }


# Dangerous shell fragments a guard blocks outright, regardless of contract —
# these are exfiltration / destruction / privilege patterns an agent editing a
# repo never needs. (The checks allowlist is stricter for *required checks*; this
# is a lighter guard for arbitrary agent Bash.)
_DANGEROUS_BASH = (
    re.compile(r"\brm\s+-rf\s+[/~]"),
    re.compile(r"\bcurl\b[^\n|]*\|\s*(sh|bash)"),
    re.compile(r"\bwget\b[^\n|]*\|\s*(sh|bash)"),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\}"),                 # fork bomb
    re.compile(r"\b(cat|less|head|tail)\b[^\n]*\.env\b"),   # read secrets
    re.compile(r"\b(cat|head|tail)\b[^\n]*(id_rsa|\.pem|credentials)\b"),
    re.compile(r"\bgit\s+push\b"),
    re.compile(r"\bgit\s+commit\b"),
    re.compile(r"\bgh\s+(pr|release|secret|workflow|auth|api)\b"),
    re.compile(r"\bchmod\s+777\b"),
    re.compile(r"/etc/(passwd|shadow|sudoers)"),
)

# Bash sub-patterns that indicate a file WRITE, so we can extract the target and
# check it against the contract's path rules.
_WRITE_TARGETS = (
    re.compile(r">>?\s*([^\s;&|]+)"),                       # redirect: > file / >> file
    re.compile(r"\btee\s+(?:-a\s+)?([^\s;&|]+)"),           # tee file
    re.compile(r"\b(?:rm|mv|cp)\s+(?:-[a-zA-Z]+\s+)*([^\s;&|]+)"),
    re.compile(r"\btouch\s+([^\s;&|]+)"),
)


def _rel(path: str, repo_root: Path) -> str:
    """Best-effort repo-relative POSIX path for a proposed file path."""
    p = Path(path)
    try:
        if p.is_absolute():
            return p.resolve().relative_to(repo_root.resolve()).as_posix()
    except (ValueError, OSError):
        return path  # outside the repo → return as-is (will fail is_malformed/scope)
    return path.lstrip("./")


def guard_path(path: str, contract: Contract, repo_root: Path) -> GuardDecision:
    """Allow/deny a single proposed file path against the contract."""
    rel = _rel(path, repo_root)
    if is_malformed_path(rel) or path.startswith("/") and _rel(path, repo_root) == path:
        return GuardDecision(False, f"Path is outside the repository or malformed: {path!r}", path=path)
    # Forbidden (case-insensitive) always wins.
    if _matches_any(rel, contract.forbidden_paths, case_insensitive=True):
        return GuardDecision(False, f"'{rel}' matches a forbidden path in .signetry/admission.yaml", path=rel)
    # Allowlist (when set): must be inside it.
    if contract.allowed_paths and not _matches_any(rel, contract.allowed_paths):
        return GuardDecision(False, f"'{rel}' is outside the allowed scope in .signetry/admission.yaml", path=rel)
    return GuardDecision(True, f"'{rel}' is within the contract's scope", path=rel)


def guard_command(command: str, contract: Contract, repo_root: Path) -> GuardDecision:
    """Allow/deny a single proposed shell command: block dangerous patterns, and
    check any file it writes against the contract."""
    cmd = (command or "").strip()
    if not cmd:
        return GuardDecision(True, "Empty command.", command=command)
    for pat in _DANGEROUS_BASH:
        if pat.search(cmd):
            return GuardDecision(False, f"Command matches a blocked pattern ({pat.pattern!r})", command=cmd)
    # Repo-declared extra deny patterns (contract v2), layered on the baseline.
    for raw in contract.denied_bash:
        try:
            if re.search(raw, cmd):
                return GuardDecision(False, f"Command matches a repo-forbidden pattern ({raw!r}) in .signetry/admission.yaml", command=cmd)
        except re.error:
            # A malformed repo pattern fails closed on exact substring match rather
            # than being silently ignored (never a widening).
            if raw and raw in cmd:
                return GuardDecision(False, f"Command matches a repo-forbidden literal ({raw!r}) in .signetry/admission.yaml", command=cmd)
    # Any file the command writes must satisfy the contract.
    for pat in _WRITE_TARGETS:
        for m in pat.finditer(cmd):
            target = m.group(1)
            if not target or target.startswith("-"):
                continue
            decision = guard_path(target, contract, repo_root)
            if not decision.allowed:
                return GuardDecision(False, f"Command writes {target!r}: {decision.reason}", command=cmd)
    return GuardDecision(True, "Command has no blocked pattern or out-of-scope write.", command=cmd)


def _guard_allowlist(value: str, allow: tuple[str, ...], *, kind: str) -> GuardDecision:
    """Shared allowlist check for tool/MCP/skill identifiers. When ``allow`` is
    empty the class imposes no extra restriction (v1 behaviour). Otherwise the
    identifier must match an entry (glob-style, case-insensitive) or it is denied
    — fail-closed for supply-chain surfaces."""
    ident = (value or "").strip()
    field = {"tool": "tool", "mcp": "mcp", "skill": "skill"}[kind]
    if not allow:
        return GuardDecision(True, f"No {kind} allowlist configured (any {kind} permitted).", **{field: ident})
    if not ident:
        return GuardDecision(False, f"Empty {kind} identifier is not on the allowlist.", **{field: ident})
    low = ident.casefold()
    for entry in allow:
        e = entry.casefold()
        if low == e or fnmatch.fnmatchcase(low, e):
            return GuardDecision(True, f"'{ident}' is on the {kind} allowlist in .signetry/admission.yaml", **{field: ident})
    return GuardDecision(False, f"'{ident}' is not on the {kind} allowlist in .signetry/admission.yaml", **{field: ident})


def guard_tool(tool: str, contract: Contract) -> GuardDecision:
    """Allow/deny an agent tool/command name against ``allowed_tools`` (v2)."""
    return _guard_allowlist(tool, contract.allowed_tools, kind="tool")


def guard_mcp(server_tool: str, contract: Contract) -> GuardDecision:
    """Allow/deny an MCP call (``server`` or ``server:tool``) against
    ``allowed_mcp`` (v2). Matches either the full ``server:tool`` or the bare
    ``server`` so a repo may allow a whole server or a specific tool."""
    ident = (server_tool or "").strip()
    if not contract.allowed_mcp:
        return GuardDecision(True, "No MCP allowlist configured (any MCP call permitted).", mcp=ident)
    # Try full identifier, then the server prefix.
    full = _guard_allowlist(ident, contract.allowed_mcp, kind="mcp")
    if full.allowed:
        return full
    server = ident.split(":", 1)[0]
    if server and server != ident:
        return _guard_allowlist(server, contract.allowed_mcp, kind="mcp")
    return full


def guard_skill(skill: str, contract: Contract) -> GuardDecision:
    """Allow/deny loading a skill/plugin against ``allowed_skills`` (v2)."""
    return _guard_allowlist(skill, contract.allowed_skills, kind="skill")


def guard(
    *,
    repo_path: Path | str,
    path: str | None = None,
    command: str | None = None,
    tool: str | None = None,
    mcp: str | None = None,
    skill: str | None = None,
    contract: Contract | None = None,
) -> GuardDecision:
    """Top-level guard: check a proposed ``path``, ``command``, ``tool``, ``mcp``
    call, and/or ``skill`` load against the repo's contract. Returns the first
    denial found (fail-closed), else an allow. Never raises."""
    root = Path(repo_path)
    contract = contract or load_contract(root)
    if tool:
        d = guard_tool(tool, contract)
        if not d.allowed:
            return d
    if mcp:
        d = guard_mcp(mcp, contract)
        if not d.allowed:
            return d
    if skill:
        d = guard_skill(skill, contract)
        if not d.allowed:
            return d
    if command:
        d = guard_command(command, contract, root)
        if not d.allowed:
            return d
    if path:
        d = guard_path(path, contract, root)
        if not d.allowed:
            return d
    if not any((path, command, tool, mcp, skill)):
        return GuardDecision(True, "Nothing to guard.")
    return GuardDecision(True, "Allowed by contract.", path=path, command=command, tool=tool, mcp=mcp, skill=skill)
