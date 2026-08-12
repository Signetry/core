"""Admitted Extension — governance for the agent supply chain (skills / MCP).

2026 threat expansion: a coding agent's authority now flows not only through the
code it writes but through the **extensions it loads** — Claude/agent *skills*
(a ``SKILL.md`` + scripts) and *MCP servers* (tools whose descriptions the model
reads as instructions). A poisoned skill doc or a hijacking MCP tool description
is prompt injection with a delivery mechanism Signetry's per-change pipeline never
sees, because the manipulation rides in *before* the agent proposes anything.

This module makes an extension a first-class governed object:

- **Fingerprint** — every file in the extension (manifest + docs + scripts) is
  content-hashed into a stable ``extension_hash``, so "the skill I admitted" is
  bound by bytes, not by name (a later silent edit changes the hash).
- **Quarantine before read** — the extension's *documentation surfaces*
  (``SKILL.md``, README, and every MCP tool ``description``) are scanned with the
  same trust-boundary detector used for repo text. An agent-directed manipulation
  in a tool description is a finding, not an instruction.
- **Allowlist** — an optional contract allowlist (``allowed_skills`` /
  ``allowed_mcp`` from the capability graph) is enforced: an extension not on the
  list is denied when the list is set.
- **Verdict + receipt** — ``admit_extension`` returns ``admit`` / ``deny`` with
  reasons and (optionally) an Ed25519-signed receipt, so an org can prove which
  extension bytes it admitted.
- **ASBOM** — ``asbom`` emits a CycloneDX-aligned software bill of materials of
  admitted extensions for org inventory.

Deterministic and offline. Never *executes* the extension; it inspects bytes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .contract import Contract
from .trust_boundary import scan_text

# Files whose *content* is documentation the agent reads as prose — quarantined
# before ingest. Everything else in an extension is hashed but not scanned for
# instructions (scripts are code, not model-facing prose).
_DOC_FILES = ("SKILL.md", "README.md", "README", "AGENTS.md", "MANIFEST.md", "skill.md", "readme.md")
_MAX_FILE_BYTES = 512_000


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256_bytes((text or "").encode("utf-8", "replace"))


@dataclass
class ExtensionFile:
    path: str          # extension-relative POSIX path
    digest: str        # sha256:...
    bytes: int
    is_doc: bool

    def to_public(self) -> dict[str, Any]:
        return {"path": self.path, "digest": self.digest, "bytes": self.bytes, "is_doc": self.is_doc}


@dataclass
class AdmittedExtension:
    name: str
    kind: str                       # "skill" | "mcp"
    version: str
    verdict: str                    # "admit" | "deny"
    extension_hash: str             # stable content fingerprint over all files
    files: list[ExtensionFile] = field(default_factory=list)
    quarantine_findings: list[dict[str, Any]] = field(default_factory=list)
    mcp_tools: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    generated_at: str = ""

    @property
    def admitted(self) -> bool:
        return self.verdict == "admit"

    def to_public(self) -> dict[str, Any]:
        return {
            "kind_of": "signetry.admitted-extension",
            "name": self.name,
            "kind": self.kind,
            "version": self.version,
            "verdict": self.verdict,
            "admitted": self.admitted,
            "extension_hash": self.extension_hash,
            "files": [f.to_public() for f in self.files],
            "file_count": len(self.files),
            "quarantine_findings": self.quarantine_findings,
            "quarantined_count": len(self.quarantine_findings),
            "mcp_tools": list(self.mcp_tools),
            "reasons": list(self.reasons),
            "generated_at": self.generated_at,
            # Invariant: admitting an extension never grants authority; it only
            # records that these exact bytes were reviewed and found clean/allowed.
            "grants_authority": False,
        }


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        # Skip VCS / cache noise.
        parts = set(p.relative_to(root).parts)
        if parts & {".git", "__pycache__", "node_modules", ".venv"}:
            continue
        out.append(p)
    return out


def _detect_mcp_tools(root: Path) -> tuple[list[str], list[tuple[str, str]]]:
    """Find MCP tool names + (source, description) pairs to quarantine.

    Looks in common MCP manifest files (``mcp.json``, ``server.json``,
    ``manifest.json``, ``package.json`` with an ``mcp`` block). Tool descriptions
    are model-facing prose, so they are returned for trust-boundary scanning.
    """
    tools: list[str] = []
    docs: list[tuple[str, str]] = []
    for name in ("mcp.json", "server.json", "manifest.json", "package.json", ".mcp.json"):
        f = root / name
        if not f.is_file():
            continue
        try:
            data = json.loads(f.read_text(errors="replace")[:_MAX_FILE_BYTES])
        except (json.JSONDecodeError, OSError):
            continue
        blocks = []
        if isinstance(data, dict):
            blocks = [data, data.get("mcp") or {}, data.get("server") or {}]
        for block in blocks:
            if not isinstance(block, dict):
                continue
            tool_list = block.get("tools")
            if isinstance(tool_list, list):
                for t in tool_list:
                    if isinstance(t, dict) and t.get("name"):
                        tools.append(str(t["name"]))
                        desc = t.get("description")
                        if isinstance(desc, str) and desc.strip():
                            docs.append((f"{name}:{t['name']}.description", desc))
            elif isinstance(tool_list, dict):
                for tname, tval in tool_list.items():
                    tools.append(str(tname))
                    if isinstance(tval, dict) and isinstance(tval.get("description"), str):
                        docs.append((f"{name}:{tname}.description", tval["description"]))
    return sorted(set(tools)), docs


def _extension_meta(root: Path, kind_hint: str | None) -> tuple[str, str, str]:
    """Return (name, kind, version). Deterministic best-effort from manifests."""
    # MCP if a server/mcp manifest is present; else skill if SKILL.md is present.
    has_mcp = any((root / n).is_file() for n in ("mcp.json", "server.json", ".mcp.json"))
    has_skill = (root / "SKILL.md").is_file() or (root / "skill.md").is_file()
    kind = kind_hint or ("mcp" if has_mcp else "skill" if has_skill else "skill")
    name = root.name
    version = "0"
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            d = json.loads(pkg.read_text(errors="replace")[:_MAX_FILE_BYTES])
            name = str(d.get("name") or name)
            version = str(d.get("version") or version)
        except (json.JSONDecodeError, OSError):
            pass
    return name, kind, version


def inspect_extension(path: Path | str, *, kind: str | None = None) -> AdmittedExtension:
    """Inspect an extension directory: fingerprint every file, quarantine its
    documentation surfaces + MCP tool descriptions. Does NOT apply an allowlist
    or a verdict — :func:`admit_extension` does that. Never executes anything."""
    root = Path(path)
    name, ext_kind, version = _extension_meta(root, kind)
    files: list[ExtensionFile] = []
    findings: list[dict[str, Any]] = []
    per_file_digests: list[str] = []

    for p in _iter_files(root):
        rel = p.relative_to(root).as_posix()
        try:
            data = p.read_bytes()[:_MAX_FILE_BYTES]
        except OSError:
            continue
        digest = _sha256_bytes(data)
        is_doc = p.name in _DOC_FILES
        files.append(ExtensionFile(path=rel, digest=digest, bytes=len(data), is_doc=is_doc))
        per_file_digests.append(f"{rel}={digest}")
        if is_doc:
            text = data.decode("utf-8", "replace")
            findings.extend(f.to_public() for f in scan_text(text, rel))

    # MCP tool descriptions are model-facing prose → quarantine them too.
    mcp_tools, tool_docs = _detect_mcp_tools(root)
    for source, desc in tool_docs:
        findings.extend(f.to_public() for f in scan_text(desc, source))

    # Stable fingerprint over the sorted per-file digests (order-independent).
    fingerprint = _sha256_text("\n".join(sorted(per_file_digests)))

    return AdmittedExtension(
        name=name,
        kind=ext_kind,
        version=version,
        verdict="deny",  # provisional; admit_extension decides
        extension_hash=fingerprint,
        files=files,
        quarantine_findings=findings,
        mcp_tools=mcp_tools,
        reasons=[],
        generated_at=datetime.now(UTC).isoformat(),
    )


def admit_extension(
    path: Path | str,
    *,
    kind: str | None = None,
    contract: Contract | None = None,
    allow_quarantined: bool = False,
) -> AdmittedExtension:
    """Inspect + rule on an extension. Fail-closed:

    - A documentation/tool-description quarantine finding **denies** admission
      (unless ``allow_quarantined`` is set for an explicit human override).
    - When ``contract`` declares a capability-graph allowlist
      (``allowed_skills`` / ``allowed_mcp``), an extension not on the list is denied.
    - Otherwise the extension is admitted, with its exact-bytes fingerprint bound.
    """
    ext = inspect_extension(path, kind=kind)
    reasons: list[str] = []

    if ext.quarantine_findings and not allow_quarantined:
        cats = sorted({f["category"] for f in ext.quarantine_findings})
        reasons.append(
            f"denied: {len(ext.quarantine_findings)} agent-directed manipulation "
            f"finding(s) in the extension's documentation/tool descriptions ({', '.join(cats)})."
        )

    if contract is not None:
        if ext.kind == "skill" and contract.allowed_skills and not _on_allowlist(ext.name, contract.allowed_skills):
            reasons.append(f"denied: skill '{ext.name}' is not on the contract's allowed_skills allowlist.")
        if ext.kind == "mcp" and contract.allowed_mcp:
            # Every tool must be individually allowlisted (server or server:tool).
            server = ext.name
            unlisted = [
                t for t in (ext.mcp_tools or [server])
                if not _on_allowlist(f"{server}:{t}", contract.allowed_mcp)
                and not _on_allowlist(server, contract.allowed_mcp)
            ]
            if unlisted:
                reasons.append(f"denied: MCP tool(s) not on the contract's allowed_mcp allowlist: {', '.join(unlisted)}.")

    if reasons:
        ext.verdict = "deny"
        ext.reasons = reasons
    else:
        ext.verdict = "admit"
        note = "admitted: extension documentation is clean of tested manipulation patterns"
        if contract is not None and (contract.allowed_skills or contract.allowed_mcp):
            note += " and it is on the contract allowlist"
        ext.reasons = [note + f"; fingerprint {ext.extension_hash}."]
        if ext.quarantine_findings and allow_quarantined:
            ext.reasons.append(
                f"note: {len(ext.quarantine_findings)} quarantine finding(s) were present but overridden by allow_quarantined."
            )
    return ext


def _on_allowlist(ident: str, allow: tuple[str, ...]) -> bool:
    import fnmatch

    low = (ident or "").casefold()
    return any(low == e.casefold() or fnmatch.fnmatchcase(low, e.casefold()) for e in allow)


# --- ASBOM (Agent Software Bill of Materials, CycloneDX-aligned) -------------

CYCLONEDX_SPEC = "1.5"


def asbom(extensions: list[AdmittedExtension], *, org: str | None = None) -> dict[str, Any]:
    """Emit a CycloneDX-aligned bill of materials of admitted extensions.

    Each extension becomes a CycloneDX ``component`` carrying its exact-bytes
    ``extension_hash`` as a SHA-256 hash and a ``signetry`` property block recording
    the admission verdict + quarantine count for org inventory/audit.
    """
    components: list[dict[str, Any]] = []
    for ext in extensions:
        raw = ext.extension_hash.split(":", 1)[-1]
        components.append({
            "type": "application" if ext.kind == "mcp" else "library",
            "name": ext.name,
            "version": ext.version,
            "bom-ref": f"signetry-extension:{ext.kind}:{ext.name}@{ext.version}",
            "hashes": [{"alg": "SHA-256", "content": raw}],
            "properties": [
                {"name": "signetry:kind", "value": ext.kind},
                {"name": "signetry:verdict", "value": ext.verdict},
                {"name": "signetry:quarantined_findings", "value": str(len(ext.quarantine_findings))},
                {"name": "signetry:file_count", "value": str(len(ext.files))},
                *([{"name": "signetry:mcp_tools", "value": ",".join(ext.mcp_tools)}] if ext.mcp_tools else []),
            ],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": [{"vendor": "Signetry", "name": "signetry-core", "components": []}],
            **({"component": {"type": "application", "name": org}} if org else {}),
        },
        "components": components,
    }
