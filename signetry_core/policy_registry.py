"""The policy registry — named, audited admission policies anyone can contribute.

Writing a first admission contract is the step where adoption stalls: the format is
simple, but deciding *what an agent should be allowed to touch in this stack* is not.
The registry answers that with ready policies for common repository shapes, and
`signetry init --policy <id>` drops one in.

Two properties keep this from being a folder of untested YAML:

**What ships is what lands.** A registry entry is a literal, valid
``.signetry/admission.yaml``. ``signetry init --policy`` copies the bytes verbatim —
no templating, no merge, no rewriting. Metadata lives in ``# @policy`` header
comments, which the contract parser ignores and a human reading the installed file
still benefits from. You can diff what you got against what is published.

**Every entry carries its own evidence.** Each policy declares example paths it
MUST block and example paths it MUST allow, and ``tests/test_policy_registry.py``
runs all of them through the real ``evaluate_contract``. A policy whose claims do
not hold fails CI. Nothing here is asserted without being checked.

Entries deliberately ship placeholder ``policy_owner`` values, so a repo that adopts
one and never edits it reports ``policy_status: placeholder`` — unowned — rather than
a borrowed claim of change control. Adopting a policy is a human act; the registry
cannot perform it for you.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pipeline.contract import Contract, _parse_admission_text, contract_from_dict

POLICY_DIR = Path(__file__).parent / "policies"

# `# @policy key: value` — the only metadata mechanism. Comments, so they survive
# into the installed file as documentation and stay invisible to the parser.
_META_RE = re.compile(r"^#\s*@policy\s+([a-z_]+)\s*:\s*(.*)$")

# A value may wrap onto following lines, indented by two or more spaces after the `#`.
# The single-space form (`# a normal comment`) is NOT a continuation, which is what
# keeps the ordinary explanatory comments in a policy file out of its metadata.
_CONT_RE = re.compile(r"^#\s{2,}(\S.*)$")

# Keys every entry must declare. Absent or empty → the entry is invalid and the
# validation test fails. There is no default for "who wrote this" or "what it blocks".
REQUIRED_META = ("id", "title", "summary", "author", "blocks", "allows")

_LIST_KEYS = frozenset({"blocks", "allows", "stack"})


@dataclass(frozen=True)
class PolicyEntry:
    """One registry policy: its metadata, its literal bytes, and its parsed contract."""

    id: str
    title: str
    summary: str
    author: str
    path: Path
    text: str
    blocks: tuple[str, ...] = ()
    allows: tuple[str, ...] = ()
    stack: tuple[str, ...] = ()
    caution: str = ""
    meta: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def contract(self) -> Contract:
        """The policy parsed through the real loader — not a separate code path."""
        return contract_from_dict(_parse_admission_text(self.text), source="registry")

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "author": self.author,
            "stack": list(self.stack),
            "caution": self.caution or None,
            "blocks": list(self.blocks),
            "allows": list(self.allows),
            "contract": self.contract.to_public(),
        }


def _parse_meta(text: str) -> dict[str, Any]:
    """Read the `@policy` header block at the top of a policy file.

    Parsing stops at the first line that is neither a comment nor blank — i.e. at the
    contract itself. Metadata is a header, not something that can hide further down a
    file, and a contributor cannot accidentally turn a mid-file comment into metadata."""
    raw_meta: dict[str, str] = {}
    order: list[str] = []
    current: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break  # the contract starts here; the header is over
        m = _META_RE.match(stripped)
        if m:
            current = m.group(1)
            if current not in raw_meta:
                order.append(current)
            raw_meta[current] = m.group(2).strip()
            continue
        cont = _CONT_RE.match(stripped)
        if cont and current:
            raw_meta[current] = f"{raw_meta[current]} {cont.group(1).strip()}".strip()
            continue
        current = None  # a plain comment ends the current value

    meta: dict[str, Any] = {}
    for key in order:
        value = " ".join(raw_meta[key].split())
        if key in _LIST_KEYS:
            meta[key] = tuple(p.strip() for p in value.split(",") if p.strip())
        else:
            meta[key] = value
    return meta


def _entry_from_path(path: Path) -> PolicyEntry:
    text = path.read_text(encoding="utf-8")
    meta = _parse_meta(text)
    missing = [k for k in REQUIRED_META if not meta.get(k)]
    if missing:
        raise ValueError(f"{path.name}: missing @policy metadata: {', '.join(missing)}")
    stated = str(meta["id"])
    if stated != path.stem:
        raise ValueError(f"{path.name}: @policy id is {stated!r} but the filename says {path.stem!r}")
    return PolicyEntry(
        id=stated,
        title=str(meta["title"]),
        summary=str(meta["summary"]),
        author=str(meta["author"]),
        path=path,
        text=text,
        blocks=tuple(meta.get("blocks", ())),
        allows=tuple(meta.get("allows", ())),
        stack=tuple(meta.get("stack", ())),
        caution=str(meta.get("caution", "")),
        meta=meta,
    )


def available_policies() -> list[PolicyEntry]:
    """Every valid registry entry, sorted by id.

    A malformed entry raises rather than being skipped: silently dropping a policy
    would make ``signetry policies`` quietly under-report the registry, and a
    contributor's broken file would look like it was never added at all."""
    if not POLICY_DIR.is_dir():
        return []
    return sorted((_entry_from_path(p) for p in POLICY_DIR.glob("*.yaml")), key=lambda e: e.id)


def policy_ids() -> list[str]:
    return [e.id for e in available_policies()]


def load_policy(policy_id: str) -> PolicyEntry:
    """Look up one policy by id. Raises ``KeyError`` naming the valid ids."""
    wanted = (policy_id or "").strip().lower()
    for entry in available_policies():
        if entry.id == wanted:
            return entry
    raise KeyError(f"unknown policy {policy_id!r} (available: {', '.join(policy_ids()) or 'none'})")
