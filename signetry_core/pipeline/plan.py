"""Plan capability binding (CaMeL / DRIFT line) — freeze what a run may do.

Before an executor runs, Signetry derives a **PlanCapabilitySet** from the mission
and the contract: the concrete, frozen set of capabilities this specific run is
permitted to exercise (allowed/forbidden paths, diff budget, tool/MCP/skill
allowlists, network posture). The set is:

- **Deterministic** — a pure function of (mission, contract). No model, no network.
- **Hashable** — bound into the signed receipt so an auditor can answer G1
  ("what was this agent allowed to do?") against the exact set that applied.
- **Enforceable out-of-band** — the same set drives the runtime guard, so a
  deviation is caught by deterministic code, not by the model policing itself.

After the run, :func:`evaluate_plan_adherence` compares the actual changeset
against the plan. A change that stays inside the plan adds no restriction; a
change that touches capabilities outside the plan is a **plan deviation** — the
pipeline caps authority (never silently widens it).

This is the out-of-band control research (CaMeL, DRIFT) made concrete: authority
is bound to a plan derived before execution, not inferred from the model's
narration after the fact.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .contract import Contract


@dataclass(frozen=True)
class PlanCapabilitySet:
    """The frozen capability envelope for one governed run.

    Derived from the contract (the enforceable half of policy) and tagged with a
    short, redaction-safe fingerprint of the mission so the receipt records *which
    task* the plan was bound for without embedding untrusted prose verbatim.
    """

    mission_digest: str                         # sha256 of the mission text (bound, not stored verbatim)
    allowed_paths: tuple[str, ...] = ()
    forbidden_paths: tuple[str, ...] = ()
    max_files_changed: int = 0
    allowed_tools: tuple[str, ...] = ()
    denied_bash: tuple[str, ...] = ()
    allowed_mcp: tuple[str, ...] = ()
    allowed_skills: tuple[str, ...] = ()
    network: str = "deny"
    contract_hash: str = ""

    def to_public(self) -> dict[str, Any]:
        return {
            "mission_digest": self.mission_digest,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "max_files_changed": self.max_files_changed,
            "allowed_tools": list(self.allowed_tools),
            "denied_bash": list(self.denied_bash),
            "allowed_mcp": list(self.allowed_mcp),
            "allowed_skills": list(self.allowed_skills),
            "network": self.network,
            "contract_hash": self.contract_hash,
            "plan_hash": self.hash(),
        }

    def hash(self) -> str:
        """Stable content hash of the capability envelope (excludes the derived
        ``plan_hash`` itself). Binds a receipt to the exact plan that applied."""
        payload = {
            "mission_digest": self.mission_digest,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "max_files_changed": self.max_files_changed,
            "allowed_tools": list(self.allowed_tools),
            "denied_bash": list(self.denied_bash),
            "allowed_mcp": list(self.allowed_mcp),
            "allowed_skills": list(self.allowed_skills),
            "network": self.network,
            "contract_hash": self.contract_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _mission_digest(mission: str) -> str:
    return "sha256:" + hashlib.sha256((mission or "").encode("utf-8", "replace")).hexdigest()


def derive_plan(mission: str, contract: Contract) -> PlanCapabilitySet:
    """Derive the frozen :class:`PlanCapabilitySet` for a run from its mission and
    contract, BEFORE any executor runs. Pure and deterministic."""
    return PlanCapabilitySet(
        mission_digest=_mission_digest(mission),
        allowed_paths=tuple(contract.allowed_paths),
        forbidden_paths=tuple(contract.forbidden_paths),
        max_files_changed=int(contract.max_files_changed or 0),
        allowed_tools=tuple(contract.allowed_tools),
        denied_bash=tuple(contract.denied_bash),
        allowed_mcp=tuple(contract.allowed_mcp),
        allowed_skills=tuple(contract.allowed_skills),
        network=contract.network,
        contract_hash=contract.hash(),
    )


@dataclass
class PlanAdherence:
    """Result of comparing an actual changeset against the bound plan."""

    within_plan: bool
    deviations: list[str] = field(default_factory=list)
    plan_hash: str = ""

    def to_public(self) -> dict[str, Any]:
        return {
            "within_plan": self.within_plan,
            "deviations": list(self.deviations),
            "plan_hash": self.plan_hash,
        }


def evaluate_plan_adherence(plan: PlanCapabilitySet, changed_files: list[str]) -> PlanAdherence:
    """Check the actual changeset against the plan's file envelope.

    The contract evaluator already blocks a forbidden/out-of-scope changeset; this
    is the explicit, receipt-bound record of whether the run stayed inside the plan
    it was granted. It reuses the contract's glob semantics via a lightweight local
    check so the plan can be evaluated even without re-running the full contract.
    Deviations here NEVER widen authority — they only ever cap it.
    """
    from .contract import _matches_any, is_malformed_path

    files = [f for f in (changed_files or []) if f]
    deviations: list[str] = []
    for f in files:
        if is_malformed_path(f):
            deviations.append(f"malformed path outside plan: {f!r}")
            continue
        if _matches_any(f, plan.forbidden_paths, case_insensitive=True):
            deviations.append(f"touched a path the plan forbids: {f}")
            continue
        if plan.allowed_paths and not _matches_any(f, plan.allowed_paths):
            deviations.append(f"touched a path outside the plan's allowed scope: {f}")
    if plan.max_files_changed and len(files) > plan.max_files_changed:
        deviations.append(f"changed {len(files)} files, exceeding the plan budget of {plan.max_files_changed}")
    return PlanAdherence(within_plan=not deviations, deviations=deviations, plan_hash=plan.hash())
