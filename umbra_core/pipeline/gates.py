"""G1 / G2 / G3 proof gates — the receipt's explicit accountability summary.

A signed receipt carries a lot of evidence (contract, plan, checks, verifier,
provenance). This module distills that evidence into the three governance gates
the architecture names, so a consumer can answer each question directly instead
of re-deriving it from scattered fields:

- **G1 — Capability integrity:** *What was this agent allowed to do?*
  Evidence: the plan capability set + its hash, and the contract hash. Passes only
  when a plan was bound before the run and the change stayed within it.
- **G2 — Behavioral authenticity:** *Did the checks / sandbox actually run?*
  Evidence: the checks report + sandbox tier + honesty ledger. Passes only when the
  contract's required checks actually ran under real isolation and passed (a
  host-restricted or unavailable run does NOT pass G2 — it is honest about that).
- **G3 — Interaction auditability:** *Is the history tamper-evident?*
  Evidence: the Ed25519 signature over the canonical receipt, and (when logged) a
  Merkle transparency-log inclusion. Passes only when signed with a NON-ephemeral
  key (the dev-fallback key's seed is public, so it is not trustworthy provenance).

Each gate reports ``pass`` / ``fail`` / ``unproven`` with a short reason — never a
green on missing evidence. Deterministic and offline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Gate:
    id: str            # "G1" | "G2" | "G3"
    name: str
    status: str        # "pass" | "fail" | "unproven"
    question: str
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "question": self.question,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass
class GateSummary:
    gates: list[Gate] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return bool(self.gates) and all(g.status == "pass" for g in self.gates)

    def to_public(self) -> dict[str, Any]:
        return {
            "all_pass": self.all_pass,
            "gates": [g.to_public() for g in self.gates],
        }


def _g1(receipt: dict[str, Any]) -> Gate:
    plan = receipt.get("plan_capability_set") or {}
    adherence = receipt.get("plan_adherence") or {}
    plan_hash = plan.get("plan_hash")
    contract_hash = receipt.get("policy_hash") or (receipt.get("contract_result") or {}).get("contract_hash")
    within = adherence.get("within_plan")
    evidence = {
        "plan_hash": plan_hash,
        "contract_hash": contract_hash,
        "within_plan": within,
        "deviations": adherence.get("deviations", []),
    }
    if not plan_hash:
        return Gate("G1", "Capability integrity", "unproven",
                    "What was this agent allowed to do?",
                    "No plan capability set was bound for this run (pre-v2 receipt).", evidence)
    if within is False:
        return Gate("G1", "Capability integrity", "fail",
                    "What was this agent allowed to do?",
                    "The change deviated from the capability plan bound before the run.", evidence)
    return Gate("G1", "Capability integrity", "pass",
                "What was this agent allowed to do?",
                "A capability plan was bound before the run and the change stayed within it.", evidence)


def _g2(receipt: dict[str, Any]) -> Gate:
    checks = receipt.get("checks") or {}
    contract = receipt.get("contract") or {}
    required = contract.get("required_checks") or []
    ran = checks.get("ran")
    all_passed = checks.get("all_passed")
    enforcement = checks.get("enforcement")
    ledger = receipt.get("provider_ledger") or {}
    # Real isolation tiers. host-restricted / declared / unavailable are honest but
    # do NOT satisfy behavioral authenticity for a privileged verdict.
    real_isolation = enforcement in ("sandboxed", "network-isolated")
    evidence = {
        "required_checks": list(required),
        "ran": ran,
        "all_passed": all_passed,
        "enforcement": enforcement,
        "checks_provider": ledger.get("checks"),
    }
    if not required:
        return Gate("G2", "Behavioral authenticity", "unproven",
                    "Did the checks / sandbox actually run?",
                    "The contract declared no required checks, so behavioral authenticity is not asserted.", evidence)
    if not ran:
        return Gate("G2", "Behavioral authenticity", "fail",
                    "Did the checks / sandbox actually run?",
                    "The contract's required checks did not run in this environment.", evidence)
    if not all_passed:
        return Gate("G2", "Behavioral authenticity", "fail",
                    "Did the checks / sandbox actually run?",
                    "Required checks ran but did not all pass.", evidence)
    if not real_isolation:
        return Gate("G2", "Behavioral authenticity", "unproven",
                    "Did the checks / sandbox actually run?",
                    f"Checks passed but ran under '{enforcement or 'unknown'}' isolation (not a full sandbox); "
                    "behavioral authenticity is not asserted for a privileged verdict.", evidence)
    return Gate("G2", "Behavioral authenticity", "pass",
                "Did the checks / sandbox actually run?",
                f"Required checks ran under real isolation ({enforcement}) and passed.", evidence)


def _g3(envelope: dict[str, Any], log_inclusion: dict[str, Any] | None) -> Gate:
    key_ephemeral = bool(envelope.get("key_ephemeral"))
    signature = envelope.get("signature")
    canonical_hash = envelope.get("canonical_hash")
    logged = bool(log_inclusion and log_inclusion.get("root"))
    evidence = {
        "signed": bool(signature),
        "canonical_hash": canonical_hash,
        "key_ephemeral": key_ephemeral,
        "algorithm": envelope.get("algorithm", "Ed25519"),
        "transparency_log": {
            "logged": logged,
            "root": (log_inclusion or {}).get("root"),
            "size": (log_inclusion or {}).get("size"),
            "index": ((log_inclusion or {}).get("entry") or {}).get("index"),
        },
    }
    if not signature or not canonical_hash:
        return Gate("G3", "Interaction auditability", "fail",
                    "Is the history tamper-evident?",
                    "The receipt is not signed / carries no canonical hash.", evidence)
    if key_ephemeral:
        return Gate("G3", "Interaction auditability", "unproven",
                    "Is the history tamper-evident?",
                    "Signed with the dev-fallback key (its seed is public), so this is not trustworthy "
                    "provenance. Set a production UMBRA_SIGNING_KEY.", evidence)
    reason = "Signed with a managed key over the canonical receipt."
    if logged:
        reason += f" Entered into the append-only transparency log (root {evidence['transparency_log']['root'][:12]}…)."
    return Gate("G3", "Interaction auditability", "pass",
                "Is the history tamper-evident?", reason, evidence)


def evaluate_gates(envelope: dict[str, Any], *, log_inclusion: dict[str, Any] | None = None) -> GateSummary:
    """Compute the G1/G2/G3 gate summary from a signed receipt ``envelope``.

    ``envelope`` is the dict returned by :func:`build_receipt`. ``log_inclusion``
    is the optional result of appending the receipt to a
    :class:`~umbra_core.pipeline.transparency.TransparencyLog` (used to strengthen
    G3). Deterministic and offline — never asserts a gate on missing evidence.
    """
    receipt = envelope.get("receipt") or {}
    return GateSummary(gates=[
        _g1(receipt),
        _g2(receipt),
        _g3(envelope, log_inclusion),
    ])
