"""Fusion: turn a detection finding into a governed, receipted fix proposal.

This is the capability no pure scanner has. A scanner says "here is a bug". Umbra
can go further: take a finding, hand a **bounded** remediation mission to an
executor (Codex / Claude Code / any adapter), run the resulting change through the
full admission pipeline (contract → trust boundary → checks → independent verifier
→ earned authority), and seal it in an Ed25519-signed receipt. The output is not
"here is a bug" but "here is the bug, a proposed fix, the evidence it passed
checks, the authority it earned, and a verifiable receipt" — and it never merges.

The bridge is deliberately thin and safe:
- The mission is scoped to the finding's file + a precise instruction; the contract
  still bounds what may change.
- Any executor works; with no live agent, the ``NullExecutor`` produces an empty
  changeset so the pipeline runs deterministically (authority caps at analyze).
- Authority is earned from evidence exactly as in a normal admission run — fusion
  adds no new authority path and never sets auto_merge.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...executors.base import Executor
from ...executors.null import NullExecutor
from ...executors.registry import resolve_available
from ..admission import AdmissionReport, run_admission
from ..receipt import build_receipt
from .model import Finding
from .secret_redaction import redact_secrets


def mission_for_finding(finding: Finding) -> str:
    """A bounded, single-purpose remediation instruction for one finding."""
    return (
        f"Fix the {finding.category.replace('_', ' ')} vulnerability "
        f"({finding.cwe or 'security issue'}) at {finding.file}:{finding.line}. "
        f"{finding.remediation} "
        f"Change only what is necessary to remediate this specific issue; do not "
        f"modify unrelated code, configuration, or tests."
    )


def _receipt_for(report: AdmissionReport) -> dict[str, Any]:
    """Seal an admission report into an Ed25519-signed receipt envelope.

    The diff is secret-redacted first (BYOK safety): even if an executor echoed a
    credential-shaped token into the change, it never reaches the receipt."""
    return build_receipt(
        repo=report.repo, base_commit=report.base_commit, contract=report.contract,
        contract_result=report.contract_result, verifier=report.verifier,
        trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
        providers=report.providers, authority_level=report.authority_level,
        authority=report.authority, executor=report.executor,
        diff=redact_secrets(report.diff),
        checks=report.checks, baseline_checks=report.baseline_checks,
        check_diagnosis=report.check_diagnosis, model_identity=report.model_identity,
        context_manifest=report.context_manifest, outcome=report.outcome,
    )


@dataclass
class FixProposal:
    finding: Finding
    mission: str
    report: AdmissionReport
    receipt: dict[str, Any] | None = None

    @property
    def diff(self) -> str | None:
        # Secret-redacted so an artifact/PR built from this never carries a key.
        return redact_secrets(self.report.diff)

    @property
    def branch_pr_ready(self) -> bool:
        """L2 = the change earned branch-only PR authority (a human still merges)."""
        return self.report.authority_level >= 2

    def to_public(self) -> dict[str, Any]:
        # Redact the diff in BOTH surfaces so no artifact/PR built from this can
        # carry an executor credential (bring-your-own-key safety).
        admission = self.report.to_public()
        if admission.get("diff"):
            admission["diff"] = redact_secrets(admission["diff"])
        return {
            "finding": self.finding.to_public(),
            "mission": self.mission,
            "admission": admission,
            "authority_level": self.report.authority_level,
            "authority": self.report.authority,
            "outcome": self.report.outcome,
            "branch_pr_ready": self.branch_pr_ready,
            "diff": self.diff,
            "receipt": self.receipt,
            "auto_merge": False,
        }


def _select_executor(executor: Executor | None, agent: str | None) -> Executor:
    """Resolve the executor: an explicit instance, a named/auto live agent, or the
    deterministic NullExecutor fallback."""
    if executor is not None:
        return executor
    if agent:
        from ...executors.registry import get_executor
        return get_executor(agent)
    # Auto-pick a live agent if one is available; else deterministic Null.
    return resolve_available() or NullExecutor()


def propose_fix(
    repo_path: Path | str,
    finding: Finding,
    *,
    executor: Executor | None = None,
    agent: str | None = None,
    repo_label: str | None = None,
    sign_receipt: bool = True,
) -> FixProposal:
    """Propose a governed fix for one finding and run it through admission.

    ``executor`` (an instance) or ``agent`` (a registry name like ``codex-cli`` /
    ``claude-code``) selects who drafts the fix. With neither, a live agent is
    auto-selected if available, otherwise the deterministic :class:`NullExecutor`
    runs the pipeline end-to-end (capped at analyze — no change proposed).

    When the run earns any authority and ``sign_receipt`` is set, an Ed25519-signed
    receipt envelope is attached.
    """
    root = Path(repo_path)
    ex = _select_executor(executor, agent)
    mission = mission_for_finding(finding)
    label = repo_label or root.name
    report = run_admission(root, label, mission, ex)
    receipt = _receipt_for(report) if sign_receipt else None
    return FixProposal(finding=finding, mission=mission, report=report, receipt=receipt)


def propose_fixes(
    repo_path: Path | str,
    findings: list[Finding],
    *,
    executor: Executor | None = None,
    agent: str | None = None,
    repo_label: str | None = None,
    max_fixes: int = 10,
    sign_receipt: bool = True,
) -> list[FixProposal]:
    """Propose governed fixes for up to ``max_fixes`` findings (highest severity
    first). Each runs through admission independently so one fix's verdict never
    contaminates another's."""
    ordered = sorted(findings, key=lambda f: -f.severity.rank)[:max_fixes]
    return [
        propose_fix(repo_path, f, executor=executor, agent=agent,
                    repo_label=repo_label, sign_receipt=sign_receipt)
        for f in ordered
    ]
