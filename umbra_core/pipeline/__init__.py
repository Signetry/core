"""The governed admission pipeline: contract -> trust boundary -> checks ->
verifier -> earned authority -> signed receipt. Agent-agnostic — driven by any
:class:`~umbra_core.executors.base.Executor`."""
from .admission import (
    AUTHORITY,
    AUTHORITY_LABEL,
    AdmissionReport,
    run_admission,
)
from .checks import ChecksReport, CheckResult, run_required_checks
from .contract import (
    Contract,
    ContractResult,
    contract_from_dict,
    default_contract,
    evaluate_contract,
    load_contract,
)
from .gates import Gate, GateSummary, evaluate_gates
from .extension import (
    AdmittedExtension,
    ExtensionFile,
    admit_extension,
    asbom,
    inspect_extension,
)
from .render import render_pr_comment
from .guard import GuardDecision, guard, guard_command, guard_mcp, guard_path, guard_skill, guard_tool
from .plan import (
    PlanAdherence,
    PlanCapabilitySet,
    derive_plan,
    evaluate_plan_adherence,
)
from .passport import (
    InMemoryPassportStore,
    JsonFilePassportStore,
    PassportError,
    PassportStatus,
    PassportStore,
    evaluate as evaluate_passport,
    gate_pr,
    issue_passport,
    revoke,
)
from .provenance import (
    SLSA_PREDICATE_TYPE,
    STATEMENT_TYPE,
    to_slsa_provenance,
)
from .receipt import (
    build_receipt,
    public_key_b64,
    sign,
    signing_key_is_ephemeral,
    verify_receipt,
    verify_signature,
)
from .transparency import (
    InMemoryLogStore,
    JsonFileLogStore,
    LogStore,
    TransparencyLog,
    merkle_root,
    verify_inclusion,
)
from .trust_boundary import (
    TrustBoundaryResult,
    register_semantic_classifier,
    sanitize_checkout,
    scan_repository_text,
    scan_structural,
    scan_text,
)
from .verifier import VerifierReport, masked_recheck, verify_change

__all__ = [
    "AdmissionReport",
    "run_admission",
    "AUTHORITY",
    "AUTHORITY_LABEL",
    "Contract",
    "ContractResult",
    "contract_from_dict",
    "default_contract",
    "evaluate_contract",
    "load_contract",
    "guard",
    "guard_path",
    "guard_command",
    "guard_tool",
    "guard_mcp",
    "guard_skill",
    "GuardDecision",
    # G1/G2/G3 proof gates
    "Gate",
    "GateSummary",
    "evaluate_gates",
    "render_pr_comment",
    # admitted extensions (skill / MCP supply chain) + ASBOM
    "AdmittedExtension",
    "ExtensionFile",
    "inspect_extension",
    "admit_extension",
    "asbom",
    # plan capability binding (CaMeL / DRIFT)
    "PlanCapabilitySet",
    "PlanAdherence",
    "derive_plan",
    "evaluate_plan_adherence",
    "ChecksReport",
    "CheckResult",
    "run_required_checks",
    "TrustBoundaryResult",
    "scan_repository_text",
    "scan_text",
    "scan_structural",
    "register_semantic_classifier",
    "sanitize_checkout",
    "VerifierReport",
    "verify_change",
    "masked_recheck",
    "build_receipt",
    "verify_receipt",
    "verify_signature",
    "sign",
    "public_key_b64",
    "signing_key_is_ephemeral",
    # passport / emergency brake
    "issue_passport",
    "gate_pr",
    "revoke",
    "evaluate_passport",
    "PassportStore",
    "PassportStatus",
    "PassportError",
    "InMemoryPassportStore",
    "JsonFilePassportStore",
    # SLSA / in-toto provenance
    "to_slsa_provenance",
    "STATEMENT_TYPE",
    "SLSA_PREDICATE_TYPE",
    # transparency log
    "TransparencyLog",
    "LogStore",
    "InMemoryLogStore",
    "JsonFileLogStore",
    "merkle_root",
    "verify_inclusion",
]
