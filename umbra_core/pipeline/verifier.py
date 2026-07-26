"""Independent Verifier — the deterministic second opinion on a proposed change.

The agent that writes a patch must never be the sole judge of its own patch. This
module is that independent check: given the actual changeset (path → new content),
the contract verdict, and optional advisory/test context, it produces a
deterministic ``VerifierReport`` — offline, no model, no agent.

What it checks (each a discrete, inspectable check):
- **contract**: the change passed the executable Change Contract (scope + budget).
- **secret_scan**: no likely credential was introduced in the new content.
- **advisory_cleared**: when a package + fixed version are claimed, the changed
  manifest actually pins a version that escapes the advisory range.
- **tests**: records the declared test command + exit code — never invents a pass.
- **citations**: every changed path the change claims is present in the changeset.

``status`` ∈ {reviewable, blocked}; ``blocked`` means a hard safety check failed
(contract or secret). Missing soft evidence lowers ``evidence_completeness`` but
stays ``reviewable`` — a reviewer decides, the verifier never fakes a green.

**Independent (masked) second opinion (MELON / ShieldAgent line).** The primary
path judges the change against the contract. A determined injection may still
produce a change that *technically* passes scope while doing what an injected
instruction asked. The masked re-check asks a counterfactual: *with the mission
set aside, is anything in this change explainable only by the untrusted repository
text that was quarantined?* Concretely, it correlates the categories of detected
trust-boundary manipulation (e.g. ``secret_access``, ``scope_expansion``,
``command_injection``) with what the changeset actually did. When a change
introduces exactly the behaviour an injection surface was pushing, that is a
**hijack signal**: the deterministic path may not block it, but the pipeline caps
authority at ≤ L1. This is a second, independent judgement — not the writer
grading itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .contract import ContractResult
from ._helpers import scan_secrets, version_key


# Signals a changeset can exhibit, mapped to the trust-boundary manipulation
# categories that would "explain" them if present. If the repo text tried to
# induce category X and the change now exhibits the matching signal, the masked
# re-check treats the coincidence as a hijack signal rather than a coincidence.
_SIGNAL_PATTERNS: dict[str, re.Pattern[str]] = {
    "reads_secret": re.compile(r"(?i)\b(process\.env|os\.environ|getenv|dotenv|\.env\b|secret|credential|api[_-]?key|token)\b"),
    "network_exfil": re.compile(r"(?i)\b(fetch|axios|requests\.(get|post)|urllib|curl|wget|http[s]?://|socket)\b"),
    "shell_exec": re.compile(r"(?i)\b(subprocess|os\.system|child_process|exec\(|eval\(|spawn\(|popen)\b"),
    "scope_expansion": re.compile(r"(?i)(deploy|\.github/workflows|infra/|ci\.ya?ml|Dockerfile|auth/)"),
}

# Which trust-boundary category "explains" which change signal.
_CATEGORY_TO_SIGNAL: dict[str, str] = {
    "secret_access": "reads_secret",
    "command_injection": "shell_exec",
    "scope_expansion": "scope_expansion",
}


@dataclass
class VerifierCheck:
    name: str
    status: str  # "pass" | "fail" | "unavailable"
    detail: str
    blocking: bool = False

    def to_public(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail, "blocking": self.blocking}


@dataclass
class VerifierReport:
    status: str  # "reviewable" | "blocked"
    checks: list[VerifierCheck] = field(default_factory=list)
    evidence_completeness: int = 0
    changed_files: list[str] = field(default_factory=list)
    secrets_found: int = 0
    # Independent (masked) second-opinion outcome. ``independent_status`` ∈
    # {"clean", "hijack_signal", "unavailable"}. A hijack signal never *blocks*
    # (the deterministic path owns blocking) but the pipeline caps authority ≤ L1
    # when it fires — the writer's change correlates with an injection surface.
    independent_status: str = "unavailable"
    hijack_signal: bool = False
    independent_detail: str = ""

    @property
    def blocked(self) -> bool:
        return self.status == "blocked"

    def to_public(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "blocked": self.blocked,
            "evidence_completeness": self.evidence_completeness,
            "changed_files": list(self.changed_files),
            "secrets_found": self.secrets_found,
            "independent_status": self.independent_status,
            "hijack_signal": self.hijack_signal,
            "independent_detail": self.independent_detail,
            "checks": [c.to_public() for c in self.checks],
        }


def _advisory_cleared(new_manifest: str, package: str, fixed: str) -> tuple[bool, str]:
    """Confirm the new manifest content actually pins ``package`` at ``>= fixed``.

    Deterministic string/version check — we don't trust the agent's claim; we read
    the pinned version out of the produced manifest and compare it to the required
    fixed version.
    """
    npm = re.search(r'"' + re.escape(package) + r'"\s*:\s*"[\^~>=<v ]*([^"\s]+)"', new_manifest)
    pypi = re.search(r"(?im)^\s*" + re.escape(package) + r"\s*==\s*([A-Za-z0-9_.+-]+)", new_manifest)
    pinned = (npm.group(1) if npm else None) or (pypi.group(1) if pypi else None)
    if not pinned:
        return False, f"Could not find a pinned version for {package} in the changed manifest."
    if version_key(pinned) >= version_key(fixed):
        return True, f"{package} is pinned at {pinned} (>= required fix {fixed})."
    return False, f"{package} is pinned at {pinned}, below the required fix {fixed}."


def masked_recheck(
    file_changes: dict[str, str],
    trust_boundary_categories: list[str] | None,
) -> tuple[str, bool, str]:
    """Independent second opinion: does the change do what an injection surface
    pushed for? Returns ``(status, hijack_signal, detail)``.

    ``trust_boundary_categories`` is the set of manipulation categories detected
    in the untrusted repository text (from the trust-boundary scan). If none were
    detected there is nothing to correlate → ``("clean", False, ...)``. Otherwise
    we look for the change *signal* each detected category would explain; a match
    is a hijack signal.

    Deterministic and offline: pure content inspection, no model. This is a
    conservative correlation, not proof of intent — hence it caps authority
    (≤ L1) rather than blocking, and always reports its reasoning.
    """
    categories = sorted({c for c in (trust_boundary_categories or []) if c})
    if not categories:
        return "clean", False, "No trust-boundary manipulation was detected, so there is no injection surface to correlate the change against."

    # Collect the signals the changeset actually exhibits (path + content).
    blob_parts: list[str] = []
    for path, content in file_changes.items():
        blob_parts.append(path)
        blob_parts.append(content or "")
    blob = "\n".join(blob_parts)
    present_signals = {name for name, pat in _SIGNAL_PATTERNS.items() if pat.search(blob)}

    hits: list[str] = []
    for cat in categories:
        signal = _CATEGORY_TO_SIGNAL.get(cat)
        if signal and signal in present_signals:
            hits.append(f"{cat}→{signal}")

    if hits:
        return (
            "hijack_signal",
            True,
            "Change correlates with quarantined injection surface(s): "
            + ", ".join(hits)
            + ". The masked re-check cannot attribute this to the mission alone; "
            "authority is capped pending human review.",
        )
    return (
        "clean",
        False,
        f"Trust-boundary manipulation was detected ({', '.join(categories)}), but the "
        "change exhibits none of the behaviours those surfaces pushed for.",
    )


def verify_change(
    file_changes: dict[str, str],
    contract_result: ContractResult,
    *,
    package: str | None = None,
    fixed_version: str | None = None,
    cve: str | None = None,
    test_command: str | None = None,
    test_exit_code: int | None = None,
    claimed_files: list[str] | None = None,
    trust_boundary_categories: list[str] | None = None,
) -> VerifierReport:
    """Run the independent verification pass over a proposed changeset.

    ``file_changes`` maps changed path → new file content. Advisory/test params are
    optional context; when absent the relevant check is ``unavailable`` (lowering
    completeness) rather than a fabricated pass. ``trust_boundary_categories`` are
    the manipulation categories detected in untrusted repo text; when provided the
    masked re-check correlates the change against them (MELON-style second opinion).
    """
    checks: list[VerifierCheck] = []
    changed = sorted(file_changes.keys())

    # 1. Contract compliance (blocking).
    checks.append(VerifierCheck(
        "contract",
        "pass" if contract_result.passed else "fail",
        "Change is within the contract's scope and budget." if contract_result.passed
        else "Contract violated: " + "; ".join(contract_result.violations),
        blocking=True,
    ))

    # 2. Secret scan (blocking).
    secrets: list[dict[str, object]] = []
    for path, content in file_changes.items():
        secrets.extend(scan_secrets(content or "", path))
    checks.append(VerifierCheck(
        "secret_scan",
        "pass" if not secrets else "fail",
        "No likely credentials in the changed content." if not secrets
        else f"{len(secrets)} likely secret(s) detected in the change (by kind/line only).",
        blocking=True,
    ))

    # 3. Advisory cleared (soft).
    if package and fixed_version:
        manifest = next(
            (c for p, c in file_changes.items() if p.endswith(("package.json", "requirements.txt"))),
            None,
        )
        if manifest is None:
            checks.append(VerifierCheck("advisory_cleared", "unavailable", f"No manifest in the changeset to confirm the {package} fix.", blocking=False))
        else:
            ok, detail = _advisory_cleared(manifest, package, fixed_version)
            checks.append(VerifierCheck("advisory_cleared", "pass" if ok else "fail", detail + (f" (targets {cve})" if cve else ""), blocking=False))
    else:
        checks.append(VerifierCheck("advisory_cleared", "unavailable", "No specific advisory/fix version was claimed for this change.", blocking=False))

    # 4. Tests (soft).
    if test_command and test_exit_code is not None:
        passed = test_exit_code == 0
        checks.append(VerifierCheck("tests", "pass" if passed else "fail", f"`{test_command}` exited {test_exit_code}.", blocking=False))
    else:
        checks.append(VerifierCheck("tests", "unavailable", "No test command was run for this change — human validation required.", blocking=False))

    # 5. Citations (soft).
    if claimed_files:
        missing = [f for f in claimed_files if f not in file_changes]
        checks.append(VerifierCheck(
            "citations",
            "pass" if not missing else "fail",
            "All claimed files are present in the changeset." if not missing
            else f"Claimed file(s) absent from the changeset: {', '.join(missing)}",
            blocking=False,
        ))
    else:
        checks.append(VerifierCheck("citations", "unavailable", "No explicit file citations to cross-check.", blocking=False))

    # 6. Independent (masked) second opinion — never blocking; caps authority.
    independent_status, hijack, independent_detail = masked_recheck(file_changes, trust_boundary_categories)
    checks.append(VerifierCheck(
        "independent_masked",
        "fail" if hijack else ("pass" if independent_status == "clean" else "unavailable"),
        independent_detail,
        blocking=False,
    ))

    resolved = sum(1 for c in checks if c.status != "unavailable")
    completeness = round(100 * resolved / len(checks)) if checks else 0
    blocked = any(c.blocking and c.status == "fail" for c in checks)
    status = "blocked" if blocked else "reviewable"

    return VerifierReport(
        status=status,
        checks=checks,
        evidence_completeness=completeness,
        changed_files=changed,
        secrets_found=len(secrets),
        independent_status=independent_status,
        hijack_signal=hijack,
        independent_detail=independent_detail,
    )
