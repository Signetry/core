# Capabilities & Proof

Umbra v0.3.0 governs more than paths. This page covers the capability graph, the
plan binding, the dual verifier, the G1/G2/G3 proof gates, and extension admission
— all deterministic, offline, and bound into the signed receipt.

## Capability graph (contract v2)

The contract can restrict what an agent may *do*, not just what files it may touch.
Every class is optional and additive — omit it for no extra restriction, and a v1
contract behaves exactly as before (its rules hash is unchanged).

| Field | Restricts |
|---|---|
| `allowed_tools` | Agent tool/command names — a tool off the list is denied. |
| `denied_bash` | Extra shell deny patterns, layered on the built-in dangerous-command baseline (a malformed regex fails **closed**). |
| `allowed_mcp` | MCP calls — `server` or `server:tool` identifiers. |
| `allowed_skills` | Skill/plugin identifiers permitted to load. |

Capabilities can only **restrict**; they never grant `auto_merge` or widen
authority. The guard enforces them deterministically:

```bash
umbra guard --repo . --tool WebFetch          # deny if not in allowed_tools
umbra guard --repo . --mcp github:push        # deny if not in allowed_mcp
umbra guard --repo . --command "docker run …" # deny if it matches denied_bash
```

## Plan capability binding (CaMeL / DRIFT)

Before the executor runs, Umbra freezes a **PlanCapabilitySet** from the mission +
contract — a hashable envelope of what the run may do (only a *digest* of the
mission is bound, never its prose). After the run, the actual changeset is checked
against that plan; a deviation caps authority (never widens it). The plan hash is
recorded in the receipt so an auditor can answer *what was this agent allowed to
do?* (gate **G1**).

## Dual verifier — the writer never self-approves

Two independent paths judge every change:

1. **Deterministic** — contract compliance, secret scan, required checks, advisory
   clearance.
2. **Independent (masked)** — a MELON-style re-check that correlates the change
   against the manipulation categories the trust boundary detected. If a change
   does what a quarantined injection surface pushed for (e.g. the README tried to
   induce secret access and the change now reads env secrets), it raises a
   **hijack signal** and authority is capped at ≤ L1. It never *blocks* — the
   deterministic path owns blocking — but the writer's word alone can't earn L2.

## Proof gates — G1 / G2 / G3

`umbra gates <receipt.json>` distills a signed receipt into three honest verdicts
(each `pass` / `fail` / `unproven` — never green on missing evidence):

| Gate | Question | Passes when |
|---|---|---|
| **G1** Capability integrity | What was this agent allowed to do? | A plan was bound before the run and the change stayed within it. |
| **G2** Behavioral authenticity | Did the checks/sandbox actually run? | Required checks ran under real isolation (`sandboxed` / `network-isolated`) and passed. A `host-restricted` run is honestly `unproven`. |
| **G3** Interaction auditability | Is the history tamper-evident? | Signed with a non-ephemeral key; strengthened when the receipt is in the Merkle transparency log. |

`umbra gates` exits non-zero unless all gates pass, so it can gate CI.

## Extension admission (skill / MCP supply chain)

An agent's authority also flows through the extensions it loads. `admit_extension`
governs a *skill* directory or an *MCP* server as a first-class object:

```bash
umbra admit-extension ./my-skill --repo .        # applies the contract allowlist
umbra admit-extension ./my-mcp-server --asbom     # emit a CycloneDX ASBOM
```

- **Fingerprint** — every file is content-hashed into a stable `extension_hash`; a
  later silent edit changes the hash.
- **Quarantine before read** — `SKILL.md` / README and every MCP tool
  `description` are scanned with the trust-boundary detector; a manipulation is a
  **deny**, not an instruction (fail-closed; `--allow-quarantined` is an explicit
  human override).
- **Allowlist** — enforced against the contract's `allowed_skills` / `allowed_mcp`.
- **ASBOM** — a CycloneDX 1.5 Agent Software Bill of Materials for org inventory.

Admitting an extension never grants authority; it records that these exact bytes
were reviewed.

## One canonical result

Every surface — CLI, API, MCP, the GitHub Action, the hosted console — returns the
same **Admission Decision Pack**, and the PR comment is rendered from it by
`umbra comment`, so no surface can invent a stronger claim than the receipt.
