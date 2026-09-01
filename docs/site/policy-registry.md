# Policy registry

Writing your first admission contract is where adoption stalls. The format is simple —
a few globs and a diff budget — but deciding *what an agent should be allowed to touch in
this stack* is a real security decision, and most teams put it off.

The registry answers it with named policies for common repository shapes:

```bash
signetry policies                            # what's available
signetry init --policy python-library        # install one
```

That writes `.signetry/admission.yaml` and prints the scope you just adopted.

## What's in it

| id | For | Scope |
|---|---|---|
| `docs-only` | any repo | Markdown, text and images. No code, no config, no CI. |
| `dependency-bump` | any repo | Manifests and lockfiles only. The narrowest useful policy. |
| `python-library` | src-layout Python | Library code, tests, `pyproject.toml`. Keeps pytest green. |
| `node-service` | Node / TypeScript | App code and tests. Not the build or release path. |
| `monorepo-service` | monorepos | One service directory; siblings and shared packages excluded. |
| `ci-workflow-fix` | GitHub Actions | Workflow files only, one at a time. **Read its caution.** |

`docs-only` is the usual starting point: it lets a team watch the whole pipeline —
scope enforcement, verifier, signed receipt — on a change that cannot break anything.

## Two properties worth knowing

### What ships is what lands

A registry entry is a literal, valid `.signetry/admission.yaml`. `init --policy` copies
the bytes verbatim: no templating, no merging, no rewriting. Diff your installed file
against the published one and you get nothing.

Metadata lives in `# @policy` header comments, which the contract parser ignores and a
human reading the installed file still benefits from.

### Every entry carries its own evidence

Each policy declares example paths it must block and example paths it must allow:

```yaml
# @policy blocks: .github/workflows/release.yml, setup.py, tests/conftest.py
# @policy allows: src/mylib/core.py, tests/test_core.py, pyproject.toml
```

`tests/test_policy_registry.py` runs every one of those through the real
`evaluate_contract` — the same function the admission pipeline uses. A policy whose
claims don't hold fails CI.

The `allows` direction matters as much as `blocks`: it's what catches an over-broad
forbidden glob quietly making a policy useless, which is the failure mode you would
otherwise discover months later when an agent could never propose anything.

## A registry policy is not an owned policy

Every entry ships `policy_owner: your-team`, and Signetry treats that as **unowned**:

```
$ signetry init --policy python-library
wrote /repo/.signetry/admission.yaml  (python-library — Python library (src layout, pytest))
  scope    5 allowed pattern(s), 10 forbidden, max 12 file(s)
  checks   pytest -q
  owner    unowned — set policy_owner and policy_version to adopt this policy as your own
```

Receipts report `policy_status: placeholder` until a human sets a real `policy_owner` and
`policy_version`. This is deliberate. A borrowed policy nobody at your organization has
read is not change-controlled, and a receipt claiming otherwise would be worse than one
that admits the gap. Adopting a policy is a human act; the registry can't perform it for
you.

`placeholder` doesn't restrict what a change can earn — authority still comes from the
deterministic contract, the independent verifier and your required checks. It only stops
the receipt from asserting provenance that doesn't exist.

## Contributing a policy

This is the most useful thing you can add to Signetry without touching the kernel, and
the bar is *evidence*, not taste.

1. Add `signetry_core/policies/<your-id>.yaml`. The filename must match `@policy id`.
2. Fill in the required header keys: `id`, `title`, `summary`, `author`, `blocks`,
   `allows`. Add `stack` and `caution` where they help.
3. Choose `blocks` and `allows` examples that would actually catch a mistake. Three or
   four of each, using realistic paths for the stack. Include at least one `blocks` entry
   that sits *inside* your `allowed_paths` — carving an exception out of a directory you
   otherwise own is the part people get wrong.
4. Run `pytest tests/test_policy_registry.py`. Your policy is validated the moment the
   file exists; there is nothing to register.

Rules the tests enforce, so you don't have to remember them:

- Every claimed block is refused, and every claimed allow passes.
- `blocks` and `allows` don't overlap.
- The policy declares real scope and a bounded diff budget — a contract with neither
  gets its scope silently replaced by the default on load, governing nothing while
  appearing to.
- `policy_owner` is a recognised placeholder, so no adopter inherits a false claim of
  ownership.

What makes a policy worth merging: a repository shape people actually have, a scope you
can defend line by line, and comments explaining *why* something is forbidden rather than
just that it is. `python-library` forbids `conftest.py` at any depth — the comment says
it executes at collection time on every developer machine, which is the reasoning a
reviewer needs.

Policies that permit something risky are acceptable if they are honest about it. See
`ci-workflow-fix`: it allows workflow edits because teams genuinely need that task
governed rather than done outside Signetry, and it carries a `caution` that `signetry
init` prints at adoption time. A risky policy with no caution will be sent back.
