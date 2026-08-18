"""Aider CLI executor — adapts ``aider --message`` to the Executor protocol.

Follows the same shape as the sibling adapters (``codex.py``, ``claude_code.py``):
fail closed on an explicit opt-in plus a live CLI, run the agent against a checkout
with commit/push authority withheld, and derive the result from the repository diff
rather than from the agent's own claim of success.

Aider is invoked with ``--no-auto-commits`` / ``--no-dirty-commits`` so it edits the
working tree but never creates a commit — the change therefore stays governable by
the admission pipeline, which is the whole point of the executor seam.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._shared import (
    Runner,
    bounded_prompt,
    changed_files,
    reason_prompt,
    sanitize_paths,
    unified_diff,
)
from .base import ExecutionResult

logger = logging.getLogger("signetry.executor.aider")

# Aider accepts any provider/model string, so there is no meaningful allowlist to
# apply. What matters is that a caller-supplied value can never smuggle shell
# metacharacters or extra arguments into the command we build — same guard the
# Codex adapter applies to its -m value.
# The first character must be alphanumeric: a value like "--dangerously-x" passes a
# naive character class (because "-" is legal inside a model name) but an argument
# parser may read a leading dash as a new option rather than as --model's value.
_SAFE_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,95}")

# Hard-coded flags that withhold authority. Kept as a named constant so a change
# here is visible in review rather than buried in the command construction.
_WITHHELD_AUTHORITY = (
    "--no-auto-commits",        # never create a commit
    "--no-dirty-commits",       # never commit pre-existing dirty state either
    "--no-suggest-shell-commands",  # never propose shell execution
)


class AiderExecutor:
    """Draft changes with Aider while withholding commit and push authority."""

    name = "aider"

    def __init__(self, runner: Runner = subprocess.run, model: str | None = None) -> None:
        self.runner = runner
        self.model = self._resolve_model(
            model if model is not None else os.getenv("SIGNETRY_AIDER_MODEL")
        )

    @staticmethod
    def _resolve_model(value: str | None) -> str | None:
        """Accept a model name only if it cannot alter the command we build."""
        value = (value or "").strip()
        if not value:
            return None
        if not _SAFE_MODEL.fullmatch(value):
            logger.warning("ignoring unsafe SIGNETRY_AIDER_MODEL value")
            return None
        return value

    # --- capability ---------------------------------------------------------
    def available(self) -> bool:
        """Two independent conditions: the operator opted in, and the CLI answers."""
        if os.getenv("SIGNETRY_ENABLE_AIDER", "false").lower() != "true":
            return False
        return self._cli_version() is not None

    def _cli_version(self) -> str | None:
        try:
            r = self.runner(["aider", "--version"], text=True, capture_output=True,
                            timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if r is None:
            return None
        out = ((getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")).strip()
        return out.splitlines()[0].strip() if out else None

    # --- provenance ---------------------------------------------------------
    def model_identity(self) -> dict[str, Any]:
        pinned = self.model
        return {
            "executor": self.name,
            "cli_version": self._cli_version() or "unavailable",
            "model_configured": pinned or "aider-default",
            # A --model value is REQUESTED, not attested-as-run. Aider does not
            # report the provider model it resolved, so this stays unavailable
            # rather than being back-filled from the request — a receipt must not
            # carry a value nothing verified.
            "model_resolved": "unavailable",
            "model_evidence": "cli-argument" if pinned else "aider-default",
        }

    # --- execution ----------------------------------------------------------
    def propose(self, prompt: str, repo_path: Path, *, read_only: bool = False) -> ExecutionResult:
        if not self.available():
            return ExecutionResult.disabled(
                prompt,
                self.name,
                "Aider is disabled. Set SIGNETRY_ENABLE_AIDER=true and configure an "
                "Aider model provider.",
            )
        if repo_path is None or not repo_path.is_dir():
            raise RuntimeError("A checked-out repository is required for AiderExecutor.propose()")

        cli_prompt = reason_prompt(prompt, "Aider") if read_only else bounded_prompt(prompt, "Aider")
        command = [
            "aider",
            "--message", cli_prompt,
            "--yes-always",         # non-interactive; the mission is already bounded
            "--no-gitignore",       # do not let the agent edit ignore rules
            *_WITHHELD_AUTHORITY,
        ]
        if read_only:
            command.append("--dry-run")
        if self.model:
            command += ["--model", self.model]

        # The mission text can be sensitive and ends up on a receipt, so the
        # replayable command records a placeholder instead of the prompt.
        replay = command[:2] + ["<agent prompt redacted from command replay>"] + command[3:]

        try:
            completed = self.runner(command, text=True, capture_output=True, timeout=900,
                                    check=False, cwd=str(repo_path))
        except (OSError, subprocess.SubprocessError) as exc:
            return ExecutionResult.failed(prompt, self.name, str(exc)[:300], command=replay)

        rc = getattr(completed, "returncode", 1)
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""
        if rc != 0:
            logger.warning("aider --message failed (rc=%s): %s", rc, stderr[-1000:])

        # Ground truth is the repository diff, not Aider's narration.
        diff = unified_diff(repo_path)
        files = changed_files(repo_path)
        summary = stdout.strip() or (
            ("Aider completed; see the diff below." if diff else "Aider ran and produced no changes.")
            if rc == 0 else f"Aider failed (exit {rc})."
        )

        return ExecutionResult(
            prompt=prompt,
            summary=sanitize_paths(summary, repo_path),
            diff=diff,
            tests_passed=rc == 0,
            files=files,
            # Honesty rule: only name the executor when it actually produced output.
            executor=self.name if rc == 0 else "unavailable",
            created_at=datetime.now(UTC).isoformat(),
            command=replay,
            stdout=sanitize_paths(stdout[-12000:], repo_path),
            error=sanitize_paths(stderr[-4000:], repo_path) or None,
            model_identity=self.model_identity(),
        )
