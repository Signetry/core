"""Aider CLI executor — adapts ``aider --message`` to the Executor protocol.

Ported from @adity982's implementation in PR #55, which predated the
``umbra_core`` → ``signetry_core`` rename and so could no longer be rebased. The
adapter design (flag set, diff-derived result, prompt redaction) is theirs; this
port updates the package path, the env-var prefix, and the model allowlist.

Aider is run against a checkout with commit and push authority deliberately
withheld: ``--no-auto-commits`` / ``--no-dirty-commits`` mean Aider edits the
working tree but never creates a commit, so the change stays governable by the
admission pipeline. The result is derived from the repository diff, not from
Aider's own claim of success.
"""
from __future__ import annotations

import logging
import os
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


class AiderExecutor:
    """Draft changes with Aider while withholding commit and push authority."""

    name = "aider"

    def __init__(
        self,
        runner: Runner = subprocess.run,
        model: str | None = None,
    ) -> None:
        self.runner = runner
        configured = model if model is not None else os.getenv("SIGNETRY_AIDER_MODEL")
        self.model = (configured or "").strip() or None

    # --- capability ---------------------------------------------------------
    def available(self) -> bool:
        """Fail closed: opt-in via env AND the CLI must actually respond."""
        if os.getenv("SIGNETRY_ENABLE_AIDER", "false").lower() != "true":
            return False
        return self._cli_version() is not None

    def _cli_version(self) -> str | None:
        try:
            result = self.runner(
                ["aider", "--version"],
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result is None:
            return None
        output = (
            (getattr(result, "stdout", "") or "") + (getattr(result, "stderr", "") or "")
        ).strip()
        return output.splitlines()[0].strip() if output else None

    def model_identity(self) -> dict[str, Any]:
        """Report what we know, and mark what we cannot verify as unavailable.

        Aider does not echo the resolved provider model, so ``model_resolved`` is
        honestly ``unavailable`` rather than being back-filled from the request.
        """
        return {
            "executor": self.name,
            "cli_version": self._cli_version() or "unavailable",
            "model_configured": self.model or "aider-default",
            "model_resolved": "unavailable",
            "model_evidence": "cli-argument" if self.model else "aider-default",
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
            "--message",
            cli_prompt,
            "--yes-always",
            # Commit authority stays with the pipeline, not the agent: Aider edits
            # the working tree and never commits, so the change remains governable.
            "--no-auto-commits",
            "--no-dirty-commits",
            "--no-gitignore",
            "--no-suggest-shell-commands",
        ]
        if read_only:
            command.append("--dry-run")
        if self.model:
            command.extend(["--model", self.model])

        # The prompt can contain the mission verbatim; keep it out of the replay
        # command recorded on the receipt.
        redacted_command = (
            command[:2] + ["<agent prompt redacted from command replay>"] + command[3:]
        )
        try:
            completed = self.runner(
                command,
                text=True,
                capture_output=True,
                timeout=900,
                check=False,
                cwd=str(repo_path),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ExecutionResult.failed(
                prompt,
                self.name,
                str(exc)[:300],
                command=redacted_command,
            )

        returncode = getattr(completed, "returncode", 1)
        stdout = getattr(completed, "stdout", "") or ""
        stderr = getattr(completed, "stderr", "") or ""
        # Ground truth is the repository diff, not Aider's own summary.
        diff = unified_diff(repo_path)
        files = changed_files(repo_path)
        summary = stdout.strip()
        if not summary:
            if returncode == 0:
                summary = (
                    "Aider completed; see the diff below." if diff
                    else "Aider ran and produced no changes."
                )
            else:
                summary = f"Aider failed (exit {returncode})."

        return ExecutionResult(
            prompt=prompt,
            summary=sanitize_paths(summary, repo_path),
            diff=diff,
            tests_passed=returncode == 0,
            files=files,
            # Honesty rule: only claim the executor produced output when it did.
            executor=self.name if returncode == 0 else "unavailable",
            created_at=datetime.now(UTC).isoformat(),
            command=redacted_command,
            stdout=sanitize_paths(stdout[-12000:], repo_path),
            error=sanitize_paths(stderr[-4000:], repo_path) or None,
            model_identity=self.model_identity(),
        )
