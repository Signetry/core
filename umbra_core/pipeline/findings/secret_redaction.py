"""Redact credential-shaped tokens from text that leaves the process.

Bring-your-own-key safety: the executor (Codex/Claude CLI) needs a credential to
draft a fix, but that credential must never leak into a diff, a receipt, an
artifact, or an opened PR. This scrubber replaces recognised secret shapes with a
fixed placeholder before any fix output is serialised. It is defense-in-depth on
top of the pipeline's allowlisted check env (which already prevents keys from
reaching check subprocesses by construction).

Deterministic, dependency-free, and conservative — it only rewrites tokens whose
*shape* is unambiguously a credential, so real code is untouched.
"""
from __future__ import annotations

import re

_PLACEHOLDER = "***REDACTED-SECRET***"

# Credential shapes (provider prefixes + generic assigned secrets).
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),                     # OpenAI / generic sk-
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),                 # Anthropic
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),               # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),             # GitHub fine-grained PAT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                          # AWS access key id
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                     # Google API key
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),             # Slack
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    # Generic: NAME containing secret-ish word = "long value"
    re.compile(
        r"(?i)((?:api[_-]?key|secret|token|password|passwd|credential)\s*[:=]\s*['\"]?)"
        r"[^\s'\"]{12,}(['\"]?)"
    ),
)


def redact_secrets(text: str | None) -> str | None:
    """Return ``text`` with credential-shaped tokens replaced by a placeholder.
    ``None`` passes through unchanged."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        if pat.groups == 2:  # keep the assignment prefix/suffix, redact the value
            out = pat.sub(lambda m: m.group(1) + _PLACEHOLDER + m.group(2), out)
        else:
            out = pat.sub(_PLACEHOLDER, out)
    return out
