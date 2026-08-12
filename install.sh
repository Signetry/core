#!/usr/bin/env sh
#
# Signetry CLI installer.  Usage:
#
#   curl -fsSL https://raw.githubusercontent.com/Signetry/core/main/install.sh | sh
#
# Installs the `signetry` CLI (signetry-core) from its **source repo** using the best
# tool available, preferring an isolated install so it never clobbers your project
# environments. signetry-core is source-available (All Rights Reserved) and is NOT
# published to PyPI, so all installs pull from git by tag:
#
#   1. uv    (uv tool install ...)      — fastest, isolated
#   2. pipx  (pipx install ...)         — isolated
#   3. pip   (pip install --user ...)   — fallback
#
# Honest + fail-closed: it prints exactly which tool it used, verifies `signetry`
# is on PATH afterward, and exits non-zero if the install or the verification
# failed. It never pipes anything else into a shell.
set -eu

# optional: SIGNETRY_VERSION=0.5.3 sh install.sh  (defaults to the latest hardened tag)
VERSION="${SIGNETRY_VERSION:-0.6.0}"
SPEC="signetry-core @ git+https://github.com/Signetry/core@v${VERSION}"

say() { printf '  %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '\n== Signetry CLI installer ==\n'

if have uv; then
    say "using uv"
    uv tool install "$SPEC"
elif have pipx; then
    say "using pipx"
    pipx install "$SPEC"
elif have pip3 || have pip; then
    PIP="pip3"; have pip3 || PIP="pip"
    say "using $PIP (--user)"
    "$PIP" install --user "$SPEC"
else
    printf '\nerror: none of uv / pipx / pip found. Install Python 3.11+ and pip, or:\n' >&2
    printf '  https://docs.astral.sh/uv/  (recommended)\n' >&2
    exit 1
fi

printf '\n'
if have signetry; then
    say "installed: $(signetry --help >/dev/null 2>&1 && echo ok)"
    signetry --help 2>/dev/null | head -1 || true
    printf '\nSignetry is ready. Next:\n'
    printf '  signetry init            # scaffold .signetry/admission.yaml\n'
    printf '  signetry admit .         # govern a change\n'
    printf '  signetry completion zsh  # shell completion\n\n'
else
    printf '\nInstalled, but `signetry` is not on your PATH yet.\n' >&2
    printf 'Add your tool bin dir to PATH (uv: ~/.local/bin ; pipx: `pipx ensurepath`),\n' >&2
    printf 'then re-open your shell. If you used pip --user, add its user-base bin dir.\n' >&2
    exit 1
fi
