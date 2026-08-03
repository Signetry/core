#!/usr/bin/env sh
#
# Umbra CLI installer.  Usage:
#
#   curl -fsSL https://raw.githubusercontent.com/bkd-dotcom/umbra-core/main/install.sh | sh
#
# Installs the `umbra` CLI (umbra-core) from its **source repo** using the best
# tool available, preferring an isolated install so it never clobbers your project
# environments. umbra-core is source-available (All Rights Reserved) and is NOT
# published to PyPI, so all installs pull from git by tag:
#
#   1. uv    (uv tool install ...)      — fastest, isolated
#   2. pipx  (pipx install ...)         — isolated
#   3. pip   (pip install --user ...)   — fallback
#
# Honest + fail-closed: it prints exactly which tool it used, verifies `umbra`
# is on PATH afterward, and exits non-zero if the install or the verification
# failed. It never pipes anything else into a shell.
set -eu

# optional: UMBRA_VERSION=0.5.3 sh install.sh  (defaults to the latest hardened tag)
VERSION="${UMBRA_VERSION:-0.5.4}"
SPEC="umbra-core @ git+https://github.com/bkd-dotcom/umbra-core@v${VERSION}"

say() { printf '  %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '\n== Umbra CLI installer ==\n'

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
if have umbra; then
    say "installed: $(umbra --help >/dev/null 2>&1 && echo ok)"
    umbra --help 2>/dev/null | head -1 || true
    printf '\nUmbra is ready. Next:\n'
    printf '  umbra init            # scaffold .umbra/admission.yaml\n'
    printf '  umbra admit .         # govern a change\n'
    printf '  umbra completion zsh  # shell completion\n\n'
else
    printf '\nInstalled, but `umbra` is not on your PATH yet.\n' >&2
    printf 'Add your tool bin dir to PATH (uv: ~/.local/bin ; pipx: `pipx ensurepath`),\n' >&2
    printf 'then re-open your shell. If you used pip --user, add its user-base bin dir.\n' >&2
    exit 1
fi
