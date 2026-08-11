#!/usr/bin/env bash
#
# Mantishack one-command installer.
#
#   Run from inside a clone:      ./install.sh
#   Or bootstrap from scratch:    curl -fsSL https://raw.githubusercontent.com/deonmenezes/mantishack/main/install.sh | bash
#
# The installer is idempotent: safe to re-run. It creates a local
# .venv, installs the pinned Python deps + Semgrep, installs Claude
# Code (if npm is present), drops a models.json config template, and
# symlinks the `mantishack` launcher onto your PATH. It finishes by
# running `mantishack-doctor` so you can see, in one screen, whether
# the install is actually ready.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config / flags
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/deonmenezes/mantishack.git"
BRANCH="${MANTISHACK_BRANCH:-main}"
TARGET_DIR=""
ASSUME_YES=0
MINIMAL=0
WITH_LLM=0
WITH_CODEQL=0
NO_PATH=0
BIN_DIR="${MANTISHACK_BIN_DIR:-$HOME/.local/bin}"

usage() {
    cat <<'EOF'
Mantishack installer

Usage: ./install.sh [options]

Options:
  -y, --yes         Non-interactive; accept all prompts (CI-friendly)
  --minimal         Python deps + Semgrep only (skip Claude Code + LLM SDKs)
  --with-llm        Also install the anthropic + openai Python SDKs
  --with-codeql     Best-effort install of the CodeQL CLI (large download)
  --no-path         Do not symlink the launcher onto PATH
  --dir <path>      Clone/target directory (default: ./mantishack in curl mode)
  --branch <name>   Branch to clone in curl mode (default: main)
  -h, --help        Show this help

Environment:
  MANTISHACK_BRANCH     Same as --branch
  MANTISHACK_BIN_DIR    PATH dir for the launcher symlink (default: ~/.local/bin)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes) ASSUME_YES=1 ;;
        --minimal) MINIMAL=1 ;;
        --with-llm) WITH_LLM=1 ;;
        --with-codeql) WITH_CODEQL=1 ;;
        --no-path) NO_PATH=1 ;;
        --dir) TARGET_DIR="${2:-}"; shift ;;
        --branch) BRANCH="${2:-}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option '$1' (try --help)" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Pretty output (degrades to plain text when not a TTY)
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'
    C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_RED=$'\033[31m'; C_CYN=$'\033[36m'
else
    C_RESET=""; C_DIM=""; C_BOLD=""; C_GRN=""; C_YLW=""; C_RED=""; C_CYN=""
fi
step() { printf '%s\n' "${C_CYN}${C_BOLD}==>${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()   { printf '    %s\n' "${C_GRN}ok${C_RESET}  $*"; }
warn() { printf '    %s\n' "${C_YLW}warn${C_RESET} $*"; }
die()  { printf '%s\n' "${C_RED}${C_BOLD}error${C_RESET} $*" >&2; exit 1; }

confirm() {
    # confirm "question" -> 0 for yes. Auto-yes with -y or non-interactive stdin.
    [ "$ASSUME_YES" = "1" ] && return 0
    [ -t 0 ] || return 0
    printf '    %s [Y/n] ' "$1"
    read -r reply || return 0
    case "$reply" in n|N|no|NO) return 1 ;; *) return 0 ;; esac
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# 0. Locate (or fetch) the repo
# ---------------------------------------------------------------------------
printf '\n%s\n\n' "${C_BOLD}Mantishack installer${C_RESET} ${C_DIM}stalk · wait · strike · hold${C_RESET}"

if [ -f "mantishack.py" ] && [ -d "core" ]; then
    ROOT="$(pwd)"
    step "Using existing checkout at ${ROOT}"
else
    step "No checkout in \$PWD - cloning Mantishack"
    have git || die "git is required to clone. Install git, or run this from inside a clone."
    DEST="${TARGET_DIR:-mantishack}"
    if [ -d "$DEST/.git" ]; then
        ok "Reusing existing clone at $DEST"
    else
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$DEST" \
            || die "clone failed (branch '$BRANCH')"
        ok "Cloned into $DEST"
    fi
    cd "$DEST"
    ROOT="$(pwd)"
    [ -f "mantishack.py" ] && [ -d "core" ] \
        || die "cloned tree does not look like Mantishack (branch '$BRANCH' may not carry the framework)"
fi

# ---------------------------------------------------------------------------
# 1. Prerequisites
# ---------------------------------------------------------------------------
step "Checking prerequisites"

have python3 || die "python3 not found. Install Python 3.10+ and re-run."
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
PY_OK="$(python3 -c 'import sys;print(1 if sys.version_info[:2]>=(3,10) else 0)')"
[ "$PY_OK" = "1" ] || die "Python 3.10+ required (found $PYV)."
ok "python3 $PYV"

if have git; then ok "git $(git --version | awk '{print $3}')"; else warn "git not found (fine for local use; needed for some scanners)"; fi

if have node && have npm; then
    ok "node $(node --version), npm $(npm --version)"
    HAVE_NPM=1
else
    warn "node/npm not found - Claude Code auto-install will be skipped"
    HAVE_NPM=0
fi

# ---------------------------------------------------------------------------
# 2. Python virtualenv + pinned deps + Semgrep
# ---------------------------------------------------------------------------
step "Setting up Python environment (.venv)"
if [ ! -d "$ROOT/.venv" ]; then
    python3 -m venv "$ROOT/.venv" || die "failed to create .venv"
    ok "created .venv"
else
    ok ".venv already present"
fi

VENV_PY="$ROOT/.venv/bin/python"
"$VENV_PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || warn "pip self-upgrade skipped"

step "Installing pinned dependencies"
# Defensive: a previous run may have co-installed semgrep here and
# downgraded click, which breaks typer. Remove it, then (re)install
# requirements so click is pinned by typer, not by semgrep.
"$VENV_PY" -m pip uninstall -y semgrep >/dev/null 2>&1 || true
"$VENV_PY" -m pip install --quiet -r "$ROOT/requirements.txt" || die "requirements install failed"
ok "core dependencies installed"

# Semgrep pins click~=8.1.8; typer (a core dep) needs click>=8.2.1.
# The two cannot share one venv, so semgrep gets its own environment
# and we expose only its binary. The framework talks to semgrep as a
# subprocess, so it never needs to share the Python env.
step "Installing Semgrep (isolated)"
TOOLS_VENV="$ROOT/.venv-tools"
if [ ! -d "$TOOLS_VENV" ]; then python3 -m venv "$TOOLS_VENV" >/dev/null 2>&1 || true; fi
if "$TOOLS_VENV/bin/python" -m pip install --quiet --upgrade pip >/dev/null 2>&1 \
   && "$TOOLS_VENV/bin/python" -m pip install --quiet semgrep; then
    ln -sf "$TOOLS_VENV/bin/semgrep" "$ROOT/.venv/bin/semgrep"
    ok "semgrep installed in .venv-tools (linked into .venv/bin, framework click untouched)"
else
    warn "semgrep install failed - static scanning will be unavailable until fixed"
fi

if [ "$WITH_LLM" = "1" ] || { [ "$MINIMAL" = "0" ] && confirm "Install anthropic + openai Python SDKs for the analysis layer?"; }; then
    step "Installing LLM provider SDKs"
    "$VENV_PY" -m pip install --quiet anthropic openai && ok "anthropic + openai installed" \
        || warn "LLM SDK install failed (optional - env keys still work per-provider)"
fi

# ---------------------------------------------------------------------------
# 3. Claude Code (orchestration layer)
# ---------------------------------------------------------------------------
if have claude; then
    ok "Claude Code already installed ($(claude --version 2>/dev/null | head -1))"
elif [ "$MINIMAL" = "1" ]; then
    warn "Claude Code not installed (--minimal). Interactive workflow needs it."
elif [ "$HAVE_NPM" = "1" ]; then
    if confirm "Install Claude Code globally via npm (@anthropic-ai/claude-code)?"; then
        step "Installing Claude Code"
        npm install -g @anthropic-ai/claude-code && ok "Claude Code installed" \
            || warn "Claude Code install failed - run: npm install -g @anthropic-ai/claude-code"
    else
        warn "Skipped Claude Code. Install later with: npm install -g @anthropic-ai/claude-code"
    fi
else
    warn "Claude Code missing and npm unavailable. Install Node.js, then: npm install -g @anthropic-ai/claude-code"
fi

# ---------------------------------------------------------------------------
# 4. CodeQL (optional, best-effort)
# ---------------------------------------------------------------------------
if [ "$WITH_CODEQL" = "1" ]; then
    step "CodeQL (best-effort)"
    if have codeql; then
        ok "codeql already on PATH"
    elif have gh; then
        gh extension install github/gh-codeql >/dev/null 2>&1 \
            && ok "installed via gh extension (use: gh codeql)" \
            || warn "gh codeql install failed - see docs/ for manual setup"
    else
        warn "codeql not installed. Install the CodeQL CLI from GitHub, or install gh and re-run with --with-codeql."
    fi
fi

# ---------------------------------------------------------------------------
# 5. Config template
# ---------------------------------------------------------------------------
step "Analysis-layer config"
CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/mantishack"
CFG_FILE="$CFG_DIR/models.json"
mkdir -p "$CFG_DIR"
if [ -f "$CFG_FILE" ]; then
    ok "config already present at $CFG_FILE"
else
    cat > "$CFG_FILE" <<'JSON'
{
  "_comment": "Analysis-layer LLMs. Or skip this file and export ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY.",
  "models": [
    { "provider": "anthropic", "model": "claude-opus-4-6", "api_key": "sk-ant-...", "role": "analysis" }
  ]
}
JSON
    ok "wrote config template to $CFG_FILE (edit in your API key)"
fi

# ---------------------------------------------------------------------------
# 6. PATH symlink for the launcher
# ---------------------------------------------------------------------------
if [ "$NO_PATH" = "0" ]; then
    step "Linking the launcher onto PATH"
    mkdir -p "$BIN_DIR"
    ln -sf "$ROOT/bin/mantishack" "$BIN_DIR/mantishack"
    ln -sf "$ROOT/bin/mantishack-doctor" "$BIN_DIR/mantishack-doctor"
    ok "linked $BIN_DIR/mantishack"
    case ":$PATH:" in
        *":$BIN_DIR:"*) ok "$BIN_DIR is already on PATH" ;;
        *) warn "add $BIN_DIR to PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
    esac
fi

# ---------------------------------------------------------------------------
# 7. Verify
# ---------------------------------------------------------------------------
printf '\n'
step "Running mantishack-doctor"
"$ROOT/bin/mantishack-doctor" || true

cat <<EOF

${C_BOLD}Next:${C_RESET}
  1. ${C_DIM}# activate the environment (only needed for CLI / CI use)${C_RESET}
     source "$ROOT/.venv/bin/activate"
  2. ${C_DIM}# launch the interactive agent${C_RESET}
     mantishack
  3. ${C_DIM}# or run a headless scan${C_RESET}
     python3 mantishack.py scan --repo /path/to/code

Re-check anytime with:  ${C_BOLD}mantishack-doctor${C_RESET}
EOF
