#!/usr/bin/env bash
#
# onboard-device.sh — take a freshly-cloned soft-fig repo to a working,
# encrypted, FUSE-mounted garden on a new device.
#
# Posture (M-onboard locked pick #6 / the install-reach open-question lean):
#   * AUTOMATIC, no prompt: release build + install the four binaries to
#     ~/.local/bin, and check that fuse3 is present.
#   * PROMPTED, reversible, user-consented: enabling the systemd --user
#     unit and registering the MCP server in ~/.claude.json.
#
# This script does NOT scaffold the garden itself — run `softfig onboard`
# (interactive, needs a passphrase at a TTY) after this. See
# docs/onboard-laptop.md for the full runbook.

set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARIES=(softfig softfig-keeperd softfig-mcp softfig-tui softfig-growlightd)

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m!!!\033[0m %s\n' "$*"; }
ask()   { # ask "prompt" -> returns 0 for yes
  local reply
  read -r -p "$* [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# ---- 1. fuse3 check (automatic, non-fatal) -------------------------------
info "Checking for fuse3 (required for the daemon's plaintext FUSE view)…"
if command -v fusermount3 >/dev/null 2>&1 || [[ -e /dev/fuse ]]; then
  echo "    fuse3 present."
else
  warn "fuse3 not found. Install it (Arch: 'sudo pacman -S fuse3') before"
  warn "starting the daemon — the garden mounts via FUSE."
fi

# ---- 2. release build (automatic) ----------------------------------------
info "Building release binaries (cargo build --release)…"
( cd "$REPO_ROOT" && cargo build --release )

# ---- 3. install binaries (automatic) -------------------------------------
info "Installing binaries to ${BIN_DIR}…"
mkdir -p "$BIN_DIR"
for b in "${BINARIES[@]}"; do
  src="${REPO_ROOT}/target/release/${b}"
  if [[ ! -x "$src" ]]; then
    warn "missing built binary: ${src} — aborting."
    exit 1
  fi
  install -m 0755 "$src" "${BIN_DIR}/${b}"
  echo "    installed ${b}"
done

case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) warn "${BIN_DIR} is not on your PATH — add it to your shell profile." ;;
esac

# ---- 4. systemd --user unit (prompted) -----------------------------------
UNIT_SRC="${REPO_ROOT}/packaging/systemd/softfig-keeperd.service"
UNIT_DIR="${HOME}/.config/systemd/user"
if [[ -f "$UNIT_SRC" ]] && command -v systemctl >/dev/null 2>&1; then
  if ask "Install + enable the softfig-keeperd user unit now?"; then
    mkdir -p "$UNIT_DIR"
    install -m 0644 "$UNIT_SRC" "${UNIT_DIR}/softfig-keeperd.service"
    systemctl --user daemon-reload
    systemctl --user enable --now softfig-keeperd.service
    info "Unit enabled. Note: the daemon boots LOCKED — run 'softfig daemon unlock'."
  else
    info "Skipped unit install. Start the daemon manually with:"
    echo "    softfig daemon start --garden \"\$HOME/soft-fig_garden\""
  fi
else
  warn "systemd user unit source or systemctl not available — skipping unit step."
fi

# ---- 5. MCP registration (prompted) --------------------------------------
if command -v claude >/dev/null 2>&1; then
  if ask "Register softfig-mcp with Claude Code (writes ~/.claude.json)?"; then
    claude mcp add softfig-mcp "${BIN_DIR}/softfig-mcp"
    info "Registered softfig-mcp."
  else
    info "Skipped MCP registration. Register later with:"
    echo "    claude mcp add softfig-mcp \"${BIN_DIR}/softfig-mcp\""
  fi
else
  warn "'claude' CLI not found — skipping MCP registration."
  echo "    Register later with: claude mcp add softfig-mcp \"${BIN_DIR}/softfig-mcp\""
fi

cat <<EOF

Done. Next:
  1. Scaffold the garden (interactive — needs a passphrase at a TTY):
       softfig onboard
  2. If you did not enable the unit, start the daemon:
       softfig daemon start --garden "\$HOME/soft-fig_garden"
  3. Unlock the session once per boot:
       softfig daemon unlock
  4. (optional) Drive the garden from the terminal UI:
       softfig-tui

See docs/onboard-laptop.md for the full walkthrough.
EOF
