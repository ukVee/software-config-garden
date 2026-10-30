#!/usr/bin/env bash
#
# probe-claude-config-dir.sh — re-verify that CLAUDE_CONFIG_DIR still
# relocates everything the `softfig claude-login` slot store depends on.
#
# Re-run after EVERY Claude Code upgrade, before trusting the slot layout
# (decision-claude-login-config-dir-slots; garden note
# projects/claude-login-switcher/notes/002-config-dir-probe-2-1-308.md).
#
# Posture:
#   * Never touches the real account. Every claude run gets a throwaway
#     CLAUDE_CONFIG_DIR under a fresh tempdir and a scrubbed environment
#     (env -i), and the only credential it ever sees is a FAKE token bundle.
#   * Checks that the mtimes of the real ~/.claude/.credentials.json and
#     ~/.claude.json are unchanged afterwards. A live interactive claude
#     session rewrites ~/.claude.json on its own, so a change there is
#     reported with that caveat rather than blamed on the probe.
#
# Exit 0 = every assertion held; exit 1 = at least one FAIL (stop and
# re-design before migrating or arming profile pools).

set -euo pipefail

CLAUDE_BIN="${CLAUDE_BIN:-$(command -v claude || true)}"
[[ -n "$CLAUDE_BIN" ]] || { echo "probe: no claude on PATH (set CLAUDE_BIN)" >&2; exit 1; }
REAL_BIN="$(readlink -f "$CLAUDE_BIN")"

pass=0
fail=0
ok()   { printf '\033[1;32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '\033[1;31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }
note() { printf '\033[1;33mNOTE\033[0m %s\n' "$*"; }

mtime() { stat -c %Y "$1" 2>/dev/null || echo absent; }

REAL_CREDS="${HOME}/.claude/.credentials.json"
REAL_JSON="${HOME}/.claude.json"
before_creds="$(mtime "$REAL_CREDS")"
before_json="$(mtime "$REAL_JSON")"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -m 0700 "$tmp/empty" "$tmp/file"

# A fake bundle of the real shape, far-future expiry so nothing tries to
# refresh it. The token strings are not secrets.
exp_ms=$(( ($(date +%s) + 31536000) * 1000 ))
printf '{"claudeAiOauth":{"accessToken":"sk-ant-oat01-probe-fake","refreshToken":"sk-ant-ort01-probe-fake","expiresAt":%s,"scopes":["user:inference","user:profile"],"subscriptionType":"pro","rateLimitTier":"default_claude_ai"}}' \
  "$exp_ms" > "$tmp/file/.credentials.json"
chmod 0600 "$tmp/file/.credentials.json"

# Run `claude auth status --json` against one config dir with a scrubbed
# environment: no session vars, no API key, nothing inherited from a live
# claude that could short-circuit auth.
status_json() {
  env -i PATH="$PATH" HOME="$HOME" TERM=dumb CLAUDE_CONFIG_DIR="$1" \
    timeout 30 "$CLAUDE_BIN" auth status --json 2>/dev/null || true
}
field() { # field <json> <key> -> raw value, or empty
  printf '%s' "$1" | sed -n "s/^ *\"$2\": *\"\{0,1\}\([^\",]*\)\"\{0,1\},\{0,1\}$/\1/p" | head -n1
}

echo "probe: claude $("$CLAUDE_BIN" --version 2>/dev/null | head -n1) at $REAL_BIN"

empty="$(status_json "$tmp/empty")"
file="$(status_json "$tmp/file")"

[[ "$(field "$empty" loggedIn)" == "false" ]] \
  && ok "empty config dir reads as logged out" \
  || bad "empty config dir did not read as logged out (credentials NOT relocated?)"
[[ "$(field "$file" loggedIn)" == "true" ]] \
  && ok "config dir holding .credentials.json reads as logged in" \
  || bad "config dir holding .credentials.json did not read as logged in"
[[ "$(field "$file" configDirectory)" == "$tmp/file" ]] \
  && ok "configDirectory echoes CLAUDE_CONFIG_DIR" \
  || bad "configDirectory is '$(field "$file" configDirectory)', expected $tmp/file"
[[ "$(field "$file" projectsDirectory)" == "$tmp/file/projects" ]] \
  && ok "projects/ relocates into the config dir" \
  || bad "projectsDirectory is '$(field "$file" projectsDirectory)', expected $tmp/file/projects"
[[ -f "$tmp/file/.claude.json" ]] \
  && ok ".claude.json is created inside the config dir" \
  || bad ".claude.json was not created inside the config dir"

# Static: the OAuth refresh lock lives in the config dir, and the strict
# credential store that refuses symlinks is still present.
if grep -a -q -F '.oauth_refresh.lock' "$REAL_BIN"; then
  ok "binary still names .oauth_refresh.lock (per-config-dir refresh lock)"
else
  bad "binary no longer names .oauth_refresh.lock — re-check where the refresh lock lives"
fi
if grep -a -q -F 'refused-symlink' "$REAL_BIN"; then
  note "binary carries the symlink-refusing credential store — never symlink .credentials.json"
fi

after_creds="$(mtime "$REAL_CREDS")"
after_json="$(mtime "$REAL_JSON")"
[[ "$before_creds" == "$after_creds" ]] \
  && ok "real ~/.claude/.credentials.json untouched (mtime $after_creds)" \
  || bad "real ~/.claude/.credentials.json mtime changed ($before_creds -> $after_creds)"
if [[ "$before_json" == "$after_json" ]]; then
  ok "real ~/.claude.json untouched (mtime $after_json)"
else
  note "real ~/.claude.json mtime changed ($before_json -> $after_json); a live interactive claude rewrites it — re-run with no claude open to rule the probe out"
fi

echo "probe: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
