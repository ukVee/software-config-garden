#!/usr/bin/env bash
#
# laptop-sandbox-probe.sh — probe the laptop's systemd + bwrap + Landlock
# constraints for the softfig-runner system unit (remote-runner slice 001).
#
# Run ON THE LAPTOP (sillyguy76) as the owner. Needs sudo for the directive
# probes (systemd-run --uid under a throwaway system user). Purely
# diagnostic: it creates and removes one throwaway system user, nothing else.
# Paste the whole output into the slice 001 `## Outcome` probe table.

set -u

PROBE_USER="softfig-probe"
PROBE_UID=65400   # throwaway, outside the normal system-user range

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }

info "1. environment"
echo "kernel:      $(uname -r)"
echo "bwrap:       $(bwrap --version 2>&1)"
echo "lsm:         $(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)"
echo "userns (host): $(unshare -Ur true 2>/dev/null && echo OK || echo BLOCKED)"

info "2. creating throwaway system user ${PROBE_USER} (uid ${PROBE_UID})"
sudo useradd -r -u "$PROBE_UID" -M -s /usr/sbin/nologin "$PROBE_USER" 2>/dev/null \
  || info "user already exists, reusing"

cleanup() {
  info "cleanup: removing throwaway user ${PROBE_USER}"
  sudo userdel "$PROBE_USER" 2>/dev/null || true
}
trap cleanup EXIT

# probe "<directive>" — can bwrap still create its namespaces under it?
# The test is bwrap's full setup (unshare-all + bind + exec), not just
# `unshare -Ur`, because the directives can break the mount phase too.
probe() {
  local directive="$1"
  local name="${directive:-<none>}"
  if systemd-run --quiet --wait --pipe --collect \
       --uid="$PROBE_USER" --gid="$PROBE_USER" \
       ${directive:+-p "$directive"} \
       -- bwrap --unshare-all --die-with-parent --ro-bind / / -- /bin/true \
       >/dev/null 2>&1; then
    printf '  %-30s OK\n' "$name"
  else
    printf '  %-30s BROKEN\n' "$name"
  fi
}

info "3. directive probes (bwrap still works under each?)"
probe ""
for d in \
  "NoNewPrivileges=yes" \
  "ProtectSystem=strict" \
  "ProtectHome=yes" \
  "PrivateDevices=yes" \
  "PrivateTmp=yes" \
  "PrivateUsers=yes" \
  "ProtectKernelTunables=yes" \
  "ProtectKernelModules=yes" \
  "ProtectControlGroups=yes" \
  "MemoryMax=4G" \
  "MemorySwapMax=0" \
  "TasksMax=4096" \
  "RuntimeMaxSec=60m" \
  "CPUWeight=10" \
  "Nice=10" \
  "IOSchedulingClass=idle" \
  "KillMode=control-group"; do
  probe "$d"
done

info "done — paste this output into the slice 001 outcome table"
