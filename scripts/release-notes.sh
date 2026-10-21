#!/usr/bin/env bash
# release-notes.sh VERSION [CHANGELOG] — print the CHANGELOG.md section for
# VERSION (its `## [VERSION]` heading and body) on stdout, for the release body.
#
# Fails instead of publishing blank or stale notes (report 080):
#   - no `## [VERSION]` section, or one with nothing under its heading;
#   - entries still listed under `## [Unreleased]` — at a tag they belong in
#     the tag's own section, so leaving them there ships the previous notes.
#
# The release workflow runs it in `gate` (before any build) and in `publish`.
set -euo pipefail

version=${1:?usage: release-notes.sh VERSION [CHANGELOG]}
changelog=${2:-CHANGELOG.md}

# One `## [name]` section, heading included. index()==1 is a literal prefix
# match — a version's dots must not act as regex wildcards.
section() {
  awk -v h="## [$1]" '
    index($0, h) == 1 { in_s = 1; print; next }
    /^## \[/ { if (in_s) exit }
    in_s { print }
  ' "$changelog"
}

notes=$(section "$version")
if [ -z "$notes" ]; then
  echo "release-notes: $changelog has no '## [$version]' section — move the [Unreleased] entries into it before tagging" >&2
  exit 1
fi
if ! printf '%s\n' "$notes" | tail -n +2 | grep -q '[^[:space:]]'; then
  echo "release-notes: '## [$version]' in $changelog is empty" >&2
  exit 1
fi
if section Unreleased | tail -n +2 | grep -Eq '^[[:space:]]*[-*] '; then
  echo "release-notes: $changelog still lists entries under [Unreleased] — move them into '## [$version]' before tagging" >&2
  exit 1
fi
printf '%s\n' "$notes"
