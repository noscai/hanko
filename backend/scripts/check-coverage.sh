#!/usr/bin/env bash
#
# Per-file coverage floor check for the ClinicOS fork delta.
#
# This repo is a fork of teamhanko/hanko. Gating coverage on the whole tree would mean an
# upstream rebase reddens CI for code we did not write, so this script gates ONLY the files
# listed in coverage-floors.txt -- the files the fork owns.
#
# A file that is absent from the coverage profile counts as 0%. Packages with no test files
# contribute nothing to the profile, so "no tests at all" must fail a non-zero floor rather
# than silently pass.
#
# NOTE: this gates Go STATEMENT coverage (what `go test -coverprofile` produces). Go's toolchain
# has no branch-coverage mode, so — unlike the Jest/Vitest gates in clinic-os / clinic-os-admin,
# which also enforce a 90% branch floor — there is no branch dimension here by construction.
#
# Usage:
#   go test -coverprofile=coverage.out ./...
#   ./scripts/check-coverage.sh [coverage.out] [coverage-floors.txt]

set -euo pipefail

PROFILE="${1:-coverage.out}"
FLOORS="${2:-coverage-floors.txt}"
MODULE_PREFIX="github.com/teamhanko/hanko/backend/v2/"

if [[ ! -f "$PROFILE" ]]; then
  echo "❌ coverage profile not found: $PROFILE" >&2
  echo "   run: go test -coverprofile=$PROFILE ./..." >&2
  exit 1
fi

if [[ ! -f "$FLOORS" ]]; then
  echo "❌ floors file not found: $FLOORS" >&2
  exit 1
fi

# Per-file STATEMENT coverage from the profile (Go has no line/branch coverage; go tool cover
# reports "% of statements", which is what this computes).
#
# Profile rows are:  <file>:<startLine>.<startCol>,<endLine>.<endCol> <numStatements> <hitCount>
# A file's coverage is (covered statements / total statements) * 100.
coverage_for() {
  local file="$1"
  awk -v target="${MODULE_PREFIX}${file}" '
    NR == 1 { next }                      # skip "mode:" header
    {
      split($1, loc, ":")
      path = loc[1]
      if (path != target) next
      total += $2
      if ($3 > 0) covered += $2
    }
    END {
      if (total == 0) { print "0.0"; exit }
      printf "%.1f", (covered / total) * 100
    }
  ' "$PROFILE"
}

failed=0
checked=0

while read -r file floor; do
  [[ -z "${file:-}" || "$file" == \#* ]] && continue

  if [[ ! -f "$file" ]]; then
    echo "❌ $file is listed in $FLOORS but does not exist" >&2
    echo "   (was it renamed by an upstream rebase? update $FLOORS)" >&2
    failed=1
    continue
  fi

  actual=$(coverage_for "$file")
  checked=$((checked + 1))

  if awk -v a="$actual" -v f="$floor" 'BEGIN { exit !(a + 0 < f + 0) }'; then
    echo "❌ $file: ${actual}% is below its floor of ${floor}%"
    failed=1
  else
    echo "✅ $file: ${actual}% (floor ${floor}%)"
  fi
done < "$FLOORS"

echo
if [[ "$failed" -ne 0 ]]; then
  echo "Coverage floors not met. Floors may only ever be raised -- if you cannot reach a floor," >&2
  echo "the fix is a test, not a lower number." >&2
  exit 1
fi

echo "All $checked fork-delta file(s) meet their coverage floor."
