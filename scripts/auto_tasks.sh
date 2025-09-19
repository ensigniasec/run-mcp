#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR=$(git rev-parse --show-toplevel 2>/dev/null || printf ".")
cd "$ROOT_DIR"

echo "==> Staged files"
STAGED_FILES=$(git diff --cached --name-only)
if [ -z "$STAGED_FILES" ]; then
  echo "No files staged. Stage your changes, then re-run."
  exit 0
fi
printf "%s\n" "$STAGED_FILES" | sed 's/^/ - /'

echo "\n==> Diffs for staged files"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  echo "\n--- 8< --------- $f --------- 8< ---"
  git diff --cached -- "$f" | cat || true
done <<<"$STAGED_FILES"

echo "\n==> Next Steps: Update CHANGELOG.md and prepare conventional commit command (not executed)"
