#!/usr/bin/env bash
# Point this clone at the tracked hooks, so a push is gated on this machine too.
set -euo pipefail
cd "$(dirname "$0")/.."

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

hooks_path="$(git config --get core.hooksPath || true)"
if [ "$hooks_path" != ".githooks" ]; then
  echo "failed to set core.hooksPath (got '${hooks_path}')" >&2
  exit 1
fi
if [ ! -x .githooks/pre-push ]; then
  echo "pre-push hook is not executable" >&2
  exit 1
fi
echo "hooks installed: core.hooksPath=.githooks (pre-push runs tools/gates.py)"
