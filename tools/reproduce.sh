#!/usr/bin/env bash
# Reproduce the release assessment from a fresh checkout.
# Usage: tools/reproduce.sh   (exits nonzero on the first disagreement)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== version =="
python3 -m qvault --version

echo "== unit tests =="
python3 -m pytest qvault/tests -q

echo "== smoke (end-to-end surfaces) =="
python3 tools/smoke.py | tail -3

echo "== claims ledger =="
python3 tools/check_claims.py | tail -2

echo "== generated documents =="
python3 tools/gen_fingerprints.py --check

echo "== capability assessment =="
python3 -c "from qvault import pillars as P; a=P.audit(); print(a['statement'])"
