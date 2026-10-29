#!/usr/bin/env bash
# Demo: run the Necromancer over the haunted fixtures with local Gemma 3.
# Requires: ollama serve running, and a local gemma3 model (ollama pull gemma3).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 necromancer.py fixtures/haunted-legacy --model "${1:-gemma3}"
echo
echo "Report: necromancer-out/haunted-audit-report.md"
echo "Resurrected: necromancer-out/revived/"
