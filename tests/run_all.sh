#!/bin/bash
# Portable regression entry point. Windows platform acceptance is separate.
set -euo pipefail
TESTS=$(cd "$(dirname "$0")" && pwd)
python3 "$TESTS/run_v3.py"
python3 "$TESTS/run_ui.py"
