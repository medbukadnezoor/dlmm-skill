#!/usr/bin/env bash
# Run the free Bubblemaps web map reader with a Python that has Camoufox 0.5.x.
# Usage, from the repository root: bash scripts/run-bubblemaps-map.sh <MINT> [extra bubblemaps_map.py flags]
# HOLDER_PYTHON: the browser Python (default: python3). BUBBLEMAPS_SCRIPT: the map script (default: this repository's copy).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${HOLDER_PYTHON:-python3}"
SCRIPT="${BUBBLEMAPS_SCRIPT:-$HERE/../skills/dlmm-scan/scripts/bubblemaps_map.py}"

command -v "$PY" >/dev/null 2>&1 || { echo "FAIL: browser Python not found: $PY (set HOLDER_PYTHON)"; echo "Fix: make a Python 3.10+ environment, install scripts/holder-tools-requirements.txt into it, run its python -m camoufox fetch, then set HOLDER_PYTHON to its python"; exit 2; }
[ -f "$SCRIPT" ] || { echo "FAIL: map script not found: $SCRIPT (set BUBBLEMAPS_SCRIPT)"; exit 2; }
"$PY" -c "import camoufox.pkgman as p; p.camoufox_path()" >/dev/null 2>&1 || { echo "FAIL: $PY cannot find the Camoufox browser (not installed, or a version/cache mismatch). Needs camoufox 0.5.x: see scripts/holder-tools-requirements.txt"; exit 2; }
exec "$PY" "$SCRIPT" "$@"
