#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${1:-release}"
NO_BUILD="${2:-}"
if [[ "$NO_BUILD" != "--no-build" ]]; then "$ROOT/scripts/linux/build-linux.sh" "$CONFIG" standalone; fi
APPDIR="$($ROOT/scripts/linux/_linuxdeploy.sh "$CONFIG" | tail -n1)"
SUFFIX=""; [[ "$CONFIG" == debug ]] && SUFFIX="-debug"
OUT="$ROOT/out/packages/NativeDNS-0.3.0-linux-x64${SUFFIX}-portable.tar.gz"
rm -f "$OUT"
tar -C "$(dirname "$APPDIR")" -czf "$OUT" "$(basename "$APPDIR")"
echo "Portable Linux bundle ready: $OUT"
