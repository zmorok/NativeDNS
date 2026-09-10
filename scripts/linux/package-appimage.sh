#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${1:-release}"
NO_BUILD="${2:-}"
if [[ "$NO_BUILD" != "--no-build" ]]; then "$ROOT/scripts/linux/build-linux.sh" "$CONFIG" standalone; fi
APPDIR="$($ROOT/scripts/linux/_linuxdeploy.sh "$CONFIG" | tail -n1)"
LINUXDEPLOY="${LINUXDEPLOY:-$(command -v linuxdeploy 2>/dev/null || true)}"
[[ -x "$LINUXDEPLOY" ]] || LINUXDEPLOY="$ROOT/tools/linuxdeploy"
[[ -x "$LINUXDEPLOY" ]] || { echo "ERROR: linuxdeploy is missing" >&2; exit 7; }
export PATH="${LINUXDEPLOY_PLUGIN_QT:+$(dirname "$LINUXDEPLOY_PLUGIN_QT"):}$ROOT/tools:$PATH"
SUFFIX=""; [[ "$CONFIG" == debug ]] && SUFFIX="-debug"
OUT="$ROOT/out/packages/NativeDNS-0.3.0-linux-x64${SUFFIX}.AppImage"
rm -f "$OUT"
(
  cd "$ROOT/out/packages"
  OUTPUT="$OUT" "$LINUXDEPLOY" --appdir "$APPDIR" --output appimage
)
echo "AppImage ready: $OUT"
