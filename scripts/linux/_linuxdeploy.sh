#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${1:-release}"
BUILD="$ROOT/build/linux/$CONFIG"
APPDIR="$ROOT/out/linux/$CONFIG/AppDir"

find_tool() {
  local env_name="$1" fallback="$2" value="${!env_name:-}"
  if [[ -n "$value" && -x "$value" ]]; then printf '%s\n' "$value"; return; fi
  if command -v "$fallback" >/dev/null 2>&1; then command -v "$fallback"; return; fi
  if [[ -x "$ROOT/tools/$fallback" ]]; then printf '%s\n' "$ROOT/tools/$fallback"; return; fi
  return 1
}

LINUXDEPLOY="$(find_tool LINUXDEPLOY linuxdeploy || true)"
QTPLUGIN="$(find_tool LINUXDEPLOY_PLUGIN_QT linuxdeploy-plugin-qt || true)"
if [[ -z "$LINUXDEPLOY" || -z "$QTPLUGIN" ]]; then
  cat >&2 <<MSG
ERROR: linuxdeploy and linuxdeploy-plugin-qt are required for portable/AppImage packaging.
Put them in PATH, in NativeDNS/tools/, or set:
  LINUXDEPLOY=/path/to/linuxdeploy
  LINUXDEPLOY_PLUGIN_QT=/path/to/linuxdeploy-plugin-qt
MSG
  exit 7
fi
export PATH="$(dirname "$QTPLUGIN"):$PATH"

rm -rf "$APPDIR"
DESTDIR="$APPDIR" cmake --install "$BUILD" --prefix /usr

"$LINUXDEPLOY" \
  --appdir "$APPDIR" \
  --executable "$APPDIR/usr/bin/NativeDNS" \
  --desktop-file "$APPDIR/usr/share/applications/io.nativedns.NativeDNS.desktop" \
  --icon-file "$APPDIR/usr/share/icons/hicolor/scalable/apps/nativedns.svg" \
  --plugin qt

printf '%s\n' "$APPDIR"
