#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${1:-release}"
NO_BUILD="${2:-}"

VERSION_FILE="$ROOT/VERSION"
[[ -f "$VERSION_FILE" ]] || { echo "ERROR: VERSION file is missing: $VERSION_FILE" >&2; exit 2; }
VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: invalid NativeDNS version in VERSION: '$VERSION'" >&2; exit 2; }

if [[ "$NO_BUILD" != "--no-build" ]]; then
  "$ROOT/scripts/linux/build-linux.sh" "$CONFIG" standalone
fi

APPDIR="$("$ROOT/scripts/linux/_linuxdeploy.sh" "$CONFIG" | tail -n1)"
SUFFIX=""
[[ "$CONFIG" == debug ]] && SUFFIX="-debug"
OUT="$ROOT/out/packages/NativeDNS-${VERSION}-linux-x64${SUFFIX}-portable.tar.gz"

rm -f "$OUT"
tar -C "$(dirname "$APPDIR")" -czf "$OUT" "$(basename "$APPDIR")"
echo "Portable Linux bundle ready: $OUT"
