#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="${1:-release}"
NO_BUILD="${2:-}"
if [[ "$NO_BUILD" != "--no-build" ]]; then "$ROOT/scripts/linux/build-linux.sh" "$CONFIG" standalone; fi
BUILD="$ROOT/build/linux/$CONFIG"
PACKAGES="$ROOT/out/packages"
mkdir -p "$PACKAGES"
rm -f "$BUILD"/*.deb
(
  cd "$BUILD"
  cpack -G DEB
)
found=0
for file in "$BUILD"/*.deb; do
  [[ -e "$file" ]] || continue
  cp -f "$file" "$PACKAGES/"
  echo "DEB ready: $PACKAGES/$(basename "$file")"
  found=1
done
[[ $found -eq 1 ]] || { echo "ERROR: CPack did not produce a .deb package" >&2; exit 8; }
