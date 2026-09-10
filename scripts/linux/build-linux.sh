#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT"
CONFIG="${1:-release}"
TARGET="${2:-standalone}"
VERSION="0.3.0"

case "$CONFIG" in
  debug) PRESET=linux-debug; SUFFIX=-debug ;;
  release) PRESET=linux-release; SUFFIX= ;;
  *) echo "ERROR: configuration must be debug or release" >&2; exit 2 ;;
esac

BUILD="$ROOT/build/linux/$CONFIG"
STAGE="$ROOT/out/linux/$CONFIG/standalone"
PACKAGES="$ROOT/out/packages"
mkdir -p "$PACKAGES"

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command '$1' is missing" >&2; exit 3; }; }
need cmake
need ninja
need pkg-config

echo "=== Configure $PRESET ==="
cmake --preset "$PRESET"
echo "=== Build $CONFIG ==="
cmake --build --preset "$PRESET" --parallel
echo "=== Tests $CONFIG ==="
ctest --preset "$PRESET"

echo "=== Stage standalone/developer tree ==="
rm -rf "$STAGE"
cmake --install "$BUILD" --prefix "$STAGE"

echo "Standalone tree ready: $STAGE"

case "$TARGET" in
  standalone) ;;
  portable) "$ROOT/scripts/linux/package-portable.sh" "$CONFIG" --no-build ;;
  appimage) "$ROOT/scripts/linux/package-appimage.sh" "$CONFIG" --no-build ;;
  deb) "$ROOT/scripts/linux/package-deb.sh" "$CONFIG" --no-build ;;
  all)
    "$ROOT/scripts/linux/package-portable.sh" "$CONFIG" --no-build
    "$ROOT/scripts/linux/package-appimage.sh" "$CONFIG" --no-build
    "$ROOT/scripts/linux/package-deb.sh" "$CONFIG" --no-build
    ;;
  *) echo "ERROR: target must be standalone, portable, appimage, deb or all" >&2; exit 2 ;;
esac

echo "=== NativeDNS Linux $CONFIG / $TARGET completed ==="
