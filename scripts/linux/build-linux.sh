#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

cd "$ROOT"
CONFIG="${1:-release}"
TARGET="${2:-standalone}"
TEST_MODE="${3:-tests}"

VERSION_FILE="$ROOT/VERSION"
[[ -f "$VERSION_FILE" ]] || { echo "ERROR: VERSION file is missing: $VERSION_FILE" >&2; exit 2; }
VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "ERROR: invalid NativeDNS version in VERSION: '$VERSION'" >&2; exit 2; }

echo "=== NativeDNS version $VERSION ==="

case "$TEST_MODE" in
  tests|no-tests) ;;
  *) echo "ERROR: test mode must be tests or no-tests" >&2; exit 2 ;;
esac

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
if [[ "$TEST_MODE" == tests ]]; then
  echo "=== Tests $CONFIG ==="
  ctest --preset "$PRESET"
else
  echo "=== Tests skipped ==="
fi

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

echo "=== NativeDNS Linux $CONFIG / $TARGET / $TEST_MODE completed ==="
