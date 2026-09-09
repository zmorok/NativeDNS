#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then exec sudo "$0" "$@"; fi
apt-get update
apt-get install -y \
  build-essential cmake ninja-build pkg-config \
  qt6-base-dev qt6-base-dev-tools \
  libcurl4-openssl-dev libsodium-dev \
  nftables policykit-1 \
  dpkg-dev fakeroot file patchelf
cat <<MSG
Core/Qt build dependencies installed.
For AppImage/portable bundles also provide linuxdeploy and linuxdeploy-plugin-qt
in PATH or NativeDNS/tools/.
MSG
