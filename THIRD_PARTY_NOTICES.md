# Third-party notices

DNSveil and MsmhAgnosticServer were inspected as read-only functional/technical references. Their GPL-3.0 source was not copied into NativeDNS by this migration. YogaDNS is used as a proprietary behavioral/visual reference; its branding/artwork/binaries are not distributed as NativeDNS assets.

## libcurl

NativeDNS uses libcurl for secure DNS transport support.

Windows builds use a pinned libcurl source archive and Schannel. Linux builds use the system libcurl discovered through pkg-config.

Copyright (c) Daniel Stenberg and contributors. The repository contains the libcurl license notice under `third_party/licenses/curl.txt`; distributable packages must retain the required notice.

## libsodium

NativeDNS uses libsodium for DNSCrypt primitives and secure random generation.

## nghttp2

The Windows build links nghttp2 to provide HTTP/2 support for DNS over HTTPS through libcurl. nghttp2 is distributed under the MIT license; its license text is included in `licenses/nghttp2.txt` in Windows packages.

Windows builds use a pinned official MSVC x64 archive. Linux builds use the system libsodium development/runtime package.

Copyright (c) Frank Denis. libsodium is distributed under the ISC license. The repository contains the notice under `third_party/licenses/libsodium.txt`.

## WinDivert

Windows transparent interception uses the official WinDivert 2.2.2-A x64 runtime under its LGPLv3-or-later/GPL licensing options.

Windows packages must include the upstream license and the unmodified required runtime/driver files. WinDivert is not used on Linux.

## Qt 6

`NativeDNS.GUI` uses Qt 6 Widgets. `NativeDNS.Core` and `NativeDNSCoreHost` do not depend on Qt.

Qt may be used under the applicable commercial or open-source license terms for the chosen Qt distribution. Dynamic Qt runtime libraries/plugins are intended to be bundled with Windows portable/installer packages and Linux portable/AppImage builds; distro packages may use system Qt dependencies.

Before public binary distribution, the packaging process must include all license notices and other compliance material required by the exact Qt modules/version/license used. Static Qt linking must not be enabled without a separate licensing review.

## linuxdeploy / linuxdeploy-plugin-qt

These are optional Linux packaging tools used to construct AppDir/AppImage/portable bundles. They are build-time tools and are not part of NativeDNS Core.

## System components

Windows SDK/Schannel/Task Scheduler and Linux POSIX/nftables/polkit components are provided under their respective platform terms.
