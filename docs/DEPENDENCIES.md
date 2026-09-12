# Dependencies

`NativeDNS.Core` is Qt-independent.

`NativeDNS.GUI` uses Qt 6 Widgets.

## libcurl

Used for secure DNS transport support.

Windows:

- source build through CMake/FetchContent;
- Schannel TLS backend;
- static libcurl linkage;
- static nghttp2 linkage for HTTP/2;
- dynamic MSVC CRT compatibility is preserved.

Linux:

- system libcurl through pkg-config;
- distro TLS/CA integration is used.

TLS certificate validation remains enabled.

## nghttp2

The Windows build pins and statically links nghttp2 as libcurl's HTTP/2 backend. Linux uses the HTTP/2 support provided by the distribution's libcurl build.

## libsodium

Used for:

- DNSCrypt cryptographic primitives;
- secure random generation.

Windows:

- official MSVC x64 prebuilt package;
- the **dynamic v143** library is linked so its CRT matches Qt/NativeDNS;
- `libsodium.dll` is deployed beside affected executables.

Linux:

- system `libsodium` through pkg-config.

NativeDNS does not replace libsodium primitives with custom cryptography.

## WinDivert

Windows only.

Used for transparent DNS packet interception/reinjection.

Windows packages deploy the official x64 WinDivert DLL and signed driver.

WinDivert installs its kernel service on demand. During shutdown NativeDNS closes its interception handle first, then stops the driver only when the registered service points to the NativeDNS-bundled `WinDivert64.sys`. A service owned by another application is left untouched.

## Qt 6 Widgets

GUI only.

Qt must not become a dependency of:

- `NativeDNS.Core`;
- `NativeDNSCoreHost`.

Windows distributable builds deploy required Qt runtime/plugins through `windeployqt`.

Linux portable/AppImage builds use `linuxdeploy`/Qt plugin; distro packages may use normal package dependency resolution.

## nftables / polkit

Linux runtime integration:

- nftables provides transparent port-53 interception;
- `pkexec`/polkit elevates privileged CoreHost operations.

The GUI itself should not run as root.

## Packaging tools

Optional build-time tools:

- Inno Setup 6 for the Windows installer;
- linuxdeploy + linuxdeploy-plugin-qt for Linux portable/AppImage output;
- dpkg/CPack tooling for `.deb`.

See `THIRD_PARTY_NOTICES.md` for third-party licensing/notices.
