# NativeDNS

NativeDNS is a native C++ DNS client/interceptor for **Windows 10/11 x64** and **Linux x64**.

The project is split into two main components:

```text
NativeDNS.Core   DNS/rules/config/transports/IPC + platform backends
NativeDNS.GUI    Qt 6 Widgets desktop application
```

`NativeDNS.Core` does not depend on Qt.

## Features

Current Core functionality includes:

- ordered hostname rules with a permanent Default rule;
- `Process`, `Bypass` and `Block` actions;
- wildcard hostname patterns;
- NativeDNS XML configuration;
- YogaDNS XML import;
- Plain DNS over UDP/TCP;
- DNS over HTTPS;
- DNS over TLS;
- DNSCrypt;
- Anonymized DNSCrypt;
- real DNS server tests with RTT/error reporting;
- live and file logging;
- background `NativeDNSCoreHost`;
- IPC between GUI/tools and CoreHost.

Platform integration:

- **Windows:** Winsock, Named Pipes, WinDivert transparent interception, Task Scheduler autostart/elevation flow.
- **Linux:** POSIX sockets, Unix Domain Sockets, nftables redirect backend, XDG autostart, `pkexec` for privileged CoreHost startup.

The production desktop UI uses **Qt 6 Widgets** on both platforms.

## Application lifecycle

NativeDNS is designed around one GUI instance and one CoreHost instance.

- Starting `NativeDNS` again should activate the existing GUI instead of creating another full instance.
- `Hide to tray` is a persistent flag.
- With `Hide to tray` enabled, closing the window hides it while the tray icon and CoreHost remain available.
- With `Hide to tray` disabled, closing the window exits the GUI and shuts down CoreHost.
- Explicit `Exit` always shuts down both GUI and CoreHost.

The GUI itself should run as the normal desktop user. Privileged interception is handled by the separate non-Qt CoreHost process.

## Build

Detailed instructions are in [`docs/BUILD.md`](docs/BUILD.md).

### Windows

Typical Debug standalone build:

```bat
scripts\windows\build-debug.bat standalone
```

Typical Release portable build:

```bat
scripts\windows\build-release.bat portable
```

Set `QT_ROOT` when Qt is not already discoverable:

```bat
set QT_ROOT=C:\Qt\6.8.3\msvc2022_64
```

Windows output forms:

- standalone directory;
- portable ZIP;
- Inno Setup installer.

### Linux

Debian/Ubuntu dependency helper:

```bash
sudo ./scripts/linux/install-build-deps-debian.sh
```

Debug standalone:

```bash
./scripts/linux/build-debug.sh standalone
```

Release:

```bash
./scripts/linux/build-release.sh [standalone|portable|appimage|deb|all]
```

Linux output forms:

- standalone staged tree;
- portable `.tar.gz`;
- AppImage;
- `.deb`.

For Arch Linux, install equivalent packages with `pacman` (`base-devel`, `cmake`, `ninja`, `pkgconf`, `qt6-base`, `qt6-svg`, `curl`, `libsodium`, `nftables`, `polkit`, `patchelf`, `file`, `fakeroot`) and use the same Linux build scripts.

## Current validation status

The Windows Qt application has been compiled and launched during current development, including the standalone deployment path.

The Linux Core/platform implementation is present, but privileged transparent interception still requires validation on a real Linux desktop/system before it should be considered production-complete.

DoH3 and DoQ protocol values are preserved by the configuration model, but the current runtime does not silently downgrade them when the required QUIC transport is unavailable.

## Documentation

- [`Architecture`](docs/ARCHITECTURE.md)
- [`Build`](docs/BUILD.md)
- [`Configuration format`](docs/CONFIG_FORMAT.md)
- [`Dependencies`](docs/DEPENDENCIES.md)
- [`DNS transports`](docs/DNS_TRANSPORTS.md)
- [`IPC protocol`](docs/IPC_PROTOCOL.md)
- [`Linux interception`](docs/LINUX_INTERCEPTION.md)
- [`Platform matrix`](docs/PLATFORM_MATRIX.md)

## Runtime dependencies

NativeDNS does **not** use .NET, WPF, WinForms, Electron, WebView, Java, Python or Node.js as its runtime architecture.

Qt and other required native runtime libraries are deployed with distributable packages where appropriate.

See `THIRD_PARTY_NOTICES.md` for third-party components and notices.
