# NativeDNS

NativeDNS is a native C++ DNS client/interceptor for **Windows 10/11 x64** and **Linux x64**.

The project is split into two main components:

```text
NativeDNS.Core   DNS/rules/config/transports/IPC + platform backends
NativeDNS.GUI    Qt 6 Widgets desktop application
```

`NativeDNS.Core` does not depend on Qt.

## Download

The Windows release packages for [v0.4.5](https://github.com/zmorok/NativeDNS/releases/tag/v0.4.5):

- [Windows x64 installer](https://github.com/zmorok/NativeDNS/releases/download/v0.4.5/NativeDNS-0.4.5-windows-x64-setup.exe)
- [Windows x64 portable ZIP](https://github.com/zmorok/NativeDNS/releases/download/v0.4.5/NativeDNS-0.4.5-windows-x64-portable.zip)

Linux packages are not part of this release. Linux interception still needs validation on a real privileged host.

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
The GUI provides persistent light/dark themes and English/Russian interface languages under `View`,
located between `File` and `Configuration`. `View > Show...` toggles Filters and Selected record;
both are shown by default and their visibility is remembered. Hiding Filters temporarily disables
the text filter, and showing it restores the entered expression and applies it again.
The action and command filters in `Log` remain independent. Hiding Selected record clears its
details and selection; log records can still be selected and copied. Showing it starts collapsed
with empty details until a new record is selected.
The DNS Servers dialog can test one or all configured servers and displays each result and RTT.
The live log supports compound display filters and saved filter management with import/export.
`Log > View` selects a persistent log view: short line, a line with expandable details, or table.
In the line with details view, Enter toggles the selected record; opening another record collapses
the previous one. Enter on its details collapses them and returns selection to the record line.
All views retain the same filters and access to the original
record. `Log > Details` controls verbosity independently.
`Log > Show only action...` filters Process, Block and Bypass independently; multiple actions can
be selected. All (the default) clears these selections and includes events without a routing action.
The selection is remembered and combined with the text filter. New records follow the bottom
immediately when the log is already scrolled to the end; scrolling up pauses this following.
`Log > Show only commands...` selects Only (technical events such as initialization, reload and
network changes) or With (technical events alongside the selected DNS actions, the default).
Only temporarily disables action selection without losing it; With restores its effect.
Only and With are mutually exclusive. Clicking the active item clears its check mark and hides
technical events while keeping DNS records subject to the action filter.
The mode is remembered, including the state with neither item selected. The text filter and
verbosity level continue to apply in every mode.
`Help > Check for updates` displays the latest release version and scrollable release notes with commit links.
Release notes support categories, including packet interception and CoreHost changes separately
from other changes; descriptions and category headings follow the selected interface language.
`Help > Check update on start` enables a background update check once per GUI launch (on by default).
The preference is remembered. Startup checks show the update window only for a newer release;
an up-to-date version or a failed check stays silent. Manual checks still show results and errors.

## Application lifecycle

NativeDNS is designed around one GUI instance and one CoreHost instance.

- Starting `NativeDNS` again should activate the existing GUI instead of creating another full instance.
- `Hide to tray` is a persistent flag.
- With `Hide to tray` enabled, closing the window hides it while the tray icon and CoreHost remain available.
- With `Hide to tray` disabled, closing the window exits the GUI and shuts down CoreHost.
- Explicit `Exit` always shuts down both GUI and CoreHost.
- With autostart enabled on Windows, Task Scheduler starts the elevated CoreHost first and then launches `NativeDNS.exe --background` as the normal desktop user.
- Configuration changes reload CoreHost routing without stopping transparent DNS interception.
- The toolbar and tray provide a Restart action to reload CoreHost routing or start CoreHost when it is absent.
- If a secure upstream cannot be resolved while offline, the GUI shows the error in the live log and retries startup after network and DNS resolution return.

The GUI itself should run as the normal desktop user. Privileged interception is handled by the separate non-Qt CoreHost process.

## Build

Detailed instructions are in [`docs/BUILD.md`](docs/BUILD.md).

Common build commands:

```text
# Windows: Debug standalone build with tests
.\scripts\windows\build-debug.bat standalone tests

# Windows: Debug standalone build without tests
.\scripts\windows\build-debug.bat standalone no-tests

# Windows: Release standalone build with tests
.\scripts\windows\build-release.bat standalone tests

# Windows: Release portable ZIP with tests
.\scripts\windows\build-release.bat portable tests

# Windows: Release installer with tests
.\scripts\windows\build-release.bat installer tests

# Windows: Build all Release artifacts with tests
.\scripts\windows\build-release.bat all tests

# Windows: Build all Release artifacts without tests
.\scripts\windows\build-release.bat all no-tests


# Linux: Debug standalone build with tests
./scripts/linux/build-debug.sh standalone tests

# Linux: Debug standalone build without tests
./scripts/linux/build-debug.sh standalone no-tests

# Linux: Release standalone build with tests
./scripts/linux/build-release.sh standalone tests

# Linux: Release portable archive with tests
./scripts/linux/build-release.sh portable tests

# Linux: Release AppImage with tests
./scripts/linux/build-release.sh appimage tests

# Linux: Release DEB package with tests
./scripts/linux/build-release.sh deb tests

# Linux: Build all Release artifacts with tests
./scripts/linux/build-release.sh all tests

# Linux: Build all Release artifacts without tests
./scripts/linux/build-release.sh all no-tests
```

The final argument controls test execution:

- `tests` — build and run the configured test suite;
- `no-tests` — build and package without running tests.

Windows build targets:

- `standalone` — staged application directory;
- `portable` — portable ZIP archive;
- `installer` — Inno Setup installer;
- `all` — portable ZIP and installer.

Linux build targets:

- `standalone` — staged application directory;
- `portable` — portable `.tar.gz` archive;
- `appimage` — AppImage package;
- `deb` — Debian package;
- `all` — portable archive, AppImage and `.deb`.

Set `QT_ROOT` when Qt is not already discoverable.

PowerShell example:

```powershell
$env:QT_ROOT = "C:\Qt\6.8.3\msvc2022_64"
```

Debian/Ubuntu dependency helper:

```bash
sudo ./scripts/linux/install-build-deps-debian.sh
```

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
