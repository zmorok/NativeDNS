# Building NativeDNS

NativeDNS targets Windows 10/11 x64 and Linux x64.

## Common requirements

- CMake 3.25+
- C++20 compiler
- Qt 6.2+ for `NativeDNS.GUI`
- Qt Test for the GUI tests when `BUILD_TESTING` is enabled

## Windows

Current Windows presets use the Visual Studio generator and an MSVC x64 Qt kit.

Required:

- Visual Studio/MSVC with C++ x64 toolset;
- Windows SDK 10.0.26100.0 or newer (build headers; the runtime still targets Windows 10/11);
- Qt 6 MSVC x64;
- Inno Setup 6 only when building the installer.

If Qt is not discoverable, set:

```bat
set QT_ROOT=C:\Qt\6.8.3\msvc2022_64
```

### Presets

```text
windows-debug
windows-release
```

### Scripts

```bat
scripts\windows\build-debug.bat [standalone|portable|installer|all] [tests|no-tests]
scripts\windows\build-release.bat [standalone|portable|installer|all] [tests|no-tests]
```

Examples:

```bat
scripts\windows\build-debug.bat standalone
scripts\windows\build-release.bat portable
scripts\windows\build-release.bat installer
scripts\windows\build-release.bat portable no-tests
```

The script:

1. configures CMake;
2. builds;
3. runs CTest unless `no-tests` was selected;
4. installs to a staging directory;
5. runs `windeployqt`;
6. optionally creates portable/installer artifacts.

Outputs are written under `out/`.

### Release update information

The GUI's **Help > Check for updates** command downloads the `update.json`
asset from the latest stable GitHub release. It compares numeric version components
and displays English/Russian release notes with links to the contributing commits.
Only the notes scroll; the version labels and action buttons remain visible.
This command checks metadata and opens the release page; it does not install packages.

The release tag must be `v` followed by the version in `VERSION`.
Prepare the manifest after committing the release version and before publishing:

```powershell
./scripts/make-update-manifest.ps1 -ReleaseRef HEAD -PreviousRef v0.4.3
```

Attach `out/release/update.json` alongside the release packages. Run the script
with PowerShell 7 on Windows or Linux. If `PreviousRef` is omitted, it finds the highest
earlier stable version tag reachable from the release commit. Non-merge commits
since that tag become bullet points; release-preparation commits are omitted.
`packaging/release-notes.json` supplies descriptions keyed by full commit hash.
Other commits use their subject in English, also used as the Russian fallback.
Optional `categories` in that file is an ordered array of `{ "id": "...", "text":
{ "en": "...", "ru": "..." } }` objects. A commit description can name its `category`
by ID. The generator includes only categories used by the selected release and rejects
unknown IDs. In `update.json`, `whats_new` remains a flat array of commit/text entries,
with optional category IDs and an additional `categories` array. Schema version remains
1: older clients display the complete flat list; newer clients group entries under
localized headings in category order. Uncategorized entries remain visible after the groups.

For mutable releases without an existing manifest, the release workflow generates
and attaches it after publication. Until the upload completes, checks may report
that the manifest is missing. Immutable releases must include it before publication.

Manifest schema 1 contains `version` (`major.minor.patch`), `release_url`
(`https://github.com/zmorok/NativeDNS/releases/tag/v<version>`) and a `whats_new`
array. Each entry contains a full lowercase SHA-1 `commit` and a `text` object
with required `en` and optional `ru` strings. The client accepts at most 256
entries, 4096 characters per description and 512 KiB per manifest. A failed check
can show the last successful result, explicitly marked as cached.

### Windows runtime model

Official Qt MSVC builds use the dynamic MSVC CRT.

NativeDNS therefore uses:

```text
Debug   /MDd
Release /MD
```

The root `NativeDNS.exe` (and `Updater.exe`) use `/MT` or `/MTd` and link only Windows system libraries. All Qt/Core modules (`bin/NativeDNS.GUI.dll`, `bin/NativeDNS.CoreHost.dll`, `bin/NativeDNS.Cli.dll`, `bin/NativeDNS.Diagnostics.dll`) and their dependencies use the dynamic CRT shown above.

`packaging/deploy-windows-runtime.ps1` deploys Qt plugins to `bin/plugins` and copies Qt, libsodium, WinDivert and MSVC runtime files to `bin` / `bin/drivers`. The package audit checks that imported Qt, libsodium and MSVC runtime DLLs are bundled in `bin` and that the root executables have no external runtime imports.

## Linux

Required:

- GCC or Clang;
- Ninja;
- pkg-config;
- Qt 6 Widgets development package;
- libcurl development package;
- libsodium development package;
- nftables;
- polkit/pkexec.

### Debian / Ubuntu

```bash
sudo ./scripts/linux/install-build-deps-debian.sh
```

### Arch Linux

Install equivalent packages:

```bash
sudo pacman -S --needed \
  base-devel \
  cmake \
  ninja \
  pkgconf \
  qt6-base \
  qt6-svg \
  curl \
  libsodium \
  nftables \
  polkit \
  patchelf \
  file \
  fakeroot
```

### Presets

```text
linux-debug
linux-release
linux-core-debug
linux-core-release
```

Core-only example:

```bash
cmake --preset linux-core-debug
cmake --build --preset linux-core-debug
ctest --preset linux-core-debug
```

### Scripts

```bash
./scripts/linux/build-debug.sh [standalone|portable|appimage|deb|all] [tests|no-tests]
./scripts/linux/build-release.sh [standalone|portable|appimage|deb|all] [tests|no-tests]
```

Without an output argument, the Debug and Release scripts build, test and stage
the `standalone` tree. Use `all` (or `build-all.sh`) only when the optional
portable, AppImage and Debian packages are required. Run build scripts as the
desktop user; runtime elevation is handled separately by CoreHost.
Tests run by default; pass `no-tests` as the second wrapper argument for a faster
packaging-only iteration.

Output forms:

- `standalone`: installed runtime tree;
- `portable`: `.tar.gz`;
- `appimage`: AppImage through `linuxdeploy`;
- `deb`: Debian package through CPack;
- `all`: all available forms.

For portable/AppImage generation, provide `linuxdeploy` and `linuxdeploy-plugin-qt` through PATH, `tools/`, or the corresponding environment variables expected by the packaging scripts.

## Network diagnostics

Windows packages have two public entry points:

- `NativeDNS.exe` starts the normal GUI.
- `NativeDNS.Debug.exe` starts the same GUI with forced Debug screen/file capture and file recording enabled.

They share the same GUI lock, activation endpoint and machine-wide CoreHost lock.
A second launch activates the current instance; a request for a different mode
shows a message asking the user to exit first. Exit through the application menu
before switching modes. Debug logging is a runtime profile: the saved XML logging
settings and normal GUI log filters are retained for the next normal launch.
Debug inherits the saved visibility of Filters and Selected record; changes to
these controls during a diagnostic session stay within that session.
Config imports and reloads retain the active runtime profile.

The diagnostic GUI initially shows only completed Process results and related
failures for configured upstream servers. Bypass, Block, original-resolver routes
and packet/lifecycle traces remain in the full file log. Display filtering does
not affect capture or routing.

Use **Diagnostics > Collect diagnostic report...** and enter the affected domain to
collect a report and the latest available logs. Collection also works without
the GUI or CoreHost running:

```powershell
./NativeDNS.Debug.exe --collect --host example.com
./NativeDNS.Debug.exe --collect --host example.com --offline --quiet
```

Optional arguments are `--config FILE`, `--host DOMAIN`, `--offline` and `--quiet`.
The default configuration is `%LOCALAPPDATA%/NativeDNS/NativeDNS.xml`; the default
domain comes from its test target, falling back to `example.com` when unavailable.
Collection writes a UTF-8 `service-*.log` and a `diagnostics-*.zip` under `logs/`.
The archive includes the report and up to three recent `NativeDNS-*.log` files,
with a total input size limit of 16 MiB. Oversized existing logs are skipped and
reported. The XML and browser profile contents are not copied to the archive.

The native collector reads CoreHost state, configuration fingerprints/effective
rules, interface DNS, hosts conflicts, WinDivert services/processes/Event Log
resource paths and explicit Edge Secure DNS preferences. It compares OS resolution
with NativeDNS A/AAAA/HTTPS results, then uses up to two returned IPs for HTTPS HEAD
probes with certificate verification. It sends no browser cookies or account
credentials and does not establish service account or region eligibility.
`--offline` skips DNS/HTTPS probes. Neither collection nor offline inspection
changes DNS settings, hosts, autostart, drivers or browser profiles. Missing
explicit Edge preferences do not prove Secure DNS is disabled.

The collector uses the packaged CLI and libcurl, with bounded subprocess/probe
timeouts. PowerShell and external curl.exe are not required at runtime. Internal
executables in `app/bin` are started through the root bootstrap so that libraries
in `app/lib` are available even before their main function and after elevation.
For manual CLI inspection:

```powershell
./app/bin/nativednsctl.exe diagnose "$env:LOCALAPPDATA/NativeDNS/NativeDNS.xml" example.com
./app/bin/nativednsctl.exe resolve "$env:LOCALAPPDATA/NativeDNS/NativeDNS.xml" example.com 1.1.1.1 --type AAAA
```

On Linux use `NativeDNS --diagnostics`, `NativeDNSCoreHost --diagnostics` and
`nativednsctl diagnose <config-path> <hostname>`. The native report collector and
Windows root launchers are Windows-specific. The CMake option
`NATIVEDNS_DIAGNOSTIC_BUILD=ON` forces the profile by default for development;
regular distributable packages leave it OFF and include the separate Debug entry.

## Sanitizers and fuzzing

The Linux quality workflow runs the Core test suite under Address/UndefinedBehavior Sanitizer and ThreadSanitizer. Clang libFuzzer targets for DNS wire packets, DNSCrypt framing, configuration XML, and IPC headers are opt-in:

```bash
cmake -S . -B build/fuzz -G Ninja \
  -DNATIVEDNS_BUILD_GUI=OFF \
  -DNATIVEDNS_BUILD_TOOLS=OFF \
  -DNATIVEDNS_FUZZING=ON \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++
cmake --build build/fuzz --target fuzz_dns fuzz_dnscrypt fuzz_config fuzz_ipc
```

External secure-transport tests are opt-in through `NATIVEDNS_LIVE_TESTS` and run manually with `ctest -L live --output-on-failure` in the build directory.

Linux certificate validation uses the loopback-only `secure_local_tls` test when
Python 3.8+ and the OpenSSL command-line tool are available. It creates temporary
CA/server certificates and checks a real successful DoH answer, expired and
wrong-host certificates, an incorrect pin, and a connection reset. Private CA
trust is injected only into the `secure_tests` executable through linker wrappers;
production binaries and system certificate stores are unchanged. The test uses
ephemeral ports and requires no external DNS or HTTPS service. Python/OpenSSL
are test tools, not application runtime dependencies.

With these tools installed, run `ctest -L tls --output-on-failure` before external
DNS checks. External `secure_live` checks real DoH/DoT resolution and explicit
bootstrap, while `dnscrypt_live` checks real DNSCrypt. Network/provider failures
in those checks remain failures; a reset is never accepted as certificate validation.

On Windows, `windivert_live_tests` is a separate opt-in executable built with
the test targets. Close NativeDNS and other active DNS interceptors first, then
run it from an administrator terminal:

```powershell
& ./build/windows/windows-debug/tests/Debug/windivert_live_tests.exe "$PWD/build/windows/windivert-live-result.txt"
```

It exercises real UDP/TCP interception, Block, Process, Process/0, Bypass,
interface binding when an active IPv4 gateway exists, TTL, TCP/53 reset,
configuration reload and CoreHost Stop/Start/Restart cleanup. It uses the current
network and a public resolver at `1.1.1.1`. Other names use a Bypass Default rule.
The result file contains checks and diagnostic logs; the temporary test config
is written alongside it. This test is not registered with ordinary CTest runs.
It does not replace Windows 10, IPv6 connectivity, VPN, captive portal or physical
network transition testing.

Local UDP/TCP churn, latency percentiles, throughput, and process resource growth are measured by the opt-in stress runner:

```bash
cmake -S . -B build/stress -G Ninja -DNATIVEDNS_BUILD_GUI=OFF -DNATIVEDNS_STRESS_TESTS=ON
cmake --build build/stress --target nativedns_stress
./build/stress/tests/nativedns_stress --seconds 3600 --clients 64
```

Use `--debug-logging` for the logging-overhead variant. Longer soak runs use the same executable and can extend `--seconds` to several hours or a day; the result includes queries/sec, p50/p95/p99 latency, failures, memory, handle/file-descriptor, and thread counts.

## Runtime layout

Main desktop executable:

```text
Windows: NativeDNS.exe
Linux:   NativeDNS
```

Background helper:

```text
Windows: app/bin/NativeDNS.CoreHost.exe
Linux:   NativeDNSCoreHost
```

The GUI should run unprivileged. Transparent interception privileges belong to CoreHost.

## Interception CLI and target-machine validation

The packaged `app/bin/nativednsctl.exe` is a static console bootstrap. It sets the
private DLL search directory before launching `NativeDNS.Cli.exe`, so no external
Qt installation or PATH modification is needed. Prefer this console entry point
in PowerShell: it waits, prints stdout/stderr and returns the worker exit code.
The GUI-subsystem `NativeDNS.exe --cli ...` also attaches to an available parent
console when needed, but PowerShell may return its prompt before a GUI program
finishes. For redirected capture, pipe it or use the console entry point.

```powershell
& ./app/bin/nativednsctl.exe core status
& ./app/bin/nativednsctl.exe core interception-status
& ./app/bin/nativednsctl.exe core interception-test
& ./app/bin/nativednsctl.exe core profile Debug
& ./app/bin/nativednsctl.exe core flush-file
& ./app/bin/nativednsctl.exe core profile Normal
```

The interception-status command is read-only. The test sends the bounded reserved
UDP/IPv4 probe described in IPC_PROTOCOL.md and returns nonzero unless capture,
synthetic injection and delivery all succeed. It requires an already running
transparent Windows CoreHost. It does not need a new UAC prompt. Profile switching
through IPC does not restart interception; startup Debug events cannot be recovered
when Debug is enabled later. Installed task path/config mismatches are rejected;
a missing or invalid task uses the existing explicit elevation flow.

Before running `windivert_live_tests`, close NativeDNS and manually stop competing
DNS interception through each product's own UI, then use an administrator terminal.
The test now includes active self-test and counter/verification assertions. Its
controlled configuration disables Windows DNS preparation/cache flushing, so it
does not modify resolver settings. It still affects DNS while its test filter is
open and uses the external network for Process/Bypass checks. The result is not a
substitute for an actual target-machine run. Compare before/after diagnostics for
YogaDNS only with the operator's approval; do not change its priorities or services
automatically. Real UAC consent/cancellation, Task Scheduler startup, multiple
WinDivert handles/impostor interactions, IPv6, Windows 10 and Linux privileged
routing require their respective live environments.
