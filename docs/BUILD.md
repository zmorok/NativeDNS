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

Do not switch NativeDNS or a linked dependency back to `/MT`/`/MTd` while using the official Qt MSVC binaries.

`windeployqt` is asked to deploy compiler runtime dependencies for standalone/portable output.

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

Configure with `-DNATIVEDNS_DIAGNOSTIC_BUILD=ON` to make GUI and CoreHost enable
diagnostic capture on every launch. The same profile can be requested explicitly
with `NativeDNS --diagnostics` or `NativeDNSCoreHost --diagnostics`.
Windows packages include `start-diagnostic-mode.cmd` for launching this profile
by double-click after exiting the current NativeDNS instance.
It enables Debug for screen/file capture and keeps file recording enabled across
GUI config imports and CoreHost reloads. The GUI initially shows only completed
Process results and related failures for configured upstream servers; Bypass,
Block, original-resolver sentinel routes, and packet/lifecycle traces remain in
the complete file log. Display filtering does not affect capture or DNS routing.

Already distributed Windows builds can enable Debug and the existing Process
display filter without downloading another application package:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./enable-diagnostics.ps1
```

Close NativeDNS through **Exit** before applying this preset, then start it
normally. The helper backs up the working XML, sets screen/file Debug and file
recording, and changes only the GUI's action/command/error display preferences.
DNS rules and network settings are retained. On older builds, importing a config
with different logging options requires applying the preset again. Their existing
Process filter can also show query-level debug traces and Process/0 routes; the
strict completed-custom-upstream view is provided by the new diagnostic profile.

Network/configuration inspection is available in the staged CLI:

```powershell
./tools/nativednsctl.exe diagnose "$env:LOCALAPPDATA/NativeDNS/NativeDNS.xml" chatgpt.com
```

On Linux use `nativednsctl diagnose <config-path> <hostname>`. This prints the
config ID/counts, selected effective rule and available network preflight findings.
It does not send a test DNS query or modify network settings. A zero exit code
means no conflict was found by the available checks, not that browser/VPN DNS
was verified. Use `servers test <config> <server-id>` or
`resolve <config> <hostname> <original-resolver-IP>` for actual DNS requests.

`resolve` also accepts `--type A`, `--type AAAA`, or `--type HTTPS` after the
optional original-resolver port. Windows staged packages include a read-only
service diagnostic script, defaulting to `gemini.google.com` and the GUI's config:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ./diagnose-service.ps1
```

Run it from the package directory while NativeDNS is running. For a double-click
launch on Windows, use `run-diagnostics.cmd` in the same directory. Optional script
parameters include `-HostName`, `-ConfigPath`, `-PackageDirectory`, and `-OutputPath`.
The script compares the Windows resolver with configured NativeDNS A/AAAA/HTTPS
queries, reads explicit Edge DNS mode/policies, records driver service paths and
the Event Log message-resource path, and probes TLS/HTTP using the returned IPs.
It writes a UTF-8 file under `logs/`. DNS settings, browser profiles and drivers
are unchanged. An absent explicit browser DNS preference does not prove Secure
DNS is off. The HTTPS probe uses normal certificate validation, sends no browser
cookies or account credentials, and does not verify account/region eligibility.
The script also works with earlier CLI builds that support only A queries;
AAAA/HTTPS DNS probes are then explicitly skipped while the A-answer TLS/HTTP
check still runs, so updating the script does not require replacing the package.

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

External secure-transport tests remain opt-in locally through `NATIVEDNS_LIVE_TESTS`; the scheduled CI workflow runs them nightly so provider/network failures are kept separate from deterministic pull-request checks.

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
Windows: NativeDNSCoreHost.exe
Linux:   NativeDNSCoreHost
```

The GUI should run unprivileged. Transparent interception privileges belong to CoreHost.
