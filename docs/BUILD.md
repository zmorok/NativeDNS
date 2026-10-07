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
- Windows SDK;
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
./scripts/make-update-manifest.ps1 -ReleaseRef HEAD -PreviousRef v0.4.2
```

Attach `out/release/update.json` alongside the release packages. Run the script
with PowerShell 7 on Windows or Linux. If `PreviousRef` is omitted, it finds the highest
earlier stable version tag reachable from the release commit. Non-merge commits
since that tag become bullet points; release-preparation commits are omitted.
`packaging/release-notes.json` supplies descriptions keyed by full commit hash.
Other commits use their subject in English, also used as the Russian fallback.

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
