# Architecture

NativeDNS is a C++20 cross-platform DNS client/interceptor with a Qt 6 Widgets GUI and a Qt-independent Core.

```text
NativeDNS.GUI (Qt 6 Widgets)
          |
          | IPC / Core API
          v
NativeDNSCoreHost (non-Qt)
          |
          v
NativeDNS.Core
  |-- common DNS/rules/config/crypto/logging
  `-- platform
      |-- windows
      `-- linux
```

## Responsibilities

### NativeDNS.Core

Owns:

- configuration model and validation;
- YogaDNS import;
- hostname normalization and ordered rules;
- DNS packet parsing/serialization;
- DNS transports and DNS server testing;
- DNSCrypt/Anonymized DNSCrypt logic;
- routing;
- logging;
- CoreHost lifecycle/protocol;
- platform abstractions.

Qt is not allowed in Core.

### NativeDNS.GUI

Owns:

- main window;
- menu/toolbar/status bar;
- live log presentation;
- DNS server editor/test UI;
- Rules editor;
- tray integration;
- user-facing autostart control;
- persistent light/dark theme and English/Russian UI preferences;
- import/export workflow.

The GUI does not implement DNS protocol logic.

### NativeDNSCoreHost

`NativeDNSCoreHost` is a separate non-Qt process.

It owns long-lived DNS routing/interception work and IPC endpoints. Privileged interception is performed in CoreHost instead of elevating the GUI.

CoreHost uses a process-instance lock so only one CoreHost instance is active.

## Common Core

Common sources contain:

- Rule Engine;
- config parser/model;
- DNS codec/parser;
- secure DNS protocol logic;
- DNSCrypt;
- Router;
- Logger;
- CoreHost command/log protocol.

Platform-specific networking headers should not leak into shared business logic.

## Platform boundary

### Windows

`NativeDNS.Core/src/platform/windows/` owns:

- Winsock networking;
- WinDivert transparent interception;
- local proxy/TCP reflection support;
- Named Pipe IPC;
- Task Scheduler autostart;
- Windows filesystem/process/network primitives.

### Linux

`NativeDNS.Core/src/platform/linux/` owns:

- POSIX networking;
- local DNS proxy;
- nftables interception;
- Unix Domain Socket IPC;
- XDG autostart;
- Linux filesystem/process/network primitives.

Prefer CMake-selected platform source files over `_WIN32`/`__linux__` branches in shared business logic.

## Rule model

Rules are ordered. The first enabled matching rule wins.

The permanent Default rule is last.

Actions:

- `Process`: resolve through the selected NativeDNS server. Server ID `0` means original/system destination.
- `Bypass`: preserve/forward through the original resolver path owned by the interception backend.
- `Block`: return the configured block behavior (`0.0.0.0/::`, NXDOMAIN, REFUSED, or silent drop).

`Process/0` and `Bypass` remain distinct semantic actions.

## GUI lifecycle

The Qt application uses a single-instance guard.

Expected behavior:

- a second GUI launch activates the existing instance;
- `Hide to tray` is persisted as a boolean UI setting;
- CoreHost starts automatically with every GUI instance and remains active while the GUI is visible or in the tray;
- there are no interactive Start/Stop controls; only a full application exit shuts CoreHost down;
- close hides the window only when tray mode is enabled and a tray is available;
- otherwise close performs a full application exit and shuts down CoreHost;
- explicit Exit always performs full shutdown.

The tray icon is an application resource, not an empty platform-provided icon.

On Windows, autostart starts `NativeDNS.exe --background` without a visible window or console. The tray application then launches the registered elevated CoreHost on demand. This keeps interception privileged without elevating the Qt GUI, and avoids starting CoreHost without its tray owner.

The unprivileged GUI scheduled task retries an abnormal exit up to three times at one-minute intervals. A normal explicit Exit returns success and is not restarted. Unhandled C++ termination is recorded as `GUI_TERMINATED` in the standard diagnostic log before the process aborts.

## Configuration persistence

NativeDNS uses a versioned UTF-8 XML configuration.

Writes are validated before publishing. Atomic file publication is implemented behind platform-specific filesystem primitives.
The DNS Servers and Rules dialogs edit private working copies. `OK` validates and publishes the complete copy, while `Close` or the window close button discards all unapplied changes.

## Dependencies and ABI

Qt is dynamically linked only by the GUI.

Windows builds use the dynamic MSVC CRT to match official Qt builds.

`libsodium` is dynamically linked on Windows and provided by the system/package manager on Linux.

The optional advanced-module/plugin concept is not currently a public stable plugin ABI. Do not treat it as an implemented extension contract.
