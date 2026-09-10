# IPC protocol

NativeDNS uses a private local IPC protocol between GUI/tools and `NativeDNSCoreHost`.

There is no TCP/HTTP control endpoint.

## Endpoints

Two logical endpoints are used:

- command/lifecycle endpoint;
- log endpoint.

Separate endpoints prevent a long log read from blocking lifecycle commands.

### Windows

```text
\\.\pipe\NativeDNS.Core.v1
\\.\pipe\NativeDNS.Core.Logs.v1
```

Windows uses local Named Pipes with restricted local-user access.

### Linux

```text
/tmp/nativedns-core-v1.sock
/tmp/nativedns-core-logs-v1.sock
```

Linux uses Unix Domain Sockets.

When CoreHost is started through `pkexec`, ownership is adjusted for the originating desktop user where required.

## Framing

All integers are unsigned little-endian.

Request header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | Magic `NND1` |
| 4 | 2 | Protocol version (`1`) |
| 6 | 2 | Operation |
| 8 | 8 | Nonzero request ID |
| 16 | 4 | Payload byte count |

Payload data is UTF-8 and bounded.

Responses preserve magic/version/request ID, mark the response operation, and return a status plus UTF-8 payload.

## Operations

Current operations include:

| ID | Name |
|---:|---|
| 1 | Ping |
| 2 | Status |
| 3 | Start |
| 4 | Stop |
| 5 | Logs |
| 6 | Shutdown |
| 7 | Clear file log |
| 8 | Clear display |
| 9 | Restart |
| 10 | Configure file log (`enabled<TAB>level`) |

The GUI polls status/logs through IPC instead of owning DNS routing lifetime directly.

After writing a new configuration or changing servers/rules, the GUI sends `Restart`.
CoreHost then stops its current interception backend, reloads the configured XML file,
and starts a fresh Router/interception state in the same privileged process.

Log rows are UTF-8 tab-separated values: sequence, level, Unix timestamp in milliseconds, code, and message. The GUI formats that timestamp in local time.

## Lifecycle

CoreHost owns the long-running Router/interception state.

A process-instance lock prevents multiple CoreHost instances from opening competing interception/IPC resources.

Explicit GUI exit sends CoreHost shutdown and waits for termination according to the GUI lifecycle policy.
