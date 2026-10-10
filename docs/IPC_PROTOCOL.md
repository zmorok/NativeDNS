# IPC protocol

Stop and Restart cancel in-flight upstream work, including bootstrap, DNSCrypt
certificate refresh and secure transfers. The command and log endpoints remain
separate. Configuration reload is transactional: a rejected configuration leaves
the validated routing snapshot and active listener in place. A restarted provider
uses a fresh cancellation token and routing cache.

NativeDNS uses a private local IPC protocol between GUI/tools and `NativeDNSCoreHost`.

There is no TCP/HTTP control endpoint.

## Endpoints

Three logical endpoints are used:

- command endpoint (including the existing lifecycle operations);
- log endpoint;
- independent shutdown endpoint (Ping and Shutdown only).

Separate endpoints prevent log reads or busy command handlers from blocking Exit.
Shutdown signals are published without taking backend/configuration locks. Both the
command and shutdown endpoints accept Shutdown for compatibility with existing tools.

### Windows

```text
\\.\pipe\NativeDNS.Core.v1
\\.\pipe\NativeDNS.Core.Logs.v1
\\.\pipe\NativeDNS.Core.Shutdown.v1
```

Windows uses local Named Pipes with restricted local-user access.

### Linux

```text
/tmp/nativedns-core-v1.sock
/tmp/nativedns-core-logs-v1.sock
/tmp/nativedns-core-shutdown-v1.sock
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
| 11 | Reload config (empty payload) |

The GUI polls status/logs through IPC instead of owning DNS routing lifetime directly.

After writing a new configuration or changing servers/rules, the GUI sends `Reload config`.
CoreHost validates and prepares the saved XML before atomically replacing the routing snapshot.
WinDivert, nftables, and DNS listeners remain active. Queries already in progress finish with
their original snapshot; later queries use the new one. If validation or endpoint preparation
fails, CoreHost retains the current routing snapshot. `Restart` (ID 9) remains available to
fully stop and start CoreHost for recovery.

Log rows are UTF-8 tab-separated values: sequence, level, Unix timestamp in milliseconds, code, and message. The GUI formats that timestamp in local time.

Appending `\tstructured` to a logs request (`after_sequence<TAB>wait_ms<TAB>level<TAB>structured`)
opts into four additional fields: query address, DNS record type, rule name, and rule action
(`process`, `block`, or `bypass`). DNS routing events carry this context; other events leave
those fields empty. Fields cannot contain tabs or line breaks. Requests without this suffix
retain the five-field format. The GUI falls back to the older format when an older CoreHost
rejects the suffix.


## Lifecycle

CoreHost owns the long-running Router/interception state.

A process-instance lock prevents multiple CoreHost instances from opening competing interception/IPC resources.

Windows IPC reserves a listening pipe in addition to its 16 worker connections.
Abandoned connections are isolated from the accept loop. CoreHost monitors its IPC
listeners and restores failed endpoints without stopping interception, recording
`IPC_ENDPOINT_FAILED` and `IPC_ENDPOINT_RECOVERED` diagnostics.

The GUI distinguishes an unavailable control channel from an exited process using
the CoreHost process-instance lock. It does not launch another CoreHost while that
lock is held. Automatic restart attempts are reset after 30 seconds of healthy
status responses, so a briefly responsive process cannot create an endless restart loop.

Explicit GUI exit cancels pending launches, sends Shutdown on the independent
endpoint (with a command-endpoint fallback), and waits for the process-instance
lock to be released. Disappearance of a pipe alone is not proof of termination.
If shutdown cannot be confirmed, the GUI stays visible and reports the failure.
On Windows, a shutdown request starts an independent 10-second cleanup deadline;
if cleanup hangs, CoreHost exits with code 12 and Windows releases its interception
handles. Linux has no forced-exit fallback because nftables rules require explicit
cleanup before the proxy exits.
