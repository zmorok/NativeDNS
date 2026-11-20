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
| 11 | Reload config (empty payload or expected config ID) |
| 12 | Interception diagnostics (empty payload, read-only) |
| 13 | Active interception test (empty payload, bounded UDP/IPv4 probe) |
| 14 | Runtime logging profile (`Normal` or `Debug`) |
| 15 | Flush file logging (empty payload, ordered writer barrier) |

The GUI polls status/logs through IPC instead of owning DNS routing lifetime directly.

After writing a new configuration or changing servers/rules, the GUI sends `Reload config`.
CoreHost validates and prepares the saved XML before atomically replacing the routing snapshot.
WinDivert, nftables, and DNS listeners remain active. Queries already in progress finish with
their original snapshot; later queries use the new one. If validation or endpoint preparation
fails, CoreHost retains the current routing snapshot. `Restart` (ID 9) remains available to
fully stop and start CoreHost for recovery.

An optional Reload config payload is the 64 lowercase hexadecimal characters of
the SHA-256 of the canonical serialized configuration. CoreHost compares it with
the saved configuration before applying changes and returns
`RELOADED config_id=<id>` on success. A mismatch returns `CONFIG_MISMATCH` without
changing routing. Empty payloads retain the legacy `RELOADED` response. The GUI
uses and verifies the ID so an unrelated CoreHost configuration cannot silently
be reported as the imported one. GUI and CoreHost must be updated together;
older CoreHost versions reject the nonempty payload.

Log rows are UTF-8 tab-separated values: sequence, level, Unix timestamp in milliseconds, code, and message. The GUI formats that timestamp in local time.

Appending `\tstructured` to a logs request (`after_sequence<TAB>wait_ms<TAB>level<TAB>structured`)
opts into four additional fields: query address, DNS record type, rule name, and rule action
(`process`, `block`, or `bypass`). DNS routing events (including Windows UDP fast-path events) carry this context; other events leave
those fields empty. Route messages report the actual answering `server_id` (plus `rule_server_id` when a fallback server answered), `rcode`, `rcode_name`, `source` (`upstream`, `cache`, `coalesced`, or `local_block`), `answer_count`, and SOA authority metadata. Fields cannot contain tabs or line breaks. Requests without this suffix
retain the five-field format. The GUI falls back to the older format when an older CoreHost
rejects the suffix.


## Lifecycle

CoreHost owns the long-running Router/interception state.

A process-instance lock prevents multiple CoreHost instances from opening competing interception/IPC resources.

Windows IPC reserves a listening pipe in addition to its 16 worker connections.
Workers reuse a fixed thread pool and each pipe uses 16 KiB kernel buffers while
retaining the 1 MiB protocol payload limit. Request reads, response writes and
waiting for the client to close after a response each have a three-second deadline.
The server then disconnects the instance and releases its resources even if a
client retains its handle. A client must read its response and close the connection;
each connection carries one request. When all workers are busy,
the listener waits for capacity without repeatedly accepting and dropping clients;
this wait is interruptible during shutdown.
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
If graceful shutdown fails, Exit falls back to OS process termination. The GUI
checks the full CoreHost executable path and a process birth token, then uses a
verified Windows process handle to prevent PID-reuse mistakes.
An elevated `NativeDNSCoreHost --force-shutdown <pid> <birth-token>` helper is used
when the GUI lacks permission. The helper accepts only its own executable path.
The GUI exits only after process termination and release of the instance lock
have been confirmed; cancellation of elevation or a failed termination leaves
the GUI visible with an error.
Shutdown runs on a dedicated GUI worker, independently of the shared DNS-test
thread pool. Once CoreHost termination is confirmed, a separate Windows deadline
also exits the GUI after 10 seconds if its event loop or Qt cleanup is stuck.

GUI status and log polls allow 1.5 seconds per request; the independent diagnostic
Ping allows one second. Each poll type has at most one outstanding request.
For a running process, at least three consecutive failed status polls spanning
ten seconds outside the startup grace period show an error window. A successful
status immediately restores the display; notifications are rearmed only after
30 seconds of continuously healthy RUNNING responses to avoid repeated windows
during a flapping connection. An exited process still follows the restart policy.
The window includes IPC errors, the independent shutdown channel probe, process
identity, last successful status and OS information.
`Terminate application` forces CoreHost shutdown and then exits the GUI; `Close`
dismisses only the error window. Windows client timeout errors include the transfer stage,
elapsed time and request deadline to distinguish connection pressure from a
missing or partial response.
CoreHost error status is also reported in this window.
On Windows, a shutdown request starts an independent 10-second cleanup deadline;
if cleanup hangs, CoreHost exits with code 12 and Windows releases its interception
handles. Linux has no emergency OS termination fallback: killing the proxy before
validated nftables cleanup can leave DNS redirected to a dead listener. Linux
continues using the independent graceful shutdown endpoint and reports an explicit
unsupported error if forced termination is needed.

### Runtime capture profile on reload

The `reload_config` payload accepts `SHA256<TAB>diagnostics=0` or
`SHA256<TAB>diagnostics=1`. The SHA-256 identifies the effective configuration,
including the requested logging override. The host validates the candidate and
fingerprint before changing its runtime profile. A normal GUI can therefore
restore saved logging levels when reusing a host, and a Debug GUI forces Debug
file/display levels without rewriting the XML. Empty and SHA-256-only legacy
payloads retain the host's current capture profile.

## Interception and logging diagnostics

New operations retain framing version 1 and existing operation IDs. Older hosts
reject unsupported operations. Status retains its `RUNNING port=...` prefix and
adds `verification=UNVERIFIED|VERIFIED|DEGRADED|ERROR` for transparent providers.
`RUNNING` describes a started mechanism, not verified DNS routing. Linux reports
unverified interception and does not implement the Windows active probe.

Operation 12 returns UTF-8 `key=value` lines with `diagnostic_version=1`. Repeated
`finding` keys contain bounded read-only process/service/WFP findings. Counters
are independently sampled atomics, not a transactionally consistent packet trace.
WinDivert packet counters include TCP reflection and NativeDNS upstream packets;
routing counters cover completed UDP/TCP routing plus the UDP fast path. Probe
traffic is excluded from user rule evaluation. Counters persist through Stop;
Start clears probe verification. `last_capture_timestamp` is Unix milliseconds.

`saved_config_id` identifies the canonical document last loaded successfully.
`routing_config_id` includes all server/rule/network settings and metadata, while
excluding logging and server-test UI settings. `disk_saved_config_id`,
`disk_routing_config_id` and `disk_routing_matches_applied` compare the current
file with applied routing; a disk read error is explicit. `runtime_profile` and
`effective_logging_*` describe memory state, not XML changes.
`startup_runtime_profile` retains the launch profile after later IPC changes. To validate routing
independently of logging, Reload accepts
`routing=<64 lowercase hex>[<TAB>diagnostics=0|1]`. The reply remains
`RELOADED config_id=<requested-id>`. Legacy plain SHA-256 payloads still validate
the complete effective configuration, including the legacy Debug overlay.

`logging_state` is `ENABLED`, `DISABLED`, `DEGRADED` (lost queued events), or
`FAILED`. Diagnostics include the actual current file path after rotation,
writer activity, flushed event count, conservative lost-event count, last error
and last successful batch timestamp. Recovering the sink retains error/loss
history. A failed file sink does not stop routing or the memory journal.

Operation 13 sends one ordinary UDP/53 packet on a selected non-loopback IPv4
interface to `192.0.2.1`, with TTL 1 and a cryptographic nonce in
`<nonce>.interception.invalid`. The socket is deliberately outside the upstream
bypass registry. Matching requires exact DNS bytes, source/destination IPv4,
source/destination ports, interface and a two-second deadline. NativeDNS injects
NXDOMAIN without consulting rules/upstreams and checks delivery of that exact
reply to the connected client. A packet can leave the host if capture fails;
TEST-NET and TTL 1 minimize its effect. One probe runs at a time, at most once
per five seconds. No destination, command, path or timeout is accepted from IPC.

The result reports send, capture, parse, injection and delivery separately;
nonzero response status means failed verification. Only all five stages mark
UDP/IPv4 interception `VERIFIED`. This does not verify TCP, IPv6, user rules,
upstreams or future network conditions. No-traffic periods never become failures.
A failed probe identifies a stage and possible causes, not a proven competitor.
Repeat the probe before/after manually stopping another interceptor to compare
snapshots. NativeDNS never stops another product or modifies its filters.

Operation 14 changes only memory logging settings and leaves routing, XML and
interception handles intact. It cannot retroactively capture early startup
Debug events. `--diagnostics` is still required for full early Debug capture.
The same restricted per-user Named Pipe ACL and local-only transport apply to
all new operations; none accepts arbitrary privileged commands or output paths.
