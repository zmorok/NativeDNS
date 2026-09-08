# Linux transparent DNS interception

## Current backend

The Linux backend uses an `inet nativedns` nftables table with an output-chain redirect for UDP/TCP destination port 53.

```text
application DNS :53
  -> nftables output redirect
  -> NativeDNS local proxy
  -> Rule Engine
     -> Process
     -> Block
     -> Bypass/original resolver
     -> Default
```

NativeDNS-created upstream sockets use an `SO_MARK` value where available. nftables excludes marked traffic before redirecting port 53, preventing Core from recursively intercepting its own Plain DNS upstream requests.

## System resolver selection

The backend attempts to discover a real resolver from common systemd-resolved/NetworkManager/resolv.conf locations.

Loopback stubs are skipped where possible to avoid redirect loops.

## Privileges

Transparent nftables setup requires elevated network-administration privileges.

The Qt GUI should run as the desktop user.

For transparent mode, the GUI launches the non-Qt `NativeDNSCoreHost` through `pkexec`.

Unix IPC ownership/permissions are adjusted so the original desktop user can communicate with the elevated CoreHost.

## Validation status

The backend exists in source and non-privileged Core/IPC/local-proxy behavior is testable without root.

Before Linux interception is considered production-complete, validate on a real Linux host:

- nftables setup and cleanup;
- UDP/TCP Process;
- Block modes;
- Bypass/original resolver;
- Default routing;
- IPv4 and IPv6;
- Core upstream loop avoidance;
- systemd-resolved/NetworkManager coexistence;
- repeated start/stop and crash cleanup;
- desktop tray/polkit integration.

Until those privileged host tests are complete, Linux transparent interception should be treated as `PARTIAL`.
