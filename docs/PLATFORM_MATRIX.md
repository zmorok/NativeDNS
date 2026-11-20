# Platform matrix

Status words describe current implementation maturity, not a release guarantee.

| Capability | Windows x64 | Linux x64 | Notes |
|---|---|---|---|
| Shared Core | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Common rules/config/DNS/crypto/logging |
| Qt 6 Widgets GUI | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Windows build/launch and widget tests verified; Linux desktop validation still needed |
| GUI single instance | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Shared Qt single-instance mechanism; verified on Windows |
| CoreHost single instance | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Platform process-instance lock |
| Plain UDP/TCP | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Platform socket backends |
| DoH | IMPLEMENTED_AND_TESTED | IMPLEMENTED | libcurl HTTP/2 multiplexing (`CURLPIPE_MULTIPLEX`); local TLS fixture verified on Windows |
| DoT | IMPLEMENTED_AND_TESTED | IMPLEMENTED | libcurl secure transport; local TLS fixture verified on Windows |
| DNSCrypt | IMPLEMENTED_AND_TESTED | IMPLEMENTED | libsodium (cached shared key + prepared queries) |
| Anonymized DNSCrypt | IMPLEMENTED_AND_TESTED | IMPLEMENTED | libsodium + relay handling |
| DoH3 | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No required QUIC backend in current transport stack |
| DoQ | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No required QUIC backend in current transport stack |
| YogaDNS import | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Shared config importer (including DoH path/IPv6/Default normalization) |
| Ordered rules | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Shared Core (precompiled rules per Snapshot) |
| IPC | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Named Pipes / Unix Domain Sockets |
| Transparent interception | IMPLEMENTED | PARTIAL | WinDivert (unit/rewrite/proxy tested; live privileged host run required per release) / nftables |
| Autostart | IMPLEMENTED | IMPLEMENTED | Task Scheduler (with executable-path drift repair detection) / XDG autostart |
| Tray lifecycle | IMPLEMENTED | IMPLEMENTED | Shared Qt behavior (no-tray fallback + dynamic re-check) |
| Portable package | IMPLEMENTED | IMPLEMENTED | ZIP / tar.gz or AppImage path |
| Installer/package | IMPLEMENTED | IMPLEMENTED | Inno Setup (graceful shutdown + `network restore` on uninstall) / DEB |

Run the project test/build scripts for the exact commit being released instead of relying on historical test-count documents.
