# Platform matrix

Status words describe current implementation maturity, not a release guarantee.

| Capability | Windows x64 | Linux x64 | Notes |
|---|---|---|---|
| Shared Core | IMPLEMENTED | IMPLEMENTED | Common rules/config/DNS/crypto/logging |
| Qt 6 Widgets GUI | IMPLEMENTED_AND_TESTED | IMPLEMENTED | Windows build/launch verified during current development; Linux desktop validation still needed |
| GUI single instance | IMPLEMENTED | IMPLEMENTED | Shared Qt single-instance mechanism; verify each desktop environment |
| CoreHost single instance | IMPLEMENTED | IMPLEMENTED | Platform process-instance lock |
| Plain UDP/TCP | IMPLEMENTED | IMPLEMENTED | Platform socket backends |
| DoH | IMPLEMENTED | IMPLEMENTED | libcurl |
| DoT | IMPLEMENTED | IMPLEMENTED | libcurl secure transport |
| DNSCrypt | IMPLEMENTED | IMPLEMENTED | libsodium |
| Anonymized DNSCrypt | IMPLEMENTED | IMPLEMENTED | libsodium + relay handling |
| DoH3 | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No required QUIC backend in current transport stack |
| DoQ | NOT_IMPLEMENTED | NOT_IMPLEMENTED | No required QUIC backend in current transport stack |
| YogaDNS import | IMPLEMENTED | IMPLEMENTED | Shared config importer |
| Ordered rules | IMPLEMENTED | IMPLEMENTED | Shared Core |
| IPC | IMPLEMENTED | IMPLEMENTED | Named Pipes / Unix Domain Sockets |
| Transparent interception | IMPLEMENTED | PARTIAL | WinDivert / nftables; Linux privileged host validation required |
| Autostart | IMPLEMENTED | IMPLEMENTED | Task Scheduler / XDG autostart |
| Tray lifecycle | IMPLEMENTED | IMPLEMENTED | Shared Qt behavior; Linux depends on desktop tray support |
| Portable package | IMPLEMENTED | IMPLEMENTED | ZIP / tar.gz or AppImage path |
| Installer/package | IMPLEMENTED | IMPLEMENTED | Inno Setup / DEB |

Run the project test/build scripts for the exact commit being released instead of relying on historical test-count documents.
