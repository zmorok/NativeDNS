# DNS transports

NativeDNS transports exchange DNS wire messages through a common Core interface.

## Plain DNS

Implemented transports:

- UDP;
- TCP.

UDP uses a connected socket for peer enforcement. Truncated UDP responses may retry through TCP within the configured deadline.

TCP uses the standard two-byte DNS message length framing.

## Parser and server testing

The DNS parser validates:

- response/question metadata;
- bounds;
- compression pointers;
- record lengths;
- transaction/question matching.

The server tester performs a real DNS query and measures monotonic RTT.

A successful TCP connection by itself is not considered a successful DNS server test.

Failed tests return a structured error code/message suitable for readable red GUI presentation.

## DoH

DNS over HTTPS uses libcurl.

Requirements include:

- certificate/hostname verification;
- HTTP success;
- `application/dns-message`;
- configured timeout;
- optional certificate/public-key pin behavior where configured.

The connection IP/bootstrap choice must not replace the TLS identity/hostname being validated.

## DoT

DNS over TLS uses the secure libcurl path and standard DNS-over-TCP framing over TLS.

Certificate and hostname validation remain enabled.

## DNSCrypt

DNSCrypt uses libsodium.

The implementation handles provider certificate retrieval/verification, authenticated encryption, nonce/key handling, padding validation, and cached provider certificates.

## Anonymized DNSCrypt

The provider certificate is obtained directly from the resolver.

Encrypted DNSCrypt packets are sent through the configured anonymizing relay. The relay should not receive the plaintext query or provider private material.

## DoH3 / DoQ

Protocol values exist in the configuration/API model.

The current Windows libcurl/Schannel configuration does not provide the required QUIC backend. When DoH3/DoQ cannot be supported by the current build, selection must fail explicitly rather than silently falling back to DoH/DoT.

## Routing interaction

Rules are applied before upstream I/O.

- `Process` uses the selected configured server.
- `Process/0` uses the original/system destination supplied by the interception backend.
- `Bypass` preserves the original resolver path.
- `Block` returns the configured blocking behavior.

Core-owned upstream sockets must be excluded from transparent self-interception to prevent DNS routing loops.

On Windows, captured UDP queries matched by `Bypass` or `Process` with server ID `0` are reinjected directly from the WinDivert receive loop. They never wait behind custom-upstream work in the routing worker queue. This is also the path that lets the operating-system resolver complete hostname lookup for DoH/DoT endpoints when neither `ip` nor `bootstrap` is configured. Explicit bootstrap behavior and configuration semantics are unchanged.

Custom upstream routing uses a bounded worker queue sized to absorb short bursts. Worker count scales with available processors within fixed limits. If the application queue is saturated, NativeDNS returns `SERVFAIL` and emits rate-limited saturation diagnostics instead of silently dropping the captured query or bypassing its rule.

IPv4 and IPv6 fragments are excluded from transparent interception and continue through the system network path unchanged. IPv6 Hop-by-Hop, Routing, Destination Options, atomic Fragment, and Authentication extension headers are parsed when they precede UDP or TCP DNS. A captured packet with an unsupported or malformed extension chain is logged and reinjected unchanged.
