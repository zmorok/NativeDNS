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

The Router keeps a bounded pool of up to eight libcurl easy handles per DoH server. Reusing a handle preserves libcurl's connection cache. DoH requests prefer HTTP/2 through ALPN and automatically fall back to HTTP/1.1 when the server does not negotiate HTTP/2. Idle connections older than 30 seconds and connections older than five minutes are not reused.

Requirements include:

- certificate/hostname verification;
- HTTP success;
- `application/dns-message`;
- configured timeout;
- optional certificate/public-key pin behavior where configured.

The connection IP/bootstrap choice must not replace the TLS identity/hostname being validated.

## DoT

DNS over TLS uses the secure libcurl path and standard DNS-over-TCP framing over TLS.

The Router keeps up to four reusable DoT handles per server. Requests on each TLS connection are serialized. The connection cache uses the same 30-second idle and five-minute absolute lifetime limits as DoH, and a transport-level failure is retried once within the original request deadline.

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

Before transparent interception starts, enabled DoH/DoT hostnames that have neither a numeric connection IP nor explicit bootstrap resolvers are resolved once through the system resolver. The resulting numeric address is retained only in the runtime configuration; the original hostname remains the TLS identity. Secure requests never perform implicit system resolution after interception has started.

On Windows, every libcurl-created secure TCP socket is bound before connect and its ephemeral source port remains registered with the same self-bypass registry used by plain DNS until libcurl closes the socket. On Linux, secure sockets receive the NativeDNS `SO_MARK` used by the nftables loop-prevention rules.

The Windows reflected-TCP listener must accept packets addressed to the original resolver IP, so it cannot bind only to loopback. Its exposure is limited by an executable- and ephemeral-port-specific firewall rule plus one-shot validation of recently captured client SYN tuples. Connections without such a tuple are rejected even if the firewall is unavailable. NativeDNS removes a stale rule both while constructing and immediately before starting interception, and removes the active rule during normal shutdown or partial-start rollback.

On Windows, captured UDP queries matched by `Bypass` or `Process` with server ID `0` are reinjected directly from the WinDivert receive loop. They never wait behind custom-upstream work in the routing worker queue. Explicit bootstrap queries use guarded plain DNS sockets and cannot be captured recursively.

Custom upstream routing uses a bounded worker queue sized to absorb short bursts. Worker count scales with available processors within fixed limits. If the application queue is saturated, NativeDNS returns `SERVFAIL` and emits rate-limited saturation diagnostics instead of silently dropping the captured query or bypassing its rule.

IPv4 and IPv6 fragments are excluded from transparent interception and continue through the system network path unchanged. IPv6 Hop-by-Hop, Routing, Destination Options, atomic Fragment, and Authentication extension headers are parsed when they precede UDP or TCP DNS. A captured packet with an unsupported or malformed extension chain is logged and reinjected unchanged.

UDP replies respect the request's EDNS(0) advertised payload size. NativeDNS uses the classic 512-byte limit when the request has no OPT record and caps EDNS UDP replies at 1232 bytes to avoid common-path IP fragmentation. A larger upstream answer is returned as a question-preserving response with `TC=1`, allowing a conforming client to retry over TCP.

Plain DNS over TCP uses a per-resolver pool of up to four connections. Requests on an individual connection are serialized, idle connections are discarded before reuse after 30 seconds, and a broken reused connection is reopened once within the original request deadline. The Router owns transport instances, so connection state is released when configuration reload replaces the Router.
