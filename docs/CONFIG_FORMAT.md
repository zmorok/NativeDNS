# Configuration format

NativeDNS uses a versioned UTF-8 XML configuration.

Current schema:

```text
schemaVersion = 1
```

## Model

The configuration contains:

- global settings/metadata;
- logging settings;
- DNS servers;
- ordered rules;
- DNS server test target/concurrency.

## Logging

The `Logging` element controls the live GUI log and the rotating diagnostic file log:

- `screen`: live-log level (`0` errors, `1` normal, `2` verbose, `3` debug);
- `file`: independently selected file-log level using the same values;
- `enabled`: enables or disables the file sink;
- `directory`: retained for compatibility with existing configurations. Runtime logs are always written to the `logs` directory in the application root. Each recording starts in a timestamped file such as `NativeDNS-143705-12092026.log` (`HHmmss-ddMMyyyy`).

File logging is enabled at the normal level for new configurations. The log includes DNS routing plus startup, environment, interception, IPC, and shutdown diagnostics. On Windows, the environment row shows the OS edition, architecture, display version, and full build number. The file rotates at 4 MiB, gives each new segment its own recording-start timestamp, and retains three previous files. A fatal CoreHost startup error is written to the default diagnostic log when possible even if configuration loading itself fails.

Saving servers or rules in the GUI applies the new configuration to the running CoreHost without stopping DNS interception. If CoreHost rejects the new configuration, its previous routing state remains active.

GUI rows begin with local time in `[dd.MM HH:mm:ss]` form. File rows use `[dd.MM.yyyy HH:mm:ss]` so exported diagnostics retain the year.
The GUI retains the newest 2,000 live-log rows; older rows are removed from the display only and remain available in the diagnostic file.

At the normal level, each successful DNS operation is one combined route/result row containing the hostname, query type, action, readable server transport, matched rule, and elapsed upstream time. Verbose/debug levels add transport internals; failures remain separate error-level rows.

Server protocol values currently represented by the model include:

- `udp`
- `tcp`
- `doh`
- `dot`
- `doh3`
- `doq`
- `dnscrypt`
- `anonymized_dnscrypt`

`doh3` and `doq` are preserved by the model even when the current build lacks an available QUIC implementation; runtime selection must fail explicitly instead of silently downgrading.

## Servers

Server fields include:

- stable numeric ID;
- name/enabled state;
- protocol;
- numeric IP and port;
- hostname;
- URL;
- bootstrap servers;
- ordered fallback server IDs;
- DNSSEC capability metadata;
- timeout;
- hashes/pins;
- DNSCrypt public key/provider;
- anonymized DNSCrypt relay;
- explicit Anonymized DNSCrypt direct-certificate-fallback policy;
- imported metadata.

Server ID `0` is reserved as the original/system destination sentinel and is not a normal configured server.

The optional semicolon-separated `fallbacks` attribute defines a server group rooted at that server. References must exist, be unique, and form an acyclic graph. A request uses a bounded aggregate deadline across the enabled candidates; it never falls back implicitly to the system resolver.

## Rules

Rules contain:

- stable ID;
- name;
- enabled state;
- permanent Default marker;
- hostname patterns;
- action;
- selected server ID;
- interface/security metadata;
- block mode.

Rules are evaluated in vector order.

The permanent Default rule cannot be removed, disabled, or moved away from the end.

Block modes:

```text
0  zero address (0.0.0.0 / ::)
1  NXDOMAIN
2  REFUSED
3  silent drop
```

## Host normalization

Names are normalized by shared cross-platform Core code. TLS/server hostnames accept canonical ASCII LDH/A-label input only. Unicode input must first be processed by a complete IDNA/UTS #46 implementation outside Core and supplied in `xn--` form.

DNS wire names and rule patterns are a separate domain: printable ASCII labels are supported, including service-label underscores. Names are lowercased, one trailing dot is removed, and wire label/name length limits are enforced. `*` and `?` are reserved for rule patterns.

`*.example.com` does not match the apex `example.com`.

## XML safety

The parser is implemented in shared C++ Core code.

Configuration files are limited to 4 MiB and bounded XML depth/event complexity. Unsupported constructs such as DTD/CDATA are rejected where the parser does not support them.

Unknown required NativeDNS fields are rejected instead of being silently discarded.

## Persistence

Configuration changes are validated before publishing.

The common config layer writes a temporary sibling file, verifies it can be parsed, then calls a platform-specific atomic publish primitive.

Windows and Linux use separate filesystem implementations behind the same Core interface.

## YogaDNS import

YogaDNS profiles are imported into the NativeDNS model.

Known server/rule fields are mapped. Unknown source metadata is retained where the importer supports it so migration does not silently lose information.

Imported runtime-sensitive options that NativeDNS cannot yet enforce should remain visible as warnings/metadata rather than being silently treated as supported.

## Blocking and DNSSEC semantics

`zero address` returns `0.0.0.0` for A and `::` for AAAA with TTL 0. For every other query type it returns NOERROR with no answers (NODATA). Synthetic replies preserve the original question, recursion-desired/checking-disabled bits, and an EDNS(0) OPT record (including the DO bit) when present.

The server `dnssec` field is capability metadata only. Local DNSSEC validation and imported rule flags `validate` / `rejectUnsigned` are not implemented. Such rules fail explicitly with `NOT_IMPLEMENTED`, and the Qt rule editor does not expose those controls.
