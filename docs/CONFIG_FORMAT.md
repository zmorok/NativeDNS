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
- `directory`: log directory. The default relative value `logs` is resolved from the staged application root, producing `logs/NativeDNS.log` beside the application folders. Absolute paths remain supported.

File logging is enabled at the normal level for new configurations. The log includes DNS routing plus startup, environment, interception, IPC, and shutdown diagnostics. It rotates at 4 MiB and retains three previous files. A fatal CoreHost startup error is written to the default diagnostic log when possible even if configuration loading itself fails.

GUI rows begin with local time in `[dd.MM HH:mm:ss]` form. File rows use `[dd.MM.yyyy HH:mm:ss]` so exported diagnostics retain the year.

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
- DNSSEC capability metadata;
- timeout;
- hashes/pins;
- DNSCrypt public key/provider;
- anonymized DNSCrypt relay;
- imported metadata.

Server ID `0` is reserved as the original/system destination sentinel and is not a normal configured server.

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

Hostnames are normalized by shared cross-platform Core code.

The implementation:

- validates UTF-8;
- lowercases supported Unicode ranges;
- converts non-ASCII labels to Punycode;
- removes one trailing dot;
- validates DNS label/name lengths;
- supports `*` and `?` wildcard characters only in rule patterns.

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
