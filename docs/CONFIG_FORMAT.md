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
