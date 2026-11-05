# Configuration format

NativeDNS uses a versioned UTF-8 XML configuration.

Current schema:

```text
schemaVersion = 1
```

The GUI keeps its working configuration in `%LOCALAPPDATA%\NativeDNS\NativeDNS.xml`
on Windows and the `nativedns` directory under the XDG configuration directory on Linux.
Use **File > Import Configuration** to apply an XML file from another computer.
Copying an XML file beside the executable does not import it. The GUI log shows
the working file path. CoreHost also accepts an explicit `--config` path.

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
Explicit rejection also restores the previous GUI configuration and saved file.
If a configuration is saved while CoreHost is starting or its reply is unavailable,
the import dialog reports pending confirmation instead of claiming it was applied.

Diagnostic builds (or `--diagnostics`) preset both capture levels to Debug and
enable file recording, including after imports/reloads. Their initial GUI view
shows only completed Process results and related errors for custom upstreams.
The full file log also retains Bypass, Block and service diagnostics. Normal log
menus are locked at Debug during diagnostic capture; changing display filters
does not lower file capture. `server_id=0` identifies the original-resolver sentinel.

`CONFIG_SUMMARY` records the absolute loaded path, application version, server/rule
counts and a `config_id` at the normal log level, on startup and after reload.
The ID is SHA-256 of the canonical serialized configuration, so XML formatting
does not affect it. Verbose logging also records ordered rules. The GUI sends
the expected ID when reloading; a different saved configuration is rejected with
`CONFIG_MISMATCH` before replacing active routing.

Windows logs and IPC text use UTF-8 independently of the ANSI/OEM/console code
pages recorded in `SYSTEM_ENVIRONMENT`. CoreHost and CLI paths are read from the
Unicode command line; changing `chcp` is not required for configuration or file logs.

Transparent mode inspects the network before interception starts, after config
reload, and after network changes. `DNS_HOSTS_OVERRIDE` identifies hosts-file names
that overlap effective custom Process/Block rules. Windows interface DoH properties,
machine DNS-encryption policy values, NRPT rule counts and active adapter DNS
addresses are also logged. Unavailable checks are reported rather than treated
as proof that no override exists. The hosts file is inspected read-only and is
never edited by NativeDNS. Browser profiles are not edited. The existing
`clearDnsCache` option flushes the system DNS cache after interception
start/reload; it cannot clear application caches. Browser Secure DNS and VPN DNS
need separate inspection. An `HTTPS` query type in a DNS log is a resource-record
type and does not identify DNS-over-HTTPS transport.

Windows transparent mode enables `windowsPrepareSystemDns` by default. After
interception starts, if enabled rules require a custom Process upstream or
Block, it temporarily disables configured per-server Windows
DoH/DoT and adapter DDR so queries can reach the port-53 interceptor. Static/DHCP
DNS addresses, DNS suffixes, registration, NRPT rules, machine encryption
policies and browser profiles are not changed. The hosts file is never modified.
Unsupported Windows APIs/properties or policy refusals produce explicit
`DNS_PREPARATION_*` findings instead of silently claiming successful preparation.
The Windows Configuration menu exposes this setting as a checkable action.

Original encryption flags, templates, hostnames and ports are persisted before
each change in `%PROGRAMDATA%\NativeDNS.NetworkRecovery`, writable only by
Administrators/SYSTEM. Stop/Exit restores them in reverse order. The next
transparent start recovers a journal left after an abnormal termination before
preparing the current network. Setting `windowsPrepareSystemDns=0` also triggers
restoration on reload. Actual changes flush the Windows DNS cache independently
of `clearDnsCache`; application/browser caches require separate handling.

Recovery preserves later external edits. A changed encryption property is
reported as `DNS_PREPARATION_CONFLICT` and its original is retained in the
journal. Removed DNS addresses are not recreated; disconnected adapters retain
their recovery records for a later retry. Failed preparation does not stop
otherwise working interception. Local proxy mode and Linux do not alter system
DNS encryption. Browser Secure DNS remains separate from Windows DNS settings.

GUI rows begin with local time in `[dd.MM HH:mm:ss]` form. File rows use `[dd.MM.yyyy HH:mm:ss]` so exported diagnostics retain the year.
The GUI retains the newest 2,000 live-log rows; older rows are removed from the display only and remain available in the diagnostic file.

At the normal level, each successful DNS operation is one combined route/result row containing the hostname, query type, action, readable server transport, matched rule, and elapsed upstream time. Verbose/debug levels add transport internals; failures remain separate error-level rows.

Completed upstream route rows also include `rcode`, `address_count`, and up to eight
`answer_ip` values, making it possible to compare the selected DNS route with the
addresses used by the OS/browser. `address_count=0` is not by itself a DNS error:
for example, an HTTPS resource-record response need not contain an A/AAAA address.

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

Windows Process rules can bind upstream and bootstrap sockets to an adapter.
The `interface` selector accepts its GUID (optionally `guid:`-prefixed) or current
numeric index. Imported `interface_id_type="name"` and `interface_name` select
the adapter alias/description. Ambiguous selectors fail explicitly. With
`ignore_rule_if_interface_down=1` (including the imported `yoga.settings.` key),
an unavailable adapter skips a non-Default rule; otherwise it returns
`INTERFACE_DOWN`. A bound Default never silently selects another adapter.
Process/server 0 with a binding uses the selected adapter's DNS; without a
binding the original intercepted resolver is retained. Bypass retains its
original path after interface availability checks. POSIX does not infer
per-interface DNS from a global resolver file. Numeric IPv6 endpoints can
carry a `%<interface-index>` scope.

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

Existing Settings metadata keys are executed by the current backend: native keys
take precedence over imported `yoga.settings.` keys. Boolean values accept
`0`/`1` or `false`/`true`; invalid values are rejected before applying a profile.

| Key | Windows behavior |
|---|---|
| `clearDnsCache` | Flush the Windows resolver cache after Start and successful Reload. Failures are logged. |
| `windowsPrepareSystemDns` | Default `1`; temporarily disable Windows DNS encryption in transparent mode and restore it on Stop/Exit or the next start after a crash. |
| `ttlMin`, `ttlMax` | Clamp ordinary RR TTLs in Process replies before caching; range 0..2147483647, minimum <= maximum. |
| `blockTcpPort53` | Reject external TCP/53 with a reset, retaining Core-owned upstream sockets. |
| `interceptOthers` | Include third-party injected packets when enabled; changing it requires a CoreHost restart. |
| `captivePortalDetection` | Permit NCSI discovery queries through the unbound Process Default. On an OS-confirmed captive interface, that Default retains the original resolver until the portal clears. |

TTL limits leave Block replies, explicit Bypass, OPT pseudo-record fields and
authenticated/signed DNS replies unchanged. Cache aging can reduce a delivered
TTL below `ttlMin`; it never extends an entry on a cache hit. Captive portal
handling does not override explicit rules, Block, DNSSEC requirements or a bound
Default. Disconnected adapters alone are not considered captive portals.

Linux currently reports system cache flush and injected-packet/TCP-block options
as unsupported. It has no OS captive portal detection source; enabling portal
support emits `CAPTIVE_PORTAL_UNAVAILABLE` on transparent startup.

`zero address` returns `0.0.0.0` for A and `::` for AAAA with TTL 0. For every other query type it returns NOERROR with no answers (NODATA). Synthetic replies preserve the original question, recursion-desired/checking-disabled bits, and an EDNS(0) OPT record (including the DO bit) when present.

The server `dnssec` field is capability metadata only. Local DNSSEC validation and imported rule flags `validate` / `rejectUnsigned` are not implemented. Such rules fail explicitly with `NOT_IMPLEMENTED`, and the Qt rule editor does not expose those controls.

## Log filter configuration

Saved GUI display filters can be imported/exported separately from the DNS configuration.
The UTF-8 XML root is `NativeDNSLogFilters` with `schemaVersion="1"`, containing one `Filters`
element. Each `Filter` has a stable unique `id`, a `Name`, and an `Expression`:

```xml
<NativeDNSLogFilters schemaVersion="1">
  <Filters>
    <Filter id="process-errors">
      <Name>Process errors</Name>
      <Expression>action="process" &amp;&amp; err="*"</Expression>
    </Filter>
  </Filters>
</NativeDNSLogFilters>
```

XML escapes such as `&amp;` are decoded before expressions are validated. Missing IDs are
assigned when importing. Configurations are limited to 1 MiB and 256 filters; names are
1..256 characters and expressions at most 4096 characters. Unsupported schema versions,
duplicate IDs, malformed XML, DTDs, and invalid expressions are rejected before changing
any rows. An empty `Filters` element represents an empty list.

Import replaces the manager's working copy. New and modified rows are bold until OK
validates and saves the list; Close discards the entire working copy, including imports.
Export writes the current valid working copy using atomic file replacement, without
applying it to the saved GUI list. Exported files remain on disk when the dialog is closed.
See [log-filters.xml](../examples/log-filters.xml) for filters for DNS record types, rule
actions, Default routing, error conditions, and Microsoft connectivity queries.
