# Protection screens

The **Protection** section of the sidebar. Each screen shows whether its
daemon runs and what it has found, and holds the feature's settings. When
the saved config does not validate, the screen says so at the top.

## AI IDS/IPS

| Card | Contents |
| --- | --- |
| **Engine status** | Whether `fr-ai-ids.service` runs and whether detection is enabled. |
| **Settings** | **Enabled**, **Quarantine duration (seconds)**, **Excluded MAC addresses** (comma-separated; an IPv4 device is matched through its DHCP reservation). **Save settings**. |
| **Currently quarantined hosts** | Each host with what holds it (an address, or a MAC with all its IPv6 addresses) and the time left. A quarantine ends on its own when its timeout passes; there is no early release from the console yet. |
| **Recent flagged events** | Each event: the host, its score, the reasons, and the counters behind them (connection rate, unique-destination ratio, SNI blocks, NXDOMAIN names, DGA-like names, threat lookups). |

The DNS signals need **Log queries** on the Ad-Block screen. See
[AI-IDS](../features/ai-ids.md).

## TLS SNI Filter

The summary shows the filtered interfaces, the number of blocked names and
the drops since the program was loaded.

| Card | Contents |
| --- | --- |
| **Attached interfaces** | Each interface, its device, and the mode: native (in the driver) or generic. |
| **What this filter doesn't see** | QUIC (rejected while the filter is on, so browsers fall back to TCP), Encrypted Client Hello, other ports than 443, ClientHellos over several TLS records, names of 32 bytes or more, IPv6 with too many extension headers, and TCP fragments. Read it before relying on the filter. |
| **Settings** | **Enabled**, **Interfaces to filter** (pick the LAN side: XDP sees only what an interface *receives*), **Blocked domains** (one per line or comma-separated; a name also blocks its subdomains). **Save settings**, then Apply. |
| **Blocked domains** | The list, each with **Remove**. |
| **Live log** | The filter's drops as they happen, streamed from `fr-xdp-sni-logger`. The drop already happened in the kernel; the page only shows it. |

See [XDP SNI filter](../features/xdp-sni-filter.md).

## Ad-Block

The resolver and its blocklists.

| Card | Contents |
| --- | --- |
| **Base list** | **Enabled**; **Ad/tracker source lists**, one URL per line (suggestions are offered); **XDP critical-subset size**: how many base-list names to also put in the XDP filter's blocklist (0 is off; it works only with that filter on). |
| **Categories** | Ready-made lists by category, each with its source and licence, to tick. Check each list's licence before use in a business. Categories added by hand in `config.yaml` are kept as they are and shown. **Allowlist**: names never blocked, with their subdomains. |
| **LAN DNS** | **Serve DHCP clients**: DHCP announces the router as the DNS server, and the pools' DNS servers become its upstreams. **Enforce**: redirect all plain DNS to the router, block DNS over TLS, and turn off Firefox's automatic DNS over HTTPS. **Log queries**: record who looked up what, for AI-IDS and application identification. |
| **Local names** | Names the resolver answers itself: a **Host** (one exact name) or an **Override** (the name and its subdomains), each with an IPv4 address. **Local domain**: a domain never asked upstream; a name under it that isn't a host doesn't exist. |
| **Refresh** | **Refresh now** downloads the lists at once, instead of waiting for the daily `fr-adblock-refresh.timer`. |

The summary shows how many names are loaded. See
[DNS filtering and local names](../features/dns-filtering.md).

## IoT Devices

| Card | Contents |
| --- | --- |
| **Settings** | **Enabled**, **Zones to scan**, **Automatically isolate devices classified as IoT (unless trusted)**, **Isolation mode**: *Internet only* or *Block*. **Save**. |
| **Scan** | When the last scan ran (every 10 minutes by `fr-iot-scan.timer`) and **Scan now**. |
| **Currently isolated** | The MACs in the kernel's isolation set now. |
| **Inventory** | Each device: name and addresses, vendor, advertised services, class (*IoT*, *general*, *unknown*) with its score, **why** (every signal that counted), and its state (*isolated*, *trusted*, *manually isolated*). **Trust**, **Isolate** and **Clear** take effect at once. |

Isolation covers what goes through the router; devices on the same
switch or Wi-Fi can still reach each other. See
[IoT discovery and isolation](../features/iot.md).

## Applications

| Card | Contents |
| --- | --- |
| **Settings** | **Enabled** (identify apps and enforce the blocked list), **Also observe TLS server names with the XDP filter**, **Also block apps in the XDP SNI filter** (catches clients that use their own DNS over HTTPS). **Save**. |
| **Prerequisites** | Whether the resolver, query logging and the XDP filter are on, whether `fr-appid` runs and when it last wrote its usage file. |
| **Apps (last 24 hours)** | Every app of the catalogue: a **Block** box, its category, active clients in the last 15 minutes, hits, last seen, and which clients. **Save blocked apps**. |

A *hit* is one lookup or one TLS connection: an activity signal, not a
traffic volume. The footer names the catalogue's source and version. See
[Application control](../features/app-control.md).

## TLS Fingerprints

| Card | Contents |
| --- | --- |
| **Settings** | **Enabled** (needs the XDP SNI filter on the LAN side) and **Quarantine a device that presents a blocklisted fingerprint**. **Save**. The status line shows the filter, whether `fr-tls-fp` runs, how many hellos it fingerprinted or could not parse, and whether it is still in its 24-hour learning period. |
| **Events** | *blocklisted* and *new fingerprint* events: when, device, JA4, server name, action. |
| **Devices and their fingerprints** | Each device's JA4 values with the latest JA3, the server names, how often and when, how many devices share it, and **Block**. |
| **Blocklist** | JA4 fingerprints or 32-hex-digit JA3 hashes with an optional label, **Add to blocklist** and **Remove**. The daemon picks changes up within 30 seconds. |

See [TLS fingerprints](../features/tls-fingerprints.md).

## ZTNA Gate

| Card | Contents |
| --- | --- |
| Summary | Enabled or disabled, session length, number of accounts and gated rules. |
| **Settings** | **Enabled** and **Session length (seconds)**, 60 to 2,592,000. **Save settings**, then Apply; an apply keeps the sessions already signed in. |
| **Local accounts** | The gate's accounts, each with **Remove**. **Add account**: user name and password. |
| **Gated rules** | The rules with **Require ZTNA**. |
| **End-user pages** | Links to `/ztna/login` and `/ztna/status`, the pages users open to sign in and check their session. |

See [ZTNA gate](../features/ztna.md).
