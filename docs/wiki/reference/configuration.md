# Configuration reference

Every key of `/etc/fr_os/config.yaml`, with its type, its default, and
the rule the loader checks it against. The rules here are the loader's
(`config/load.go`); the error messages quoted are the ones you will see.

For what the file is and how it is checked as a whole, read
[The configuration file](../concepts/configuration-file.md) first.

## Conventions

| Type | Meaning |
| --- | --- |
| *name* | Lower-case letters, digits, `_` and `-`, starting with a letter: `^[a-z][a-z0-9_-]*$`. Zone, rule, port forward, pinhole and blocklist category names. |
| *zone* | The name of a declared zone. Where a rule allows it, `self` means the router. |
| *bool* | `true` or `false`. YAML 1.1 also reads `yes`/`no`/`on`/`off` as booleans. |
| *int* | An integer. A boolean is not accepted where a number is expected. |
| *port* | An integer 1 to 65535. |
| *port spec* | A port (`443`) or a range string (`"1000-2000"`, low to high). |
| *IPv4 interface* | An address with its prefix length: `10.73.1.1/24`. |
| *network* | An IPv4 or IPv6 address or network: `192.168.1.0/24`, `2001:db8::/32`, `10.0.0.5`. |
| *MAC* | `aa:bb:cc:dd:ee:ff`, any case. Stored in lower case. |
| *hostname* | Labels of 1 to 63 letters, digits and `-` (not first or last), joined by dots; 253 characters at most. |
| *time* | `"HH:MM"`, quoted, `00:00` to `24:00`. |

Lists may not name the same thing twice unless a key says duplicates are
merged.

## Top level

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `version` | int | required | Must be `1`. |
| `hostname` | hostname | required | Non-empty. Goes into the web console's certificate. |
| `timezone` | string | the system's | An IANA zone name, for example `Europe/Budapest`. Rule schedules and `expires` dates without an offset are read in it. |
| `zones` | mapping | required | See [zones](#zones). |
| `interfaces` | mapping | required | See [interfaces](#interfaces). Must not be empty. |
| `rules` | list | `[]` | See [rules](#rules). |
| `nat`, `dhcp`, `ipv6`, `management`, `logging`, `wireguard`, `ztna`, `adblocker`, `local_dns`, `app_control`, `xdp_sni_filter`, `tls_fingerprint`, `iot`, `ai_ids`, `metrics`, `pqc`, `update` | mapping | off / empty | One section each, below. |

## zones

A mapping of zone name to its settings.

```yaml
zones:
  wan: {}
  lan: {description: Our computers}
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| *(the key)* | name | | Not `self` (reserved for the router). |
| `description` | any | `""` | Free text, shown in the console. |

Every declared zone must be used by an interface or by the WireGuard
tunnel: *"Zone 'x' is declared but not used by any interface"*.

A zone **faces the internet** when `nat.masquerade` points at it, or when
it is named `wan`.

## interfaces

A mapping of interface name to its settings.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| *(the key)* | name | | |
| `device` | string | required | A Linux interface name: 1 to 15 characters, letters, digits, `_`, `.`, `-`, not starting with a punctuation mark. A device may be in only one interface. |
| `zone` | zone | required | A declared zone. |
| `address` | IPv4 interface | none | The router's own address on this network. Needed for a DHCP pool. |
| `description` | any | `""` | Free text. |
| `vlan.parent` | string | | The physical device the VLAN is on. Not the interface's own device. |
| `vlan.id` | int | | 1 to 4094. |

## rules

A list of rules, evaluated in order. See
[Zones and segments](../concepts/zones.md#how-a-packet-is-decided) for
where they sit among the built-in guards.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `name` | name | required | Unique among rules. |
| `action` | `accept`, `drop`, `reject` | required | |
| `from_zone` | zone | any | Not `self`. |
| `to_zone` | zone or `self` | any | `self` puts the rule in the input chain; anything else in the forward chain. |
| `proto` | `any`, `tcp`, `udp`, `icmp` | `any` | |
| `dst_port` | port spec | any | Needs `proto: tcp` or `udp`. |
| `src_address` | network or list | any | IPv4 and IPv6 may be mixed. An empty list is refused ("leave the key out instead"). Duplicates are merged. |
| `dst_address` | network or list | any | As `src_address`. With both set, they must share an address family. |
| `src_mac` | MAC | any | |
| `log` | bool | `false` | Log every packet the rule matches. |
| `require_ztna` | bool | `false` | Match only sources signed in at the ZTNA gate. |
| `schedule` | mapping | always | See below. |
| `expires` | date and time | never | ISO 8601 (`2026-12-31T23:59`) or a YAML timestamp. Without an offset, read in `timezone`. Enforced in the kernel (`meta time`), so it is exact without a new apply. |

### schedule

```yaml
schedule:
  days: [weekdays]          # or [mon, wed, fri], [weekend], [daily]; a single string works too
  start: "21:30"
  end: "06:30"              # before start: the window runs over midnight
  cut_established: true     # drop/reject rules only
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `days` | list of day names | `[daily]` | `mon` ... `sun`, `weekdays`, `weekend`, `daily`, any case. Not empty. |
| `start` | time | required | Not `24:00`. |
| `end` | time | required | Not equal to `start`; use `00:00` to `24:00` for a whole day. An `end` before `start` crosses midnight. |
| `cut_established` | bool | `false` | Only for `drop` and `reject` rules. Ends connections that were open when the window starts. |

`firewall-cli schedule-check` runs on a timer and keeps scheduled rules
right across daylight-saving changes and time-zone changes.

## nat

```yaml
nat:
  masquerade:
    - {out_zone: wan}
  port_forwards:
    - {name: web, in_zone: wan, proto: tcp, dst_port: 443, to_address: 10.73.1.10, to_port: 8443}
```

`masquerade` is a list of:

| Key | Type | Rule |
| --- | --- | --- |
| `out_zone` | zone | Required. Not `self`. |

`port_forwards` is a list of:

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `name` | name | required | Unique among port forwards. |
| `in_zone` | zone | required | Where the connection arrives. Not `self`. |
| `proto` | `tcp` or `udp` | required | |
| `dst_port` | port | required | The port on the router. |
| `to_address` | IPv4 address | required | The inside host. |
| `to_port` | port | `dst_port` | The port on the inside host. |

A port forward only rewrites the destination. A forward rule from
`in_zone` to the host's zone must still accept the traffic.

## dhcp

A mapping of zone name to its IPv4 pool, served by Kea.

```yaml
dhcp:
  lan:
    range_start: 10.73.1.100
    range_end: 10.73.1.199
    dns_servers: [10.73.1.1]
    lease_time: 3600
    reservations:
      - {mac: "aa:bb:cc:dd:ee:ff", address: 10.73.1.10, hostname: nas}
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| *(the key)* | zone | | The zone must have exactly one interface, and it must have an `address`. |
| `range_start`, `range_end` | IPv4 address | required | Inside the interface's network, not the router's own address, start not after end. |
| `dns_servers` | list of IPv4 addresses | required | Not empty. Use the router's own address when its resolver serves the LAN. |
| `lease_time` | int | `3600` | Seconds, positive. |
| `reservations` | list | `[]` | See below. |

Each reservation:

| Key | Type | Rule |
| --- | --- | --- |
| `mac` | MAC | Required. Unique in the pool. |
| `address` | IPv4 address | Required. Inside the network, not the router's address, unique in the pool. |
| `hostname` | string | Optional. |

## ipv6

```yaml
ipv6:
  enabled: true
  lan_zones: [lan]                     # optional: default is every LAN zone that can have it
  ula_prefix: fd12:3456:789a::/48      # optional: default is a random one
  pinholes:
    - {name: nas-https, zone: lan, host: "::5054:ff:fe12:3456", proto: tcp, port: 443}
```

Unknown keys are refused in this section and in each pinhole.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs an internet-facing interface: IPv6 is taken from the provider there (SLAAC and DHCPv6 with prefix delegation). |
| `lan_zones` | list of zones | automatic | The zones that get a /64 of the delegated prefix. Each must exist, have an interface, not face the internet, and not be excluded (below). Without the key: every zone with an interface that does not face the internet and is not excluded. |
| `ula_prefix` | IPv6 /48 | random | A unique local /48 in `fd00::/8` (RFC 4193). `fd00::/48` is refused: the global ID must be random. |
| `pinholes` | list | `[]` | Inbound IPv6 openings to LAN hosts. See below. |

**Exclusion.** A zone can't have IPv6 while a forward `drop` or `reject`
rule that touches it names only IPv4 addresses: over IPv6 the same hosts
would get around it. Block such a host by `src_mac`, or name its IPv6
networks in the rule too.

Each pinhole:

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `name` | name | required | Unique among pinholes. |
| `zone` | zone | required | A LAN zone of this configuration. |
| `host` | IPv6 address | required | A global unicast address (`2000::/3`), or an interface identifier such as `::5054:ff:fe12:3456`, which follows the provider's prefix when it changes. Not `::`, not `::1` (the router), not a reserved anycast identifier. |
| `proto` | `tcp` or `udp` | required | |
| `port` | port spec | required | At most 1000 ports in one pinhole. |
| `from` | IPv6 network | anywhere | Only this source network. Can't be a unique local, link-local or multicast network. |

A pinhole is refused while a forward `drop`/`reject` rule from the
internet would match its traffic, because pinholes are evaluated before
the rules and the rule would silently stop holding.

## management

```yaml
management:
  zones: [lan]
  allow_wan: false
  confirm_apply_seconds: 300
  addresses: [10.73.1.1]
  ipv6: false
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `zones` | list of zones | automatic | Where the web console (443) and SSH (22) are reachable. Default: every zone that does not face the internet. An internet-facing zone needs `allow_wan`. Duplicates are merged. |
| `allow_wan` | bool | `false` | Allows internet-facing zones in `zones`; with `zones` empty, opens management from every zone. Not recommended: use the VPN. |
| `confirm_apply_seconds` | int | `300` | `0` (no confirmation) or 60 to 3600. How long an apply from the console waits for confirmation. |
| `addresses` | list of IPv4 addresses | all | The addresses the console and SSH listen on. Each must be on an interface of a management zone or on the VPN tunnel; a change that would remove one is refused. Move them with **System → webUI address**. |
| `ipv6` | bool | `false` | Management over IPv6 too. Refused while an input `drop`/`reject` rule on ports 22 or 443 names only IPv4 addresses for a zone managed over IPv6. |

## logging

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `drops` | bool | `true` | Log packets dropped by the default policy, in both chains. |
| `drops_per_minute` | int | `10` | 1 to 10000. The rate limit of that log. |

## wireguard

```yaml
wireguard:
  enabled: true
  listen_port: 51820
  address: 10.99.0.1/24
  zone: vpn
  endpoint: vpn.example.org
  peers:
    - {name: phone, public_key: "<44-character key>", address: 10.99.0.2/32, dual_stack: true}
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs `address`. |
| `listen_port` | port | `51820` | UDP. Open from anywhere: WireGuard answers nothing to unknown keys. |
| `address` | IPv4 interface | none | The router's tunnel address, with a prefix of /30 or wider. Not the network or broadcast address. Must not overlap any interface's network. |
| `zone` | zone | `vpn` | The tunnel's zone. Must be declared, and must not face the internet. |
| `endpoint` | hostname | none | The name or address clients connect to; written into their configuration. |
| `peers` | list | `[]` | See below. Peers need `address`. |
| `private_key` | | | **Refused.** The router keeps its private key itself, outside `config.yaml`. |

Each peer:

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `name` | string | required | 1 to 32 letters, digits, `_`, `.`, `-`, starting with a letter or digit. Unique. |
| `public_key` | string | required | A WireGuard key: 44 characters of base64 ending in `=`. Unique. |
| `address` | IPv4 /32 | required | A free host address in the tunnel network, not the router's. Unique. |
| `dual_stack` | bool | `false` | Set by the console when the peer's client configuration was issued with its IPv6 tunnel address as well. With IPv6 on, a peer without it is offered a re-issued configuration. |

## ztna

```yaml
ztna:
  enabled: true
  session_ttl_seconds: 28800
  users:
    - {username: alice, password_hash: "<set by the console>"}
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs at least one user. |
| `session_ttl_seconds` | int | `28800` (8 hours) | 60 to 2592000 (30 days). How long a sign-in at the gate lasts. |
| `users` | list | `[]` | `username`: 1 to 64 letters, digits, `_`, `.`, `-`, starting with a letter or digit, unique. `password_hash`: set by the console; never write a password here. |

Rules with `require_ztna: true` match only sources signed in at the gate.

## adblocker

The router's own DNS resolver (a dnsmasq instance) and its blocklists.

```yaml
adblocker:
  enabled: true
  serve_lan: true
  force_dns: true
  query_logging: true
  source_urls: [https://example.org/hosts.txt]
  categories:
    malware: [https://example.org/malware.txt]
  allowlist: [example.com]
  xdp_critical_limit: 0
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs `source_urls` or `categories`. |
| `source_urls` | list of URLs | `[]` | `http://` or `https://`. The base list (the `ads` category). |
| `categories` | mapping | `{}` | Category name to a non-empty list of URLs. `ads` is reserved for `source_urls`. |
| `allowlist` | list of domains | `[]` | Domains never blocked, with at least one dot. Stored in lower case. |
| `serve_lan` | bool | `false` | Serve DNS to the DHCP zones. Needs at least one DHCP pool. |
| `force_dns` | bool | `false` | Redirect plain DNS from clients to the router and reject DNS over TLS (853). Needs `serve_lan`. |
| `query_logging` | bool | `false` | Write the resolver's query log, which application identification and AI-IDS read. |
| `xdp_critical_limit` | int | `0` | 0 or more. With the XDP SNI filter on, this many names from the downloaded blocklist are also blocked on the XDP path (names too long for the kernel filter are left out and reported). 0: none. |

The lists are downloaded by `firewall-cli adblock-refresh` on a timer and
from the console. This is one of the few things in FR_OS that reaches the
internet, and only to the URLs you list.

## local_dns

Names the router's resolver answers itself. Needs `adblocker.enabled` and
`adblocker.serve_lan`. Unknown keys are refused.

```yaml
local_dns:
  domain: home.arpa
  hosts: {nas.home.arpa: 10.73.1.10}
  overrides: {printer.example.com: 10.73.1.20}
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `domain` | hostname | none | The local domain. A single label must be one of `corp`, `home`, `internal`, `intranet`, `lan`, `localdomain`, `private`; otherwise use a domain of your own (such as `home.arpa`). |
| `hosts` | mapping | `{}` | Name (at least two labels) to IPv4 address. |
| `overrides` | mapping | `{}` | Name to IPv4 address, answered instead of the real one. |

A name can't be both a host and an override, there are at most 1024
entries in all, and no name may overlap the names of a blocked
application.

## app_control

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | |
| `blocked_apps` | list of app ids | `[]` | Ids from the built-in catalogue, each once. Needs `adblocker.enabled` and `adblocker.serve_lan`: apps are blocked by the resolver. |
| `block_via_xdp` | bool | `false` | Also drop the apps' TLS connections on the XDP path. Needs `xdp_sni_filter.enabled`. |
| `observe_sni` | bool | `false` | Use TLS server names seen by the XDP program for attribution. Needs `xdp_sni_filter.enabled`. |

## xdp_sni_filter

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs `interfaces`. |
| `interfaces` | list of interface names | `[]` | Names from `interfaces` (not devices). Usually the LAN side, where clients' handshakes arrive. |
| `blocklist` | list of hostnames | `[]` | Each **under 32 bytes**, the kernel program's limit; a longer name is refused rather than silently not blocked. A trailing dot is dropped, letters are stored in lower case. |

## tls_fingerprint

Needs `xdp_sni_filter.enabled`: the XDP program hands over the
ClientHellos.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | |
| `blocklist` | list | `[]` | Each entry a string (the fingerprint) or `{fingerprint, label}`. A fingerprint is a JA4 (`t13d1516h2_8daaf6152771_e5627efa2ab1`) or a 32-hex-digit JA3 hash, stored in lower case, each once. `label`: at most 80 characters. |
| `quarantine_on_match` | bool | `false` | Quarantine a host whose fingerprint is on the blocklist. |

## iot

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Needs `zones`. |
| `zones` | list of zones | `[]` | Where to look for devices. Not a zone NAT masquerades out of. Duplicates are merged. |
| `auto_isolate` | bool | `false` | Isolate every device the scan classifies as IoT. |
| `isolation_mode` | `internet_only` or `block` | `internet_only` | `internet_only`: DHCP, DNS and the zones NAT masquerades out of. `block`: DHCP and DNS from the router only. `internet_only` needs a `nat.masquerade` entry. |
| `trusted_macs` | list of MACs | `[]` | Never isolated, not even by `auto_isolate`. |
| `isolated_macs` | list of MACs | `[]` | Always isolated. A MAC can't be both trusted and isolated. |

## ai_ids

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | |
| `excluded_macs` | list of MACs | `[]` | Never scored or quarantined. |
| `quarantine_duration_seconds` | int | `7200` (2 hours) | 1 to 604800 (7 days). |

## metrics

The Prometheus endpoint of the web console.

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `site` | string | none | A label for this router in a fleet: lower-case letters, digits, `.`, `_`, `-`, up to 63. |
| `token_sha256` | string | none | The SHA-256 of the bearer token, 64 lower-case hex digits. The token itself is never stored. |

## pqc

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | The web console becomes TLS 1.3-only (its key exchange prefers X25519MLKEM768 either way), and SSH offers `mlkem768x25519-sha256` where the installed OpenSSH supports it (9.9 and later), with classical fallback otherwise. |

## update

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `repo` | string | FR_OS's own repository | A GitHub repository, `OWNER/NAME`, to read releases from. |
| `auto_install_security` | bool | `false` | Install signed security releases automatically. |
| `kernel_updates` | bool | `true` | Offer kernel updates. |

> The update helper that installs releases arrives with a later 2.0
> phase; until then the console's **Update** screen is read-only.
