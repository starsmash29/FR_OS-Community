# The configuration file

Everything FR_OS does follows from one file: `/etc/fr_os/config.yaml`.
The web console reads and writes it, `firewall-cli` validates and applies
it, and the router boots from it. There is no hidden database.

## Where it lives and who can read it

| | |
| --- | --- |
| Path | `/etc/fr_os/config.yaml` |
| Owner | `root`, group `fr_os-webui`, mode `0640` |
| Written by | The web console (through the apply-helper), `firewall-cli assign-interfaces`, or you |
| Read by | The apply-helper, `firewall-cli`, the web console. The sensors read a reduced JSON view instead (`/etc/fr_os/sensor-view.json`) |

The file holds no private keys. Secrets that must be stored are stored as
hashes: ZTNA users' passwords as password hashes, and the metrics bearer
token as its SHA-256.

## A complete small example

This is close to what first boot writes, with an IoT VLAN added:

```yaml
version: 1
hostname: fr-router
timezone: Europe/Budapest

zones:
  wan: {}
  lan: {}
  iot: {description: IoT devices}

interfaces:
  wan: {device: enp1s0, zone: wan}
  lan: {device: enp2s0, zone: lan, address: 10.73.1.1/24}
  iot:
    device: enp2s0.30
    zone: iot
    address: 192.168.30.1/24
    vlan: {parent: enp2s0, id: 30}

rules:
  - {name: allow-mgmt-from-lan, action: accept, from_zone: lan, to_zone: self, proto: tcp, dst_port: 22}
  - {name: webui-from-lan, action: accept, from_zone: lan, to_zone: self, proto: tcp, dst_port: 443}
  - {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
  - {name: iot-to-wan, action: accept, from_zone: iot, to_zone: wan}

nat:
  masquerade:
    - {out_zone: wan}

dhcp:
  lan: {range_start: 10.73.1.100, range_end: 10.73.1.199, dns_servers: [1.1.1.1, 9.9.9.9]}
  iot: {range_start: 192.168.30.100, range_end: 192.168.30.199, dns_servers: [1.1.1.1, 9.9.9.9]}

management:
  zones: [lan]

iot:
  enabled: true
  zones: [lan, iot]
  auto_isolate: true
  isolation_mode: internet_only
```

## The sections

Only `version`, `hostname`, `zones` and `interfaces` are required. Every
other section is optional, and a feature whose section is missing is off.

| Section | What it configures |
| --- | --- |
| `version` | The schema version. Must be `1`. |
| `hostname` | The router's host name. Also used in the web console's certificate. |
| `timezone` | An IANA time zone name (`Europe/Budapest`). Rule schedules and expiry dates are read in it. Omit it for the system's own zone. |
| `zones` | The zones. See [Zones and segments](zones.md). |
| `interfaces` | Which device is in which zone, its address and VLAN. |
| `rules` | The firewall rules, in order. |
| `nat` | Masquerade (`masquerade`) and port forwards (`port_forwards`). |
| `dhcp` | One DHCP pool per zone, with reservations. |
| `ipv6` | IPv6 on the WAN and LAN: which LAN zones, a ULA prefix, pinholes. |
| `management` | Where the web console and SSH are reachable, and the apply confirmation time. |
| `logging` | Logging of default drops and its rate. |
| `wireguard` | The VPN: port, tunnel address, zone, endpoint and peers. |
| `ztna` | The zero-trust sign-in gate: users and session lifetime. |
| `adblocker` | The DNS resolver's blocklists, categories, allowlist, forced DNS and query logging. |
| `local_dns` | Local host names and overrides served by the resolver. |
| `app_control` | Application blocking by name. |
| `xdp_sni_filter` | The XDP SNI filter: ports and blocked names. |
| `tls_fingerprint` | TLS fingerprinting: blocklist and quarantine on match. |
| `iot` | IoT discovery and isolation. |
| `ai_ids` | The AI-IDS anomaly detector: on or off, excluded MACs, quarantine time. |
| `metrics` | The Prometheus endpoint: site label and token hash. |
| `pqc` | Hybrid post-quantum key exchange for the web console and SSH. |
| `update` | Where release information comes from, and automatic security updates. |

The [configuration reference](../reference/configuration.md) describes every key of every section, with
its type, default, limits and the exact rule it is checked against.

## How it is checked

The loader checks the whole file, top to bottom, before anything else
happens, and stops at the first problem with a message that names it.
Some things it checks across sections:

- every zone that a rule, a pool, a port forward or a feature names is
  declared, and every declared zone is used;
- a device is in only one interface;
- a DHCP pool lies inside its zone's network, and its range does not
  contain the router's own address;
- a management zone that faces the internet needs `management.allow_wan`;
- the addresses the console listens on stay reachable after the change;
- features that depend on each other are on together (for example,
  application blocking needs the DNS resolver serving the LAN, and the
  XDP options need the XDP SNI filter).

Every value that ends up on a command line, in the nftables script or in
a generated file passes through this one loader, so a value from the
configuration can never inject a command or a rule.

### YAML details worth knowing

FR_OS reads YAML exactly as FR_OS 1.x did (PyYAML's `safe_load`, YAML 1.1):

- `yes`, `no`, `on`, `off`, `true` and `false` are booleans. A zone or
  rule named `no` must be quoted: `"no"`.
- A time such as `21:30` must be quoted (`"21:30"`): unquoted, YAML 1.1
  reads it as a number in base 60.
- Keys keep the order you write them in. Rule order matters; zone and
  interface order is kept when the console rewrites the file.
- **Most unknown keys are ignored, not refused**, as in FR_OS 1.x: a
  misspelt key (`enabeld: true`) leaves its setting at the default. Check
  the result on the screen or with `firewall-cli render`. The `ipv6`
  section, its pinholes and `local_dns` are the exceptions: they refuse
  keys they don't know.

## Editing by hand

You can edit the file directly over SSH. Always validate before you
apply, and apply with a confirmation window when you are connected over
the network:

```console
# cp /etc/fr_os/config.yaml /root/config.yaml.bak
# nano /etc/fr_os/config.yaml
# firewall-cli validate
# firewall-cli apply --confirm-within 120
```

The web console rewrites the file in a normalised form when it saves, so
comments you add by hand are not kept once you save from the console.
Keep your own copy under version control if comments matter to you.
