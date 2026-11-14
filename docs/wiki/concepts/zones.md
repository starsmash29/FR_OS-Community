# Zones and segments

FR_OS's policy is written between **zones**, not between ports or
addresses. This page explains zones, how interfaces and VLANs join them,
and the exact order in which the firewall decides what happens to a
packet.

## Zones

A zone is a named group of networks that you trust the same way. Typical
zones:

| Zone | What is in it |
| --- | --- |
| `wan` | The upstream network: your ISP, the internet |
| `lan` | Your own computers and phones |
| `iot` | Cameras, speakers, smart plugs, TVs |
| `guest` | Visitors' devices |
| `dmz` | A server you expose to the internet |
| `vpn` | Remote devices connected over WireGuard |

Zones are declared under `zones:` and only exist to be referred to:

```yaml
zones:
  wan: {description: Upstream}
  lan: {description: Our computers}
  iot: {}
```

Rules:

- a zone name is required to be used: a declared zone that no interface
  (and no VPN tunnel) is in is refused, because a rule for it could never
  match;
- the name `self` is reserved: it means **the router itself**, and is used
  only as a rule's destination (`to_zone: self`).

A zone **faces the internet** when NAT masquerades out of it
(`nat.masquerade[].out_zone`), and a zone named `wan` always does. Several
defaults follow from that: the management ports are closed there, and IPv6
takes its prefix from there and never hands one out there. The IoT
"internet only" isolation means "only the zones NAT masquerades out of".

## Interfaces

An interface puts one network device into one zone:

```yaml
interfaces:
  wan: {device: enp1s0, zone: wan}
  lan: {device: enp2s0, zone: lan, address: 10.73.1.1/24}
```

- `device` is the Linux device name. A device can be in only one
  interface.
- `address` is the router's own IPv4 address and prefix on that network.
  The WAN normally has none: it gets its address by DHCP.
- A zone can have several interfaces: two ports can both be `lan`.

### VLANs

A VLAN interface is a tagged sub-interface of a physical port. It lets one
cable carry several zones to a VLAN-capable switch or access point:

```yaml
interfaces:
  lan:   {device: enp2s0, zone: lan, address: 10.73.1.1/24}
  iot:   {device: enp2s0.30, zone: iot, address: 192.168.30.1/24,
          vlan: {parent: enp2s0, id: 30}}
  guest: {device: enp2s0.40, zone: guest, address: 192.168.40.1/24,
          vlan: {parent: enp2s0, id: 40}}
```

The VLAN id is 1 to 4094, and a VLAN can't be its own parent. The
**Segments** screen in the web console writes exactly this for an IoT and
a guest segment, with their DHCP pools and rules, in one step.

### The VPN zone

The WireGuard tunnel (`wg0`) is not listed under `interfaces`; it joins
the zone named in `wireguard.zone`, and that zone counts as used.

## How a packet is decided

nftables sees a packet in one of two chains:

- **input**, when it is addressed to the router itself (`to_zone: self`);
- **forward**, when the router passes it from one zone to another.

Both chains have a **default policy of drop**: what nothing accepts is
dropped. The output chain (what the router itself sends) accepts.

Your rules are evaluated **in the order they are written**, and the first
rule that matches with `accept`, `drop` or `reject` decides. But before
your rules, FR_OS puts guards that no rule can override. This is the
order, top to bottom:

### Input chain (to the router)

1. Sources in the **brute-force jail** and the **IDS quarantine** are
   dropped.
2. Packets from **isolated IoT devices** are limited to DHCP and DNS.
3. Loopback is accepted.
4. The **IPv6** essentials for the WAN and LAN (neighbour discovery,
   router advertisements, DHCPv6 replies, needed ICMPv6) are accepted.
5. **Scheduled block rules that cut existing connections** are checked.
6. Packets of **established and related** connections are accepted;
   **invalid** ones are dropped.
7. **DNS** to the router is accepted from the zones its resolver serves.
8. The **management ports** (22 and 443) are dropped from every zone that
   is not a management zone.
9. The **WireGuard** port is accepted, from anywhere. WireGuard answers
   nothing to a packet that is not from a known key, so the port looks
   closed.
10. **Your rules** with `to_zone: self`, in order.
11. Everything else is logged (rate-limited) and dropped.

### Forward chain (between zones)

1. IPv6 is allowed only between the WAN and the LAN zones that have it,
   and only from a LAN host's own network; unique local addresses never
   cross the border.
2. Sources in the **IDS quarantine** are dropped.
3. On ports the XDP SNI filter watches, QUIC (UDP 443) is rejected so
   that browsers fall back to TLS over TCP, where the filter can see the
   server name.
4. **Isolated IoT devices** are held to their isolation (internet only,
   or nothing). Only `iot.trusted_macs` are exempt.
5. **Scheduled block rules that cut existing connections** are checked.
6. **Established and related** connections are accepted; **invalid** ones
   dropped.
7. **IPv6 pinholes** are accepted; nothing else new from the internet
   reaches the LAN over IPv6.
8. With forced DNS, **DNS over TLS** (port 853) is rejected so clients fall
   back to the router's resolver.
9. **Your rules** with any other `to_zone`, in order.
10. Everything else is logged (rate-limited) and dropped.

Because established connections are accepted early, a rule decides when a
connection **starts**. To end connections that are already open when a
scheduled block begins, give that rule `cut_established: true` (see the
schedules section in the rule reference).

## Writing rules

A rule names its zones, what it matches and what to do:

```yaml
rules:
  - name: lan-to-internet
    action: accept
    from_zone: lan
    to_zone: wan

  - name: webui-from-lan
    action: accept
    from_zone: lan
    to_zone: self
    proto: tcp
    dst_port: 443

  - name: no-tablet-on-school-nights
    action: reject
    from_zone: lan
    to_zone: wan
    src_mac: aa:bb:cc:dd:ee:ff
    schedule: {days: [weekdays], start: "21:30", end: "06:30", cut_established: true}
```

| Field | Meaning |
| --- | --- |
| `name` | Required and unique. It appears in logs and hit counters. |
| `action` | `accept`, `drop` (silently) or `reject` (with an error back to the sender). |
| `from_zone` | The source zone. Omit it for any zone. Can't be `self`. |
| `to_zone` | The destination zone, `self` for the router, or omit it for any. |
| `proto` | `any` (the default), `tcp`, `udp` or `icmp`. |
| `dst_port` | A port (`443`) or a range (`1000-2000`). Needs `tcp` or `udp`. |
| `src_address`, `dst_address` | One network or a list, IPv4 or IPv6. If both are given they must share an address family. |
| `src_mac` | Match one source MAC address. |
| `log` | Log every packet the rule matches. |
| `require_ztna` | Match only sources that have signed in at the ZTNA gate. |
| `schedule` | Days and a time window when the rule applies. |
| `expires` | A date and time after which the rule stops matching. The expiry is checked in the kernel, so it is exact without a new apply. |

The full reference for every field and its validation rule is in the
[configuration reference](../reference/configuration.md#rules), and
[Firewall rules and schedules](../features/firewall-rules.md) shows them
at work.

### Good habits

- **Allow what is needed; let the default drop the rest.** A rule that
  accepts any zone to any zone is flagged by the security checklist.
- **Put specific rules above general ones.** A rule that can never match,
  because an earlier one already decides every packet it would, is
  reported as **shadowed**.
- **A port forward needs a rule.** `nat.port_forwards` rewrites the
  destination; a forward rule from the incoming zone to the inside host
  must still accept it.
- **Address-only rules and IPv6.** A rule that names only IPv4 addresses
  does not match the same host's IPv6 traffic. With IPv6 on, write the
  IPv6 networks into the rule too, or match by zone or MAC address.

## Segments

A **segment** is a zone with its own network: a VLAN, a subnet, a DHCP pool
and rules. Segmenting is the most effective single thing you can do on a
home or office network: a compromised camera in `iot` can't reach a laptop
in `lan` if no rule allows it.

The **Segments** screen creates two ready-made segments on the LAN port:

| Segment | VLAN | Network | DHCP pool |
| --- | --- | --- | --- |
| `iot` | 30 | `192.168.30.1/24` | `.100` to `.199` |
| `guest` | 40 | `192.168.40.1/24` | `.100` to `.199` |

Each segment gets one rule, from the segment to each zone that faces the
internet, and nothing else: it can't reach the LAN, the other segment or
the router's console. Its DHCP pool hands out `1.1.1.1` and `9.9.9.9` as
DNS servers. If the management zones were left to their default, the
screen pins them to the zones you had before, so a new segment never
becomes a management zone. Adding the `iot` segment also turns on IoT
discovery there.

If your network gear can't tag VLANs, **IoT isolation** is the
alternative: FR_OS discovers IoT devices on the LAN and holds each one to
internet-only (or nothing) by its MAC address, from inside the same zone.
It acts on traffic that passes through the router; it can't stop two
devices on the same switch from talking to each other directly, which only
a separate segment can.
