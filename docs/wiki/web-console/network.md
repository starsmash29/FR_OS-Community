# Network screens

The **Network** section of the sidebar: Interfaces, Segments, Rules, NAT,
DHCP and VPN. Each screen saves to `config.yaml`; click **Apply now** on
the dashboard to load the change.

## Interfaces

**Interfaces** lists the configured interfaces (name, device, zone,
address) with **Edit** and **Delete**.

**Add interface** / **Edit interface**:

| Field | Meaning |
| --- | --- |
| **Name** | The interface's name in the config, used by other sections (`dhcp`, `xdp_sni_filter.interfaces`). |
| **Device** | The Linux network device: `enp2s0`, or a VLAN such as `enp2s0.30`. |
| **Zone** | The zone it belongs to. |
| **Static address** | Optional, in CIDR form (`10.0.0.1/24`). The router's own address on that network; a DHCP pool needs one. The WAN port usually has none: it gets its address from the provider by DHCP. |

**IPv6** explains what the router does with IPv6 and shows what it has
now: the default route, the delegated prefix, the stable (ULA) networks
and the pinholes. **Take IPv6 from the provider** turns `ipv6.enabled`
on or off. See [IPv6](../features/ipv6.md).

**Detected network interfaces** lists every port the kernel sees, with
its driver, MAC address and link: use it to find the device name of a
port.

## Segments

Keep smart devices and guests off your own network in one step. The
screen offers two segments, each a VLAN on the LAN port:

| Segment | VLAN | Network | Device |
| --- | --- | --- | --- |
| IoT devices (`iot`) | 30 | `192.168.30.1/24` | `<LAN port>.30` |
| Guests (`guest`) | 40 | `192.168.40.1/24` | `<LAN port>.40` |

Tick the ones you want and click **Add the ticked segments**. For each,
FR_OS adds the zone, the VLAN interface, a DHCP pool (`.100` to `.199`,
with public DNS servers) and a rule to the internet, and nothing towards
your LAN or the router's management: the management zones are pinned so
the new segment does not become one. The IoT segment is also added to
[IoT discovery](../features/iot.md), with discovery turned on.

Then set your access point to put the IoT and guest Wi-Fi on VLAN 30 and
40, or use a VLAN-capable switch. The first sign-in brings you here once;
**Skip for now** leaves it for later. See
[Zones and segments](../concepts/zones.md#segments).

## Rules

**Firewall rules** are evaluated in order, first match wins. `self` as a
zone means the router itself.

### The rule check

At the top, the [rule check](../features/monitoring.md#rule-hit-counters-and-the-rule-check)
lists any rule that accepts everything, is open to the whole internet, is
shadowed or made redundant by an earlier rule, has not matched for 90
days, or has expired. **Remove expired rules** deletes the expired
temporary rules in one click.

### The rule list

| Column | Meaning |
| --- | --- |
| Name, Action, From, To, Proto, Port | The rule. An empty zone is *any*. |
| Source MAC | A device, by its hardware address, whatever address DHCP gave it. |
| Schedule | The days and time window; *active now* or *inactive*; *cuts open connections* when it also ends connections opened before the window. *always* without one. |
| Expires | The time a temporary rule stops applying; *expired* afterwards. |
| Last match | When the rule last matched, from the hourly hit record. |
| Log, ZTNA | Whether matches are logged, and whether the rule needs a [ZTNA](../features/ztna.md) sign-in. |
| Order | ▲ and ▼ move the rule up or down. |

Scheduled drop and reject rules that cut open connections are evaluated
before all other rules, whatever their place in the list.

### Add rule

| Field | Notes |
| --- | --- |
| **Name** | Unique. |
| **Action** | `accept`, `drop` (silently) or `reject` (with an answer). |
| **From zone**, **To zone** | Blank is any zone; `self` is the router. |
| **Protocol** | `any`, `tcp`, `udp` or `icmp`. |
| **Destination port** | tcp and udp only: a port, or a range such as `1000-2000`. |
| **Source address**, **Destination address** | Optional, CIDR, IPv4 or IPv6, several separated by commas. |
| **Source MAC address** | Optional, `aa:bb:cc:dd:ee:ff`. |
| **Schedule** | Optional. Tick days (none ticked is every day) and set **From** and **Until**; an end before the start runs past midnight (`22:00`–`06:00`). **Also cut connections opened before the window starts** applies to drop and reject rules. |
| **Expires** | Optional: a temporary rule, in the schedule time zone. The kernel stops applying it at that moment, without an apply. |
| **Log matches** | Log every packet the rule matches. |
| **Require ZTNA** | Match only sources signed in at the ZTNA gate. |

After **Add rule**, the screen says at once if the new rule trips the rule
check.

### Schedule time zone

Rule schedules use this IANA time zone (`Europe/Budapest`, for example;
empty is the router's system time zone). The screen shows the router's
time now. Daylight-saving changes are picked up within the hour by
`fr-schedule-check.timer`.

See [Firewall rules and schedules](../features/firewall-rules.md).

## NAT

| Card | Add with | Notes |
| --- | --- | --- |
| **Masquerade (outbound NAT)** | **Out zone** | Traffic leaving through that zone takes the router's address. A zone named here faces the internet. |
| **Port forwards (inbound DNAT)** | **Name**, **In zone**, **Protocol** (tcp or udp), **Destination port**, **Forward to address**, **Forward to port** (blank: the same port) | Each forward is listed with **Delete**. |

See [NAT and port forwards](../features/nat.md).

## DHCP

Only a zone with exactly one interface that has a static address can
serve DHCP; set that up on the Interfaces screen first. Each eligible
zone has a card:

| Field | Notes |
| --- | --- |
| **Range start**, **Range end** | The pool, inside the interface's network. |
| **DNS servers** | Comma-separated. With the router's resolver serving the LAN, clients get the router instead and these become its upstreams. |
| **Lease time** | In seconds. |

**Enable DHCP** (or **Save**) and **Disable DHCP on this zone**.

**Reservations** give a device a fixed address: **MAC address**,
**Address**, optional **Hostname**, then **Add reservation**; each has
**Delete**.

See [DHCP](../features/dhcp.md).

## VPN

The WireGuard VPN, with its state (on or off, tunnel up or down, number
of devices, UDP port, what happens to IPv6 in the tunnel).

**Settings**: **VPN on**, **Router's address in the tunnel**, **UDP
port**, and **Address devices reach the router at** (your public address
or a DNS name). **Save settings**. Turning it on also adds the `vpn` zone
and, if they are missing, three rules: `webui-from-vpn` (TCP 443 to the
router), `ssh-from-vpn` (TCP 22 to the router) and `vpn-to-lan` (when a `lan` zone
exists). Change them on the Rules screen.

**Devices** lists each device: name, tunnel addresses, the start of its
public key, its last handshake and where from, and **Remove**. A device
marked **No IPv6 in its configuration** needs a new configuration if it
uses a full tunnel; the screen explains how.

**Add a device**: a **Name**, optionally **Its public key** (leave it
empty and the router makes the key pair), and **Send all its traffic
through the VPN** for a full tunnel. The next page is the only copy of the
device's configuration and private key, as a QR code for the WireGuard
app and as text.

See [WireGuard VPN](../features/wireguard.md).
