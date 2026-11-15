# IPv6

FR_OS takes IPv6 from your provider on the WAN and passes it on to your
LAN zones, with the same default-deny stance as IPv4: nothing new comes in
from the internet unless you open a pinhole.

```yaml
ipv6:
  enabled: true
```

That is usually all it takes.

## On the WAN

`dhcpcd` (`fr-dhcp6.service`) runs on the WAN device, IPv6 only:

- it takes an address by **SLAAC** from the provider's router
  advertisements, with stable addresses that don't carry the MAC
  (RFC 7217);
- it asks by **DHCPv6** for an address and a **delegated prefix**;
- it reads router advertisements on the WAN only, never on a LAN;
- it sends no host name and runs no hook script, so nothing the provider
  sends is written to the router's own files.

The kernel never handles router advertisements itself, and never makes a
SLAAC address of its own. From boot on, `/etc/sysctl.d/50-fr_os-ipv6.conf`
turns `accept_ra` and `autoconf` off on every interface, so only dhcpcd's
stable addresses appear on the WAN.

`ipv6.enabled` needs an internet-facing interface: a zone NAT masquerades
out of, or a zone named `wan`.

## On the LAN

Each LAN zone gets one **/64** of the delegated prefix. A dnsmasq instance
that does only router advertisements (`fr-ra.service`, under its own
dynamic user) announces it, and clients configure themselves by SLAAC.
There is no DHCPv6 server on the LAN. When the prefix changes, the
advertisements follow it.

**Which zones get IPv6.** With `lan_zones` left out: every zone with an
interface that does not face the internet, except those an IPv4-only
block rule touches (below). Name them yourself with `lan_zones: [lan, iot]`.

**Unique local addresses.** Once the provider has delegated a prefix, the
router also gives each LAN zone a stable /64 from a unique local /48 (`ula_prefix`, random unless you set one). On
the zones its resolver serves, the router's ULA address is announced as
the DNS server, so local DNS keeps working when the provider's prefix
changes. ULA traffic never crosses the internet border.

## The IPv4 trap, closed

A rule such as "drop everything from 10.73.1.50" says nothing about the
same device's IPv6 addresses, which it picks itself. FR_OS refuses to give
IPv6 to a zone while a forward `drop` or `reject` rule that touches it
names only IPv4 addresses, and the console says which rule and why. Fix it
by matching the device with `src_mac`, or by adding its IPv6 networks to
the rule.

The same reasoning applies elsewhere:

- the brute-force jail and the IDS quarantine hold an IPv6 host by its MAC
  address, so moving within its /64 doesn't get it out;
- `management.ipv6` (management over IPv6) is refused while an input rule
  blocks the management ports by IPv4 address only.

## Pinholes

Every LAN host with IPv6 has a global address, so there is no port
forwarding: you open a pinhole to the host instead.

```yaml
ipv6:
  enabled: true
  pinholes:
    - name: nas-https
      zone: lan
      host: "::5054:ff:fe12:3456"   # interface identifier: follows the prefix
      proto: tcp
      port: 443
      from: 2001:db8:42::/48        # optional: only from this network
```

- `host` is either a full global address, or just the **interface
  identifier** (the last 64 bits, written `::...`). The identifier form
  keeps working when the provider changes your prefix.
- `port` is a port or a range, at most 1000 ports.
- A pinhole is refused if a `drop`/`reject` rule from the internet would
  match the same traffic, because pinholes are checked before the rules
  and the rule would silently stop holding.

## In the web console

**Interfaces** has the IPv6 settings and shows the IPv6 status the router
has now (read through the apply-helper): addresses, the delegated prefix,
and which zones were left out and why.

## Check it

```console
# ip -6 addr
# ip -6 route
# journalctl -u fr-dhcp6 -n 50
```
