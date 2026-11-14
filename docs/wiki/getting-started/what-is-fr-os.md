# What FR_OS is

FR_OS turns an x86-64 computer with two or more network ports into a
firewall and router. It sits between your upstream connection (an ISP
modem, an office uplink, another router) and your own networks, and
decides what may pass between them.

It is built on Debian Linux. The packet filtering is the Linux kernel's
own: nftables for the stateful policy and NAT, and an eBPF/XDP program for
early filtering at the network driver. Everything FR_OS adds on top (the
configuration, the web console, the privileged helper and the traffic
sensors) is written in Go and Rust and published under the GNU AGPLv3.

## What it does

**Routing and firewalling**

- Splits your network into zones (for example `wan`, `lan`, `iot`,
  `guest`) and enforces which zone may reach which, with a default-deny
  policy.
- NAT masquerade towards the internet and port forwards inward.
- VLANs on a physical port, so one cable can carry several zones.
- DHCP for IPv4 (Kea) with fixed reservations by MAC address.
- IPv6 on the WAN (SLAAC and DHCPv6 prefix delegation) and on the LAN
  (router advertisements), with IPv6 pinholes for chosen inbound services.
- Rules that apply only at given times, or expire on a date.

**Remote access**

- A WireGuard VPN with one key pair per device, dual-stack if you want,
  with the client configuration shown as a QR code.
- A zero-trust gate (ZTNA): a zone can require a sign-in before it is
  reachable, and the access expires on its own.

**Seeing and controlling traffic**

- A local DNS resolver with blocklist categories and allowlists, local
  host names, and optional forced DNS so clients cannot go around it.
- Application identification from DNS lookups and TLS server names, and
  application blocking by name.
- An XDP filter that drops TLS connections to blocked server names at the
  network driver, before the rest of the network stack runs.
- A TLS client fingerprint inventory (JA3 and JA4) per device, with alerts
  and an optional blocklist.
- IoT device discovery with a score and the reasons for it, and isolation
  to internet-only or no access at all.
- AI-IDS: a local anomaly detector that learns each device's normal
  behaviour and can quarantine a host that suddenly behaves differently.

**Managing the router**

- An HTTPS web console with administrator and viewer accounts, TOTP and
  WebAuthn security keys, and a forced password change on first sign-in.
- Every change validated, applied as one transaction, and optionally held
  until you confirm it; unconfirmed changes revert on their own.
- A security checklist and an attack-surface view of what is listening
  and from where it is reachable.
- An opt-in Prometheus endpoint, rule hit counters, drop logs, and an
  activity log of who changed what.

## Who it is for

- **Home labs and enthusiasts** who want a firewall they can read end to
  end and run on hardware they already have.
- **Families** who want to keep IoT devices away from laptops, give
  guests their own network, and put a schedule on a child's tablet.
- **Small offices** that need zones, a VPN, DNS filtering and a clear
  record of changes, without a subscription.
- **Developers and security people** who want to study or extend a
  firewall whose privileged code is small and whose behaviour is pinned by
  tests.

## What it is not

Being clear about limits is part of running a firewall well.

- **It is not a TLS-inspecting proxy.** FR_OS never decrypts traffic and
  never installs a certificate on your clients. Application control, the
  XDP filter and TLS fingerprints read only what is visible on the wire:
  DNS questions, the server name in a ClientHello, and the shape of the
  handshake. Encrypted DNS and Encrypted Client Hello hide those.
- **It is not a signature-based IDS.** AI-IDS compares a device with its
  own past behaviour and scores domain names; it does not ship a catalogue
  of attack signatures. "AI" here means local statistics, not a language
  model, and nothing is sent anywhere.
- **It is not a managed appliance.** There is no vendor cloud, no remote
  management by anyone but you, no support contract and no high-availability
  pair in FR_OS 2.0.
- **It is not unbreakable.** No firewall is. FR_OS is designed to make
  mistakes hard and attacks expensive, and to tell you what it does.
- **It is not a compliance product.** It can help you meet the network
  security parts of a framework, but using it does not by itself make you
  compliant with any law or standard.

## FR_OS 1.x and FR_OS 2

FR_OS 1.x was written in Python. FR_OS 2 is a rewrite in Go and Rust that
keeps the behaviour of 1.x: the same `config.yaml`, the same ruleset, the
same files, the same web console. That is not a promise on paper; it is
tested against about 23,000 cases recorded from 1.x (see
[Architecture](../concepts/architecture.md#tested-against-fr_os-1x)).
Where FR_OS 2 does something differently on purpose, the decision is
written down in
[`testdata/reference/decisions.md`](../../../testdata/reference/decisions.md).
