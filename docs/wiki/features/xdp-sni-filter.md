# XDP SNI filter

When a browser opens an HTTPS connection, its first message (the TLS
**ClientHello**) names the server it wants in clear text: the *server
name indication*, SNI. The XDP SNI filter reads that name **in the network
driver**, before the Linux network stack has done any work on the packet,
and drops the connection if the name is blocked.

It is an eBPF/XDP program written in Rust with [aya](https://aya-rs.dev),
verified by the kernel when it loads.

## Turn it on

```yaml
xdp_sni_filter:
  enabled: true
  interfaces: [lan]          # interface names from 'interfaces', not devices
  blocklist:
    - example-tracker.com
    - badsite.example
```

Put it on the interfaces where **clients' handshakes arrive**: the LAN
side. On the WAN it would see only inbound connections.

## What it matches

- A blocked name also blocks its **subdomains**, on a label boundary:
  `example.com` blocks `www.example.com` but not `notexample.com`. (The
  names are kept reversed in an LPM trie, so the longest match wins.)
- Names are compared in lower case, with a trailing dot ignored.
- **Each name must be under 32 bytes**, the kernel program's limit. A longer
  name is refused by the configuration rather than silently not blocked.

Other sources add names to the kernel's list at apply time, in memory
only: up to `adblocker.xdp_critical_limit` names from the downloaded DNS
blocklist, and the names of blocked applications with
`app_control.block_via_xdp`. Names from those that are too long for the
kernel are left out, and the apply says which.

## What it handles

- Ethernet with up to two VLAN tags (802.1Q and 802.1ad);
- IPv4 and IPv6, TCP to port 443;
- a ClientHello whose name is not in its first TCP segment: a second
  program follows the handshake through the next in-order segments,
  keeping only where it is in the extension list per flow;
- hostile shapes: a segment out of order is dropped until it comes in
  order, one with a bad TCP checksum is dropped before it is read, and a
  handshake it can't follow (too many segments, too slow, a jumbo segment)
  is dropped rather than let through. TCP fragments, IPv6 extension headers
  it won't walk to their end, and IPv4-mapped IPv6 addresses are dropped.

On the ports it watches, FR_OS also **rejects QUIC** (UDP 443), so
browsers fall back to TLS over TCP, where the name is visible.

## Native and generic mode

The program attaches in **native** mode (in the driver) where the driver
supports it, and in **generic** mode otherwise. Generic mode runs after the
kernel's GRO merges segments, so FR_OS turns GRO off on a port in generic
mode, to see each segment as sent; it turns it back on when the filter
leaves the port.

## Events and the live log

Every drop is reported on a ring buffer. `fr-xdp-sni-logger` writes them
to `/var/log/fr_os-sni/events.jsonl`, which the **TLS SNI Filter** screen
streams live and which [AI-IDS](ai-ids.md) counts per host. The program also
hands copies of ClientHellos to [TLS fingerprinting](tls-fingerprints.md).
Counters (packets seen, hellos parsed, drops and their reasons) are on the
same screen and in the [metrics](monitoring.md).

## Limits

- **Encrypted Client Hello** hides the real name; the filter sees only the
  outer, public name.
- A ClientHello **spread over several TLS records** is not followed.
- It filters TLS on TCP port 443. Other ports and protocols pass.

## Tested in the kernel

The program is tested by running it in the kernel (`BPF_PROG_TEST_RUN`) on
thousands of recorded frames: ClientHellos for every name shape, cut at
every byte, behind VLAN tags, IPv4 options and fragments, IPv6 extension
headers, split over segments in and out of order, with bad checksums and
random damage. Every frame must get the same verdict, move the same
counters and leave the same state as FR_OS 1.x's C program did.
