# WireGuard VPN

The VPN lets your phone or laptop reach your network from anywhere, as if
it were at home: the web console, a file server, a camera. It is
[WireGuard](https://www.wireguard.com/): one key pair per device, nothing
to answer for anyone without a key, and a tunnel that survives roaming
between networks.

## Turn it on

```yaml
zones:
  wan: {}
  lan: {}
  vpn: {}

wireguard:
  enabled: true
  listen_port: 51820
  address: 10.99.0.1/24       # the router's tunnel address; the tunnel network
  zone: vpn
  endpoint: vpn.example.org   # what devices connect to: your public name or address
```

Or on the **VPN** screen: set the router's tunnel address and the address
devices reach the router at, tick **VPN on**, click **Save settings** and
then **Apply**. Turning it on there also declares the `vpn` zone and adds
the rules `webui-from-vpn`, `ssh-from-vpn` and `vpn-to-lan` if they are
missing. The first apply with the VPN on makes the
router's key pair.

The tunnel's zone (`vpn` by default) must be declared and must not face
the internet. Like any zone, it reaches nothing until a rule says so,
except the web console and SSH: by default every zone that does not face
the internet is a [management zone](../reference/configuration.md#management).

```yaml
rules:
  - {name: vpn-to-lan, action: accept, from_zone: vpn, to_zone: lan}
```

The UDP port (`listen_port`) is open from anywhere. That is safe:
WireGuard answers nothing to a packet that isn't signed with a key it
knows, so a scanner can't even tell the port is in use.

If your provider gives you a new public address now and then, use a
dynamic DNS name as the `endpoint`. Behind your provider's own router,
forward the UDP port to FR_OS there.

## Adding a device

Under **Add a device** on the **VPN** screen, give the device a name and click **Add device**.
FR_OS:

1. generates a new key pair for the device;
2. picks the first free address in the tunnel network (`10.99.0.2/32`,
   then `.3`, ...);
3. adds the device to `wireguard.peers` and saves the config;
4. shows the device's configuration once, as text and as a QR code for the
   WireGuard app.

The device's **private key is on that page and nowhere else**: it is not
in `config.yaml`, not in a log, and the page is sent with `no-store` so
the browser doesn't cache it. Scan it or copy it before you leave the
page. If you lose it, remove the device and add it again.

Then click **Apply** to load the new peer.

Adding a device is recorded as a security alert, which the dashboard shows
to every admin until they have seen it: a new VPN key is a new way into
your network.

### Split or full tunnel

| Choice | What the device sends through the tunnel |
| --- | --- |
| Split (default) | Only your networks: the tunnel network and the networks of every zone that does not face the internet (and their stable IPv6 networks, see below). Everything else goes out directly. |
| Full tunnel | Everything (`0.0.0.0/0, ::/0`). The device's internet traffic goes through your router, and so through its DNS filtering. |

A full tunnel also needs a rule from the VPN zone to the internet, and
masquerading:

```yaml
nat:
  masquerade:
    - {out_zone: wan}

rules:
  - {name: vpn-to-internet, action: accept, from_zone: vpn, to_zone: wan}
```

### A device with its own key

If you'd rather generate the key on the device, paste its **public** key
in **Its public key** when you add it. FR_OS then stores the public key and the address and
shows no configuration: write it on the device yourself, with the router's
public key from the VPN screen.

### Removing a device

**Remove** next to the device, then **Apply**. Its key no longer works
from that apply on.

## The router's key

The router's private key is in `/etc/fr_os/wireguard/private.key` (mode
0600, in a 0700 directory), generated on the first apply that needs it.
It is never in `config.yaml`: a `wireguard.private_key` key is refused.
The tunnel is configured with `wg syncconf` from standard input, so the
key never appears on a command line other users could read.

## IPv6 through the tunnel

When [IPv6](ipv6.md) is on, the router gives the tunnel a stable
(ULA) IPv6 network too, and a device added from then on gets an IPv6
tunnel address in its configuration (`dual_stack: true`); a full-tunnel
configuration also carries `::/0`. Through the tunnel it can reach the
router and the LAN's stable addresses over IPv6; anything else over IPv6
that arrives in the tunnel is refused, never routed on.

A device added before the tunnel had IPv6, or with its own key, is marked
**No IPv6 in its configuration**. If that device uses a full tunnel, its
IPv6 traffic still goes *around* the tunnel, in the clear on whatever
network it is on. Remove it and add it again for a new configuration (with
a new key: the old private key was never stored), or add the IPv6 address
the screen shows to `Address` and `::/0` to `AllowedIPs` on the device.
Its old configuration keeps working until then.

When IPv6 is off, or the VPN zone gets no IPv6, the VPN screen says so in
words, and devices use IPv4 through the tunnel.

## Checking it

The **VPN** screen shows whether the tunnel is up, the router's public
key, and for each device its addresses, the start of its key, its latest
handshake and the address it was last seen from. A device that has never
completed a handshake has the wrong endpoint, the wrong router key, or a
UDP port that doesn't reach the router.

## Limits

- One tunnel interface (`wg0`), IPv4 tunnel addressing with an optional
  IPv6 network on top.
- The router does not run as a WireGuard client to another server.
- The router's address must be reachable from outside: behind carrier-grade
  NAT, without a public address, devices can't reach it.

See [`wireguard`](../reference/configuration.md#wireguard) in the
configuration reference for every key.
