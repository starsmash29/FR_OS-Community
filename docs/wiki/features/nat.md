# NAT and port forwards

## Masquerade

Masquerade lets every device behind the router share the router's address
on the upstream network. It is what makes a home network reach the
internet:

```yaml
nat:
  masquerade:
    - {out_zone: wan}
```

Traffic leaving through `out_zone` gets the router's address there as its
source. A zone named in `masquerade` **faces the internet**, which changes
several defaults (management is closed there, IPv6 takes its prefix from
there, IoT "internet only" isolation means this zone).

Masquerade does not allow anything by itself: a forward rule must still
accept the traffic (`lan` to `wan`, for example).

## Port forwards

A port forward sends connections that arrive at the router on a port to a
host inside:

```yaml
nat:
  port_forwards:
    - name: home-server-https
      in_zone: wan
      proto: tcp
      dst_port: 443
      to_address: 10.73.1.10
      to_port: 443

rules:
  - name: allow-home-server-https
    action: accept
    from_zone: wan
    to_zone: lan
    proto: tcp
    dst_port: 443
    dst_address: 10.73.1.10
```

- The forward rewrites the destination before the filter sees it, so the
  rule matches the **inside** address and port (`to_address`, `to_port`).
- **The rule is required.** Without it, the forward chain's default drop
  stops the connection after the rewrite.
- `to_port` defaults to `dst_port`.
- Port forwards are IPv4. For IPv6, where every host has its own global
  address, use an [IPv6 pinhole](ipv6.md#pinholes) instead.

In the web console, **NAT** lists the masquerade zones and the port
forwards, and adds and removes them.

## Before you open a port

- Put the server in a zone of its own (a `dmz`), so a compromised server
  can't reach the LAN.
- Forward only the ports the service needs.
- Narrow the rule to known sources with `src_address` where you can.
- Prefer the [WireGuard VPN](wireguard.md) for anything that only you use.
