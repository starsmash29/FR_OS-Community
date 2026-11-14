# DHCP

FR_OS hands out IPv4 addresses with **Kea**, one pool per zone.

```yaml
interfaces:
  lan: {device: enp2s0, zone: lan, address: 10.73.1.1/24}

dhcp:
  lan:
    range_start: 10.73.1.100
    range_end: 10.73.1.199
    dns_servers: [10.73.1.1]
    lease_time: 3600
    reservations:
      - {mac: "aa:bb:cc:dd:ee:ff", address: 10.73.1.10, hostname: nas}
```

## Requirements

- The zone has **exactly one interface**, and that interface has a static
  `address`. The router's address is the clients' gateway.
- The range lies inside that network and does not contain the router's
  address; `range_start` is not after `range_end`.
- `dns_servers` is not empty. Point it at the router's LAN address when the
  router's own resolver serves the LAN (see
  [DNS filtering](dns-filtering.md)); otherwise at public resolvers.
  First boot and the segments use `1.1.1.1` and `9.9.9.9`.

## Reservations

A reservation always gives one device the same address, by its MAC. The
address must be inside the network (it may be inside or outside the
range), and each MAC and each address appears once. Reserve addresses for
servers, printers and anything a rule names by address.

Devices that randomise their MAC address per network (most phones and
laptops do by default) get a new MAC, and so a new lease, on each
network. Turn that off on the device for the networks where a reservation
should apply.

## In the web console

**DHCP** shows each pool and its reservations, and edits them. The
active leases are what [IoT discovery](iot.md) starts from.

## Check it

```console
# journalctl -u kea-dhcp4-server -n 50
```

The preflight of every apply checks the generated Kea configuration with
`kea-dhcp4 -t`, so a pool that Kea would refuse never reaches the running
system.
