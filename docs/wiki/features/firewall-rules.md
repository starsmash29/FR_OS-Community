# Firewall rules and schedules

Rules decide which traffic may pass between zones and to the router
itself. Read [Zones and segments](../concepts/zones.md) first: it explains
the chains, the built-in guards and the order in which rules are checked.

## The basics

```yaml
rules:
  - {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
  - {name: dns-only-for-iot, action: accept, from_zone: iot, to_zone: self, proto: udp, dst_port: 53}
  - {name: block-bad-net, action: drop, from_zone: lan, to_zone: wan, dst_address: [203.0.113.0/24, 2001:db8:66::/48]}
```

- Rules are checked **in order**; the first that matches decides.
- `to_zone: self` means the router itself; any other `to_zone` (or none)
  is traffic the router forwards.
- What no rule accepts is dropped, and logged at a limited rate.
- `drop` is silent; `reject` answers with an error, so the client gives up
  at once instead of waiting.

In the web console, **Rules** lists the rules in order. You can add, move
up and down, and delete rules there, and remove every expired rule in one
step.

## Matching

| To match | Use |
| --- | --- |
| A zone pair | `from_zone`, `to_zone` |
| A protocol and port | `proto: tcp` or `udp` with `dst_port: 443` or `"8000-8100"`; `proto: icmp` for ping |
| Addresses | `src_address`, `dst_address`: one network or a list, IPv4 and IPv6 mixed |
| One device | `src_mac`. Works over IPv4 and IPv6, because a device picks its own IPv6 addresses but keeps its MAC |
| Signed-in users | `require_ztna: true`: only sources that signed in at the [ZTNA gate](ztna.md) |
| Logging | `log: true` logs every packet the rule matches |

## Schedules

A rule with a `schedule` applies only in its window:

```yaml
- name: kids-tablet-bedtime
  action: reject
  from_zone: lan
  to_zone: wan
  src_mac: aa:bb:cc:dd:ee:ff
  schedule:
    days: [weekdays]
    start: "21:30"
    end: "06:30"
    cut_established: true
```

- **Days** are `mon` to `sun`, or the groups `weekdays`, `weekend` and
  `daily`.
- **Times** are `"HH:MM"`, always quoted. An `end` earlier than `start`
  runs over midnight, as above. `00:00` to `24:00` is the whole day.
- **The time zone** is the configuration's `timezone`, or the router's
  own. The console's **Rules** screen sets it.
- **`cut_established`** (for `drop` and `reject` rules): connections that
  are already open when the window starts are cut too. Without it, a video
  call started at 21:29 would go on past 21:30, because established
  connections are accepted before the rules are checked.

**How it works.** The kernel compares times in UTC. FR_OS converts each
local window to UTC with the time zone's current offset, splits it where
either clock crosses midnight, and loads it as nftables `meta day` and
`meta hour` matches. `firewall-cli schedule-check` runs every hour (at two
minutes past) and re-applies when the offset changes, so windows stay right
across daylight-saving changes. The rule is enforced by the kernel itself;
nothing has to run at 21:30.

## Expiry

```yaml
- name: contractor-access
  action: accept
  from_zone: vpn
  to_zone: lan
  dst_address: 10.73.1.10
  expires: "2026-12-31T18:00"
```

After `expires`, the rule no longer matches. The check is in the kernel
(`meta time`), so it is exact to the second without a new apply. An expiry
without a UTC offset is read in the configuration's time zone. Expired
rules stay in the file until you remove them (**Rules → Remove expired**).

## Hit counters

Every rule carries an nftables counter. The hourly schedule check records
them, and the **Rules** screen shows how often each rule matched. A rule
that has never matched may be shadowed by an earlier one, or simply not
needed.

## What the console checks for you

The **Security score** screen flags:

- **any-to-any** rules: `accept` with no zones, no addresses and no port;
- **internet-wide** rules: `accept` from an internet-facing zone to
  anything without narrowing it down;
- **shadowed** rules: rules that can never match, because an earlier rule
  already decides every packet they would.

## Limits

- Rules match on zones, addresses, MACs, protocols and ports. They don't
  match on host names; use [DNS filtering](dns-filtering.md),
  [application control](app-control.md) or the
  [XDP SNI filter](xdp-sni-filter.md) for names.
- A rule that names only IPv4 addresses does not match the same host's
  IPv6 traffic. With IPv6 on, a zone touched by such a `drop`/`reject` rule
  is not given IPv6 at all (see [IPv6](ipv6.md)).
- The management ports (22, 443) can't be opened by a rule from a zone
  that isn't a management zone; see the
  [privilege model](../concepts/privilege-model.md#management-access).

## Check it

```console
# firewall-cli render | less        # the full nftables script
# nft list chain inet fr_os forward  # what the kernel has now, with counters
```
