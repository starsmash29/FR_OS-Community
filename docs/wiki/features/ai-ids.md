# AI-IDS

AI-IDS is FR_OS's local anomaly detector. It learns what is normal **for
each device** and raises an alarm, and optionally quarantines the device,
when it suddenly behaves differently: it starts scanning, beaconing to
blocked names, or looking up random-looking domains.

"AI" here means transparent statistics running on the router. There is no
language model, no cloud service, and nothing leaves the router. Every
verdict can be explained by the numbers behind it.

## Turn it on

```yaml
ai_ids:
  enabled: true
  excluded_macs: ["aa:bb:cc:dd:ee:ff"]   # e.g. a backup server that scans on purpose
  quarantine_duration_seconds: 7200       # 2 hours (max 7 days)

adblocker:                                # the resolver, see DNS filtering
  enabled: true
  serve_lan: true
  categories:                             # feed the malware/phishing signal
    malware: [https://urlhaus.abuse.ch/downloads/hostfile/]
    phishing: [https://phishing.army/download/phishing_army_blocklist.txt]
  query_logging: true                     # for the DNS signals
```

AI-IDS works with conntrack alone; the DNS signals need the resolver's
query log, the malware/phishing signal counts answers from the ad-block
categories named exactly `malware` and `phishing`, and the SNI signal
needs the [XDP SNI filter](xdp-sni-filter.md).

## What it watches

`fr-ai-ids` (unprivileged, `fr_os-sensor`) samples new connections from
conntrack through the apply-helper every 5 seconds, follows the
resolver's query log and the XDP filter's drop events, and attributes each
to an internal host (an IPv6 host by its MAC address). For every host it
keeps six counters over a 60-second window:

| Signal | What it counts | Floor while learning |
| --- | --- | --- |
| Connection rate | New connections per second | 5 per second |
| Destination-scan pattern | Distinct destinations per connection (a scan approaches 1.0), with at least 5 connections | 0.8 |
| SNI-blocklist beacon | TLS connections the XDP filter dropped | 3 |
| NXDOMAIN burst | Distinct names that don't exist | 30 |
| DGA-like NXDOMAIN lookups | Distinct non-existent names that look machine-generated | 10 |
| Malware/phishing DNS lookups | Lookups the malware and phishing blocklists refused | 3 |

## How it decides

- **Against the device's own past.** Each window, every counter is compared
  with that host's last 30 windows. A value 3 standard deviations or more
  above its own average (a z-score of 3) is unusual for this host.
- **While it learns.** Until a host has 5 past windows, it is held to the
  fixed floors above instead, which are generous on purpose.
- **The score** of a flagged host is its highest z-score, and the event
  lists every signal that fired.

**Looking machine-generated.** Malware often finds its servers by
generating domain names (DGA). A name counts as DGA-like when the label its
owner chose (`example` in `www.example.co.uk`) is at least 10 characters,
has a character entropy of at least 3 bits, and fewer than 40% of its
letter pairs are common English pairs. One such name means nothing; a
burst of them that don't exist, from one host, is the signal.

## Quarantine

A flagged host is quarantined through the apply-helper: its address goes
into the `ids_quarantine` nftables set, which is checked before any rule in
both the input and forward chains. The host can't reach the router or
anything through it until the quarantine times out
(`quarantine_duration_seconds`) or you lift it.

Never quarantined: hosts in `excluded_macs`, and infrastructure (the
router itself, gateways and DNS servers).

The **AI IDS/IPS** screen shows the recent events, each with its score,
its signals and the counters behind them, the hosts in quarantine, and the
settings.

## Tuning

- **A device that scans on purpose** (a monitoring server, a backup
  appliance): put its MAC in `excluded_macs`.
- **Too long or too short:** change `quarantine_duration_seconds`.
- **Give it time.** The first minutes of a new device are judged against
  the floors, the first half hour builds its baseline.

## Limits

- It sees connection metadata and DNS names, not payloads. A careful
  attacker that keeps to a device's normal pattern is not flagged.
- Hosts behind another NAT router look like one host.
- An anomaly is a reason to look, not proof. Read the signals before you
  act on a device.
