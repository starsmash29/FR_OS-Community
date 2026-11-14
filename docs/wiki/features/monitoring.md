# Monitoring and logs

FR_OS tells you what it is doing in four places: the **dashboard**, a
**Prometheus** endpoint for your own monitoring, the **logs** of dropped
traffic and of rules you mark, and the **audit log** of every admin
action. All of it stays on the router unless you fetch it yourself.

## The dashboard

The dashboard is the first screen after sign-in. Next to the apply
buttons it shows:

- **Security alerts**: events every admin should see, such as a new VPN
  device. Each admin sees them until they click that they have seen them.
- Whether the saved `config.yaml` passes validation.
- **The security score**, with a link to its checklist (one of its checks
  is the rule check, below).
- **Protection services**: which of the filtering and detection features
  are on.
- **System resources** and uptime, and the **Interfaces** with their
  addresses.
- **Recently dropped**: the latest 50 packets the default policy dropped
  and logged, read from the kernel's journal.

## Prometheus metrics

The web console serves Prometheus metrics at `https://<router>/metrics`.
It is **off until you create a token**: without one, the endpoint answers
404.

1. On the **System** screen, card **Multi-site monitoring**, click
   **Generate token**. The token is shown **once**; copy it. Only its
   SHA-256 is saved (`metrics.token_sha256`), never the token itself.
2. Optionally set a **site name** (`metrics.site`), the label that tells
   your routers apart in a fleet dashboard. The default is the host name.
3. Point Prometheus at the router with the token as a bearer token.

```yaml
# prometheus.yml on your monitoring server
scrape_configs:
  - job_name: fr_os
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/fr_os.token
    tls_config:
      ca_file: /etc/prometheus/fr_os-cert.pem   # from the System screen's download link
    static_configs:
      - targets: ["10.73.1.1:443"]
```

A request without the right token gets 401. The check is strict on
purpose: a stored digest that is malformed denies every request, and a
`config.yaml` that doesn't validate never turns the endpoint public.
**Replace token** makes a new one (the old one stops working); **Remove
token** turns the endpoint off again.

The endpoint is part of the web console, so it is reachable only from the
[management zones](../reference/configuration.md#management). The answer
is cached for 15 seconds; a configuration change shows at once.

### What it reports

| Metric | What |
| --- | --- |
| `fros_info` | Constant 1; labels `site_name`, `hostname`, `version`, `codename` |
| `fros_config_valid` | 1 if `config.yaml` on disk passes validation |
| `fros_interface_bytes_total` | Bytes per interface and direction |
| `fros_xdp_status` | The [XDP SNI filter](xdp-sni-filter.md) per interface: 0 off, 1 native, 2 generic |
| `fros_xdp_blocked_connections_total` | Connections the XDP filter dropped for a blocked name |
| `fros_adblock_total_domains` | Names in the resolver's block list |
| `fros_dns_blocked_domains` | Names loaded per blocklist category |
| `fros_app_active_clients`, `fros_app_hits_24h`, `fros_app_blocked` | [Application control](app-control.md): clients per app in the last 15 minutes, hits in 24 hours, blocked apps |
| `fros_tls_fingerprinted_clients`, `fros_tls_distinct_fingerprints`, `fros_tls_fingerprint_events_24h` | [TLS fingerprints](tls-fingerprints.md) |
| `fros_iot_devices`, `fros_iot_isolated_devices` | [IoT discovery](iot.md): devices by classification, devices isolated |
| `fros_ztna_active_sessions` | Devices signed in at the [ZTNA gate](ztna.md) |
| `fros_bruteforce_banned_ips` | Sources in the brute-force jail |
| `fros_ai_ids_quarantined_hosts` | Hosts in [AI-IDS](ai-ids.md) quarantine |
| `fros_hw_cpu_*`, `fros_hw_ram_*`, `fros_hw_storage_*` | CPU model, use and clock; RAM modules, use and size; mounts, use and size |

A metric whose source can't be read at that moment is left out of the
answer rather than reported as zero.

## Logs of dropped traffic

With `logging.drops: true` (the default), every packet the **default
policy** drops, in the input and the forward chain, is logged to the
kernel log with the prefix `fr_os/drop/input: ` or `fr_os/drop/forward: `,
at most `logging.drops_per_minute` (default 10) per minute, so a flood
can't fill the disk.

```yaml
logging:
  drops: true
  drops_per_minute: 10
```

On the router's console:

```bash
journalctl -k -g 'fr_os/drop/'           # all logged drops
journalctl -k -g 'fr_os/drop/forward' -f # follow drops between zones
```

The journal keeps at most 200 MB and 90 days.

### Logging one rule

Give a rule `log: true` and every packet it matches is logged with the
prefix `fr_os/<rule name>: `:

```yaml
rules:
  - {name: ssh-from-vpn, action: accept, from_zone: vpn, to_zone: self, proto: tcp, dst_port: 22, log: true}
```

```bash
journalctl -k -g 'fr_os/ssh-from-vpn:'
```

A logged rule is not rate-limited: use it to watch a rule for a while, not
on a rule that matches heavy traffic.

## Rule hit counters and the rule check

Every rule has a counter in the kernel. Once an hour the router records
which rules matched, and the **rule check** on the **Rules** screen
(also part of the dashboard's security score) uses that record together with the rules themselves. It
reports:

- an accept rule that matches everything;
- a rule open to the whole internet;
- a rule that an earlier rule shadows, or makes redundant;
- a rule that has matched nothing for 90 days;
- a temporary rule whose date has passed.

The check is careful about "shadowed": it never calls a rule shadowed
when it isn't, but it can miss one that is shadowed only by a combination
of rules. Adding a rule on the Rules screen tells you at once if the new
rule trips the check.

## The audit log

Every sign-in and every change request to the web console is recorded:
who, when, from where, which action, and the outcome. **Form contents are
never recorded**, so no password or key ends up in the log. The latest
200 entries are on the **Users** screen.

The log is `/var/log/fr_os/audit.log`, owned by root. The web console can
read it, but adds to it only through the apply-helper, which appends one
line at a time: a compromised console could add lines, but not rewrite
the ones that show what it did.

## Logs of the other services

Each service logs to the system journal under its own unit:

| Unit | What |
| --- | --- |
| `fr-firewall` | The boot's fail-closed apply |
| `fr-apply-helper` | Every privileged action |
| `fr-webui` | The web console |
| `fr-adblock-dns`, `fr-adblock-refresh` | The resolver and the blocklist downloads |
| `fr-xdp-sni-logger` | The XDP filter's events (also in `/var/log/fr_os-sni/events.jsonl`) |
| `fr-ai-ids`, `fr-appid`, `fr-tls-fp`, `fr-iot-scan` | The sensor daemons |
| `fr-schedule-check` | The hourly schedule check and rule hit record |

```bash
journalctl -u fr-apply-helper --since today
```

## Limits

- There is no built-in long-term history: the dashboard shows now, the
  journal keeps 90 days. For graphs over months, scrape the metrics.
- Metrics and logs never leave the router on their own. There is no
  remote syslog or push; your monitoring server fetches what it needs.

See [`logging`](../reference/configuration.md#logging) and
[`metrics`](../reference/configuration.md#metrics) in the configuration
reference.
