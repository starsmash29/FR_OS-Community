# DNS filtering and local names

FR_OS can run its own DNS resolver for your network (a dedicated dnsmasq
instance, `fr-adblock-dns.service`). It answers your clients, refuses
names on the blocklists you choose, serves your own local names, and,
if you want, keeps a log that application identification and AI-IDS use.

## Turn it on

```yaml
adblocker:
  enabled: true
  serve_lan: true
  source_urls:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
  categories:
    malware: [https://urlhaus.abuse.ch/downloads/hostfile/]
    phishing: [https://phishing.army/download/phishing_army_blocklist.txt]
  allowlist: [example.com]
  force_dns: true
  query_logging: true

dhcp:
  lan:
    # ...
    dns_servers: [10.73.1.1]   # the router itself
```

| Key | What it does |
| --- | --- |
| `enabled` | Runs the resolver with the blocklists. Needs at least one list. |
| `serve_lan` | Serves DNS to the DHCP zones (it listens there, and the firewall lets DNS in from them). Needs a DHCP pool. |
| `source_urls` | The base list (the `ads` category). |
| `categories` | More lists by name. |
| `allowlist` | Domains never blocked, even when a list has them. |
| `force_dns` | Redirects every plain DNS query from those zones to the router, whatever server the client asked, and rejects DNS over TLS (port 853) so clients fall back. Needs `serve_lan`. |
| `query_logging` | Writes `/var/log/fr_os-dns/queries.log`, which [application control](app-control.md) and [AI-IDS](ai-ids.md) read. Trimmed every hour when it grows past its size limit. |

Set the DHCP pool's `dns_servers` to the router's own address, so clients
use the resolver without needing `force_dns`.

## Categories in the console

The **Ad-Block** screen offers ready-made categories, each with its
source and its terms:

| Category | Source |
| --- | --- |
| Malware distribution sites | abuse.ch URLhaus host file |
| Phishing | Phishing Army (CC BY-NC 4.0: non-commercial use only) |
| Public DNS-over-HTTPS resolvers | dibdot/DoH-IP-blocklists. Stops browsers and apps from going around the resolver over DoH |
| Gambling, Adult content, Social networks, Fake news | StevenBlack/hosts extensions |

The base list defaults to StevenBlack/hosts. Check each list's licence
for your use; FR_OS only downloads what you select.

## Downloading the lists

The lists are downloaded by `firewall-cli adblock-refresh`:

- every night at 04:15, with up to 30 minutes of random delay
  (`fr-adblock-refresh.timer`);
- when you press **Refresh now** on the Ad-Block screen (the apply-helper
  does the download; the web console never writes there itself).

This is one of the few things in FR_OS that reaches the internet, only to
the URLs you list, and only while the resolver is on.

## Local names

```yaml
local_dns:
  domain: home.arpa
  hosts:
    nas.home.arpa: 10.73.1.10
    printer.home.arpa: 10.73.1.20
  overrides:
    intranet.example.com: 10.73.1.30
```

- `hosts` are your own names. Everything else under `domain` that isn't a
  host answers "no such name", so it never leaks to the internet.
- `overrides` answer instead of the real record, for a public name that
  should point inside.
- A single-label `domain` must be a private one (`lan`, `home`,
  `internal`, `corp`, `intranet`, `localdomain`, `private`); `home.arpa`
  (RFC 8375) is the standard choice.
- At most 1024 names in all. Local names need the resolver (`enabled` and
  `serve_lan`), and none may overlap a blocked application's names.

## Limits

- **DNS over HTTPS and encrypted DNS.** A client that uses DoH talks HTTPS
  to its resolver, which the router can't tell from other HTTPS. The
  "Public DNS-over-HTTPS resolvers" category blocks the well-known DoH
  names, and `force_dns` handles plain DNS and DNS over TLS; an app with
  its own hard-coded DoH server can still go around.
- **Blocking a name blocks lookups, not connections.** A client that
  already knows an address, or uses a hard-coded one, isn't stopped by DNS.
  The [XDP SNI filter](xdp-sni-filter.md) stops TLS connections by name.

## Check it

```console
$ dig @10.73.1.1 doubleclick.net      # blocked: 0.0.0.0 or no answer
$ dig @10.73.1.1 nas.home.arpa         # your local name
```

```console
# journalctl -u fr-adblock-dns -n 50
# journalctl -u fr-adblock-refresh -n 50
```
