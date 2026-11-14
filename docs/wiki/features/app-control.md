# Application control

Application control answers two questions: **which apps does each client
use**, and **can I stop one**. It works from names the router can see
(DNS lookups and, optionally, TLS server names), matched against a
built-in catalogue. It never decrypts anything.

## The catalogue

FR_OS ships a catalogue of 41 applications, generated from the community
project [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)
(MIT), in these categories:

| Category | Examples |
| --- | --- |
| Messaging | WhatsApp, Telegram, Signal, Messenger, Discord |
| Social | Instagram, Facebook, TikTok, Reddit, Snapchat, LinkedIn |
| Streaming | Netflix, YouTube, Disney+, Prime Video, Twitch |
| Music | Spotify, Deezer |
| Gaming | Steam, Epic Games, Roblox, Xbox, PlayStation, Nintendo |
| Conferencing | Zoom, Webex |
| Storage | Dropbox, OneDrive, iCloud |
| Remote access | TeamViewer |
| AI | ChatGPT / OpenAI |

Each application is a list of domains (matched with their subdomains) and
exact names. The **Applications** screen lists them all.

## Seeing app use

`fr-appid` (unprivileged, `fr_os-sensor`) follows:

- the resolver's query log, so it needs the [DNS resolver](dns-filtering.md)
  with `query_logging: true`;
- with `observe_sni: true`, the TLS server names the
  [XDP SNI filter](xdp-sni-filter.md) reports.

It attributes each name a client looks up to an application and keeps a
count per client and application. The **Applications** screen shows which
clients used which apps recently.

## Blocking an app

```yaml
app_control:
  enabled: true
  blocked_apps: [tiktok, roblox]
  block_via_xdp: true
```

- The resolver answers "no such name" for every name of a blocked app.
  This needs `adblocker.enabled` and `adblocker.serve_lan`.
- With `block_via_xdp: true`, the app's names are also added to the XDP
  filter's blocklist, so a client that knows an address and connects over
  TLS is stopped too. This needs `xdp_sni_filter.enabled`.

Turn on `adblocker.force_dns` too, so clients can't simply ask another
resolver. The block applies to every client the resolver serves.

## Limits

- Attribution sees **names**, not content. An app that shares a CDN with
  others, or uses Encrypted Client Hello and DoH, can be missed or
  attributed to its CDN.
- Blocking by name stops new lookups; connections that are already open
  run until they close.
- The catalogue is what it is: an app not in it can still be blocked by
  adding its domains to a DNS blocklist or to `xdp_sni_filter.blocklist`.
