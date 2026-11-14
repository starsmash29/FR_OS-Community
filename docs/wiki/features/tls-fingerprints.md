# TLS fingerprints

Every TLS client (a browser, an app, a piece of malware) builds its
ClientHello in its own way: which versions, cipher suites, extensions and
groups it offers, and in which order. A **fingerprint** condenses that
into a short string. FR_OS computes two standard ones:

- **JA4**, for example `t13d1516h2_8daaf6152771_e5627efa2ab1`: readable,
  stable against extension shuffling;
- **JA3**, a 32-digit MD5 hash, the older and widely published format.

A fingerprint says *what kind of client* made a connection, without
decrypting anything and without a certificate on the client.

## Turn it on

```yaml
xdp_sni_filter:
  enabled: true
  interfaces: [lan]

tls_fingerprint:
  enabled: true
  blocklist:
    - {fingerprint: t13d1516h2_8daaf6152771_e5627efa2ab1, label: example bad client}
    - 0123456789abcdef0123456789abcdef
  quarantine_on_match: true
```

TLS fingerprinting needs the [XDP SNI filter](xdp-sni-filter.md): the XDP
program on the LAN side hands over copies of the ClientHellos.

## The inventory

`fr-tls-fp` (it opens the XDP ring buffer as root, then runs as
`fr_os-sensor`) keeps, for each client address:

- every JA4 it presented, with the JA3 values that went with it (browsers
  that shuffle extensions produce several JA3 per JA4);
- a few of the server names it was used for;
- counts and first and last seen times.

The **TLS Fingerprints** screen shows it per device. The inventory is
bounded (1024 clients, 32 fingerprints each, 10,000 network-wide) so a
noisy or hostile network can't grow it without limit.

## New-fingerprint alerts

After a **24-hour learning period**, a JA4 that has never been seen on the
network before raises a "new fingerprint" event. A new browser version or
a new device also does that, so treat it as a reason to look, not a
verdict.

## Blocklist and quarantine

A ClientHello whose JA4 or JA3 is on `tls_fingerprint.blocklist` is
recorded as a match. With `quarantine_on_match: true`, the client is
quarantined through the apply-helper (the same nftables quarantine
[AI-IDS](ai-ids.md) uses), at most once every ten minutes per client.

## Limits

- Fingerprints identify **client software**, not people or intent. Many
  devices share the fingerprints of common browsers and libraries.
- Clients behind another NAT router all appear as that router's address.
- The same limits as the XDP filter apply to what is seen: TLS on TCP
  port 443, in ClientHellos the program can read.
