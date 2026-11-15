# Glossary

**Apply.** Making the running router match the saved configuration, as
one transaction. See [Applying changes safely](concepts/apply-and-rollback.md).

**apply-helper.** The one root service (`fr-apply-helper`) that does
privileged work, on request over a Unix socket, after checking who asks.
See [Privilege model](concepts/privilege-model.md).

**Attack surface.** Every port something on the router listens on, and
from where it can be reached. A screen of its own.

**Audit log.** The record of every sign-in and change request to the web
console, in `/var/log/fr_os/audit.log`.

**Baseline (fail-closed).** The minimal ruleset loaded when no
configuration can be applied: loopback and replies to the router's own
connections only, nothing forwarded.

**Brute-force jail.** An nftables set of sources that failed to sign in
too often; their packets to the management ports are dropped for an hour.

**ClientHello.** The first message of a TLS connection, sent in clear.
It names the server (SNI) and lists what the client supports, which is
what a TLS fingerprint is made from.

**Confirmation (held apply).** An apply that must be confirmed within a
time, or the router goes back to the configuration before it.

**conntrack.** The kernel's connection tracking table; AI-IDS samples new
connections from it.

**DGA.** Domain generation algorithm: malware that makes up domain names
to find its servers. AI-IDS looks for bursts of such names that don't
exist.

**Differential test.** A test that compares FR_OS 2's answer with the one
FR_OS 1.x recorded for the same input. See [Testing](development/testing.md).

**DNAT, port forward.** Sending connections that arrive on a port of the
router to a host inside. See [NAT](features/nat.md).

**DoH, DoT.** DNS over HTTPS, DNS over TLS: encrypted DNS that bypasses
the router's resolver unless it is blocked (`adblocker.force_dns`).

**ECH.** Encrypted Client Hello: TLS that hides the real server name. The
SNI filter sees only the outer, public name.

**Fail-closed.** Failing so that nothing gets through, rather than
everything.

**GRO.** Generic receive offload: the kernel merging segments before
processing. Turned off on a port where the XDP program runs in generic
mode.

**Internet-facing zone.** A zone that `nat.masquerade` points at, or one
named `wan`.

**IPv4-mapped IPv6 address.** An IPv6 form of an IPv4 address
(`::ffff:10.0.0.5`); never valid on the wire, so the XDP filter drops it.

**JA3, JA4.** Two standard formats of TLS client fingerprint. JA4 is
stable when a browser shuffles its extensions; JA3 is the older MD5 form.

**Management zone.** A zone from which the web console and SSH are
reachable: by default every zone that doesn't face the internet.

**Masquerade.** Outbound NAT: traffic leaving through a zone takes the
router's address there.

**mDNS.** Multicast DNS: how devices on a local network announce their
services (`_googlecast`, `_hap` for HomeKit, printers). IoT discovery
asks for it.

**nftables.** The Linux kernel's packet filter. FR_OS builds one ruleset
from the configuration and loads it atomically.

**Persistence.** The partition where a live-booted router keeps its
state across reboots.

**Pinhole.** An IPv6 rule that lets connections from the internet reach
one host and port inside. See [IPv6](features/ipv6.md).

**PQC.** Post-quantum cryptography. FR_OS offers hybrid key exchange
(X25519MLKEM768 for TLS, mlkem768x25519-sha256 for SSH).

**Quarantine.** An nftables set whose members can't reach the router or
anything through it until a timeout passes; AI-IDS and TLS fingerprinting
put hosts there.

**RA.** Router advertisement: how an IPv6 router tells devices its prefix
so they configure their own addresses (SLAAC).

**Rule check.** The check that finds rules that accept everything, are
open to the internet, are shadowed, unused or expired.

**Security alert.** An audit entry that could mean a way in, shown on
the dashboard until each admin marks it as seen.

**Segment.** A zone with its own network, usually a VLAN, with DHCP and
access to the internet only. See [Zones and segments](concepts/zones.md#segments).

**`self`.** The zone name meaning the router itself, in rules.

**Sensor.** One of the unprivileged daemons that read traffic: `fr-ai-ids`,
`fr-appid`, `fr-tls-fp`, `fr-iot-scan`, `fr-xdp-sni-logger`.

**SNI.** Server name indication: the server's name in a ClientHello.

**ULA.** Unique local address: the router's own stable IPv6 network
(`fd00::/8`), which stays the same whatever the provider gives.

**Viewer.** A read-only web console account.

**VLAN.** A virtual network on one cable, told apart by a tag (802.1Q).

**WebAuthn.** The standard behind security keys and passkeys; a
phishing-resistant second factor.

**XDP.** eXpress Data Path: running a program in the network driver,
before the kernel's network stack. FR_OS's SNI filter is an XDP program.

**Zone.** A named part of the network (`lan`, `wan`, `iot`), the unit
rules are written between. See [Zones and segments](concepts/zones.md).

**ZTNA.** Zero trust network access: a rule that matches only devices
whose user signed in at the gate. See [ZTNA gate](features/ztna.md).
