# Frequently asked questions

## About FR_OS

**What is FR_OS?**
An open-source firewall and router for x86-64 PCs and virtual machines:
Debian underneath, an nftables firewall with zones, DHCP, IPv6, a
WireGuard VPN, DNS filtering, and traffic sensors (an XDP filter, TLS
fingerprints, application identification, IoT discovery, AI-IDS), run
from a web console. See [What FR_OS is](getting-started/what-is-fr-os.md).

**Is it free?**
Yes. FR_OS Community is free software under the GNU AGPLv3: every feature
in this documentation is in it.

**Does it send anything to the internet?**
Not by itself. No telemetry, no cloud service, no account with anyone.
What reaches the internet is what you turn on: the blocklists you choose,
the release check when you open the Update screen, the updates you
install. See [Security model](security/index.md#100-local).

**Is "AI-IDS" a language model in the cloud?**
No. It is statistics running on the router: each device is compared with
its own recent behaviour, and every verdict comes with the numbers behind
it. Nothing leaves the router. See [AI-IDS](features/ai-ids.md).

**Is FR_OS unhackable? Does it make me compliant?**
No software is unhackable, and FR_OS doesn't claim to be. It is built to
make an attack hard and visible: see the [security model](security/index.md).
Using FR_OS does not by itself make you compliant with any law or
standard.

**How does FR_OS 2 relate to FR_OS 1.x?**
FR_OS 2 is a rewrite in Go and Rust of the Python FR_OS 1.x. It is held
to 1.x's recorded behaviour on about 23,000 test cases, so the firewall
does the same thing, with memory-safe parsers and no Python on the
router. The configuration file and the web console's account file keep
1.x's formats. See [Testing](development/testing.md).

## Hardware and installation

**What hardware do I need?**
An x86-64 machine with at least two network ports (or one port and VLANs),
2 GB of memory and a USB stick or disk. See [Hardware](getting-started/hardware.md).

**Does it run on a Raspberry Pi or other ARM boards?**
Not in this version: the image is x86-64 only.

**Can I run it in a virtual machine?**
Yes. Give the VM two network interfaces. A VM's virtual CD is read-only,
so add a small disk for persistence: `firewall-cli persistence create`.

**Does it support Secure Boot?**
Not yet: the image is not signed for Secure Boot. Turn Secure Boot off in
the firmware.

**My provider uses PPPoE, or gives me a static address.**
This version's WAN takes its address by DHCP only. Behind a provider's
router that does PPPoE, connect FR_OS to that router's LAN.

**Do I have to keep the USB stick in?**
Yes, for a live system: it boots from the stick and keeps its state in
the persistence partition on it. See [Installation](getting-started/installation.md).

## Using it

**I changed something and nothing happened.**
Most screens save to the configuration; click **Apply now** on the
dashboard to load it. See [Save, then apply](web-console/index.md#save-then-apply).

**I locked myself out with a rule.**
Wait: an apply is held for confirmation (300 seconds by default) and goes
back by itself when nobody confirms it. A reboot reverts it too. See
[Backup and recovery](operations/backup-and-recovery.md).

**How do I manage the router from outside?**
Through the [WireGuard VPN](features/wireguard.md). Opening the web
console to the internet is possible but not recommended.

**I forgot the admin password.**
On the router as root: `firewall-cli set-admin-password --username NAME`.

**Can others look without changing anything?**
Yes: give them a **viewer** account on the Users screen.

**Why can't I add my security key?**
Browsers allow security keys only on a host name, not an IP address. Open
the router by its name (`https://fr-router.lan/`), or use an
authenticator app.

**Does the XDP filter replace DNS filtering?**
No, they work together. DNS filtering stops the lookup; the XDP filter
stops a TLS connection to a blocked name even when the client found the
address another way. Neither sees inside encrypted traffic, and Encrypted
Client Hello hides the real name from both.

**Does FR_OS decrypt my traffic?**
No. Every feature works from what is visible without decryption: DNS
names, TLS server names, the shape of a ClientHello, connection metadata.

**Can I edit config.yaml by hand?**
Yes, as root. Run `firewall-cli validate` after every edit, then apply.
See [The configuration file](concepts/configuration-file.md) and the
[configuration reference](reference/configuration.md).

## The project

**Who makes FR_OS?**
Its maintainer, with an AI coding agent that implements and reviews the
work; nothing is merged without the maintainer's approval. Every change is tested as described
in [Testing](development/testing.md).

**Can I contribute?**
Not yet; contributions open after the first release. Bug reports and
ideas are welcome as issues, and security problems are reported privately
([SECURITY.md](../../SECURITY.md)).

**Is there a commercial edition?**
FR_OS Enterprise is a separate commercial edition (see
[LEGAL.md](../../LEGAL.md)). This documentation covers Community.
