# System screens

The **System** section of the sidebar: Update, System, Attack surface,
Security score and Users (Users is on
[Signing in and accounts](accounts.md#users-screen-admins-only)).

## Update

> **Status.** In this version the Update screen shows and checks, but
> does not install. Installing a release, rolling back and trying a new
> kernel go through the update-helper, which arrives with a later 2.0
> phase; until then those buttons answer *Not ported to FR_OS 2 yet*.

| Card | Contents |
| --- | --- |
| **Version** | The installed version and codename, and the latest release of the repository in `update.repo` (FR_OS's own by default). Opening the screen asks GitHub for it over HTTPS: the only page of the console that contacts an outside server. |
| **Security updates** | When the router last checked, and **Install security updates automatically** (`update.auto_install_security`): only releases marked as security releases, only after their signature verifies. |
| **Kernel** | The kernel's update state, and **Fetch Debian's kernel fixes daily** (`update.kernel_updates`). A new kernel is only made ready; trying it reboots the router into it once, and the router keeps it only if it comes up with the firewall, its ports and the console working. |
| **Rollback** | The version that ran before, if one is recorded. |
| **Last update attempt** | What the last update or rollback did, and its result. |

Every release is checked against the release signature
(`SHA256SUMS.sig`) and the public key the router ships with. See
[Updates](../operations/updates.md).

## System

### Post-quantum key exchange

The state of the hybrid key exchange for the console's HTTPS and for SSH:

| Check | Meaning |
| --- | --- |
| Host OpenSSL supports X25519MLKEM768 | Needs OpenSSL 3.5 or later. |
| Last applied TLS group preference, hybrid group applied | What the console was started with. |
| Installed sshd supports mlkem768x25519-sha256 | Needs OpenSSH 9.9 or later. |
| Hybrid KexAlgorithms drop-in active | Whether SSH uses it now. |

**Enable PQC hybrid key exchange** (`pqc.enabled`) makes the console TLS
1.3-only and offers the hybrid algorithms; a client or a build that
doesn't know them falls back to the classical ones, so nothing breaks.
The TLS preference takes effect after an apply and a restart of
`fr-webui`, because OpenSSL reads it once, at start.

### Management access

Where the console and SSH listen and from which zones they are reachable,
the zones the firewall drops them from whatever the rules say, and advice
on reaching the router through the VPN. **Allow management from the
internet (WAN)** (`management.allow_wan`) is the explicit, not
recommended way to open them to the internet; it raises a security alert.

### webUI address

The addresses the console and SSH listen on, besides the router itself
(`management.addresses`). Only this card moves them: a change elsewhere
that would take one of these addresses away is refused. **Move the
webUI** applies the change at once and holds it: confirm it **from the
new address** within the confirmation time, or the router goes back.

### Over IPv6

**Also over IPv6 (stable address)** (`management.ipv6`) makes the
console and SSH listen on the router's stable (ULA) IPv6 address of each
management zone, never on the provider's public addresses.

### Software integrity

Will compare FR_OS's own files with the signed release they came from.
FR_OS 2 keeps no list of its files' hashes yet, so the card says *not
verifiable*, and the security score counts the item as unknown.

### Storage and persistence

Whether the router runs from its own disk (*installed*), live with
persistence (*persistent*: settings, passwords and leases survive
reboots), or live **without** persistence (every change is lost at the
next reboot), and the boot medium. See
[Installation](../getting-started/installation.md#persistence).

### Multi-site monitoring

The Prometheus endpoint: **Generate token** (shown once), **Replace
token**, **Remove token**, the **Site name**, and the console's
certificate to download, with its SHA-256 fingerprint. See
[Monitoring and logs](../features/monitoring.md#prometheus-metrics).

## Attack surface

Every port something on the router listens on, and from which zone the
firewall lets a new connection reach it, worked out from what runs now
and the saved configuration. Anything reachable from an internet-facing
zone comes first, with a warning.

| Column | Meaning |
| --- | --- |
| Port, Service | What listens. |
| Needed by | The feature that needs it, or *not needed*: something nothing in the configuration needs. Stop or remove it. |
| Bound to | The addresses it listens on (*loopback* is reachable from no zone). |
| One column per zone | **open** (any host in the zone can connect), **restricted** (only some: by source address, device, ZTNA sign-in or time of day; hover for the rule), **closed** (the input chain drops it), or *-* (the service is not bound to an address in that zone). |

**Check it from the outside**: this view reads the router's own
configuration and can't see what your provider or an upstream router
does, and it does not list port forwards (those are on the NAT screen).
To see what the internet sees, scan the WAN address from outside your
network, for example:

```console
$ nmap -Pn -sS -sU --top-ports 1000 <WAN address>
```

## Security score

The hardening checklist, checked against this router. Each item links to
the screen that fixes it; an item that can't be known right now is
*unknown* and doesn't count either way.

| Check | Passes when |
| --- | --- |
| No default account names | No account is named `admin`, `administrator`, `root`, `user`, `fr_os` or `fros`. |
| A second factor for every admin | Every admin has a security key or an authenticator app. |
| Management closed to the internet | `management.allow_wan` is off. |
| Up to date | The installed release is the latest. |
| Security updates install themselves | `update.auto_install_security` is on. |
| No any-to-any, internet-wide or shadowed rules | The rule check finds none. |
| Firewall drops are logged | `logging.drops` is on. |
| Devices are segmented | IoT isolation is on, or an `iot` or `guest` zone exists (the Segments screen). |
| Nothing unneeded listens | The attack surface shows no unneeded service. |
| FR_OS's own files are intact | Unknown in this version (see Software integrity). |

The percentage is the share of the known items that pass. The dashboard
shows it too.
