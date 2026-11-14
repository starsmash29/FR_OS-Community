# First boot

The first time FR_OS starts, it sets itself up without asking anything.
This page explains each step, so you know what you are looking at on the
console and what to do when a step can't decide on its own.

First boot runs once (`fr-first-boot.service`). When it finishes, it
writes the marker file `/etc/fr_os/.first-boot-done`; on later boots it is
skipped.

## What you need upstream

In FR_OS 2.0 the WAN port takes its address **by DHCP** from the upstream
network. That is the usual case behind an ISP modem or router, or on an
office network. A PPPoE connection or a fixed WAN address with a static
gateway is not configured by FR_OS 2.0: put the ISP's modem in front of
FR_OS and let it hand out an address.

## The steps

### 1. Accounts and directories

FR_OS installs its system integration and creates its unprivileged system accounts (`fr_os-webui` for the web
console, `fr_os-sensor` for the traffic sensors, and the groups they share)
and the directories each one may write to. See the
[privilege model](../concepts/privilege-model.md).

### 2. How the WAN is found

FR_OS lists the physical Ethernet ports, then sends a DHCP request
(DHCPDISCOVER) out of each one in turn and listens for an offer:

| What it hears | What it decides |
| --- | --- |
| **Exactly one** port gets an offer | That port is the **WAN**: the upstream network hands out addresses there. The **LAN** is another port, one with a link if there is one. |
| **Several** ports get offers | **Nothing is assigned.** FR_OS will run a DHCP server on its LAN, and doing that on a network that already has one is the mistake this check exists to prevent. You assign the ports yourself (below). |
| **No** port gets an offer | The ports with a link come first, then port order. The console says plainly that this was a guess, so check the cabling. |

The decision and its reason are printed on the console and in the
first-boot log (`journalctl -u fr-first-boot`).

### 3. The LAN address

The LAN gets the first of these networks that does **not** overlap the
network the WAN's DHCP server offered:

| Choice | LAN address | DHCP pool |
| --- | --- | --- |
| 1 | `10.73.1.1/24` | `10.73.1.100` to `10.73.1.199` |
| 2 | `172.29.73.1/24` | `172.29.73.100` to `172.29.73.199` |
| 3 | `192.168.173.1/24` | `192.168.173.100` to `192.168.173.199` |

The choices are deliberately unusual, so they rarely clash with an ISP
router's own `192.168.0.0/24` or `192.168.1.0/24`. You can change the LAN
address later.

### 4. The starting configuration

FR_OS writes `/etc/fr_os/config.yaml`, a small and safe starting point:

- the WAN port in the `wan` zone and the LAN port in the `lan` zone;
- the LAN to the internet allowed, with NAT masquerade on the WAN;
- the web console (TCP 443) and SSH (TCP 22) reachable **from the LAN
  only**; nothing is open from the WAN;
- DHCP on the LAN with the pool above, handing out `1.1.1.1` and
  `9.9.9.9` as DNS servers;
- IoT discovery on the LAN, with automatic isolation to internet-only for
  devices whose score marks them as IoT devices (see the IoT page).

A DHCP client is set up on the WAN port only. On the LAN the router itself
is the DHCP server.

### 5. The administrator password

FR_OS generates a random password for an account named `admin` and shows
it **on the machine's console**, on the login screen, together with the
console's address. The password is kept in a root-only file and is never
written to the system log or to the world-readable `/etc/issue`. It
disappears from the screen as soon as it has been changed.

The first sign-in to the web console with this account is forced through
a setup step: you choose your own username and password, and the
generated ones stop working at once. See
[Your first 30 minutes](first-30-minutes.md).

### 6. The services

FR_OS enables and starts its services: the firewall, the apply-helper,
the web console, the sensors (AI-IDS, application identification, TLS
fingerprinting, the XDP event logger), the IoT scan timer, the schedule
check, the DNS query-log trim, the blocklist refresh, and the console's
port summary. A service that fails to start is reported on the console and
stays enabled, so systemd tries it again on the next boot; it does not stop
the others, and first boot still completes.

## The console after first boot

From now on the login screen of the machine's console shows, and keeps
current on every link change:

- every physical port, its link state, the role the configuration gives
  it (`wan`, `lan`, ...) and its IPv4 addresses;
- the web console's address;
- a warning when the LAN port has no link while an unused port does: the
  LAN cable is probably in the wrong port.

The console never changes port roles on its own: a cable in the wrong
port must not move the LAN, and the web console with it, onto the
upstream network.

## When first boot can't decide

If no WAN/LAN assignment was made, every port gets a DHCP client and no
DHCP server runs anywhere. Assign the ports yourself, on the machine's
console as root:

```console
# firewall-cli detect-interfaces
# firewall-cli assign-interfaces --wan enp1s0 --lan enp2s0
```

`assign-interfaces` takes `--lan-address` (default `10.73.1.1/24`),
`--hostname` (default `fr-router`) and `--opt ZONE:DEVICE` for each extra
port (repeatable, for example `--opt dmz:enp3s0`), and refuses to replace an existing configuration unless you
pass `--force`. Then apply it:

```console
# firewall-cli apply
```
