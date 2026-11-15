# Updates

A firewall that isn't patched is the easiest way into a network. FR_OS
is updated on three levels, and each one keeps you in control.

| Level | How | State in this version |
| --- | --- | --- |
| **Debian's security fixes** (OpenSSL, OpenSSH, dnsmasq, Kea, nftables and the rest of userspace) | `unattended-upgrades`, daily, from Debian's security suite only, without reboots, into the persistent root | Works |
| **The kernel** | Debian's kernel fixes are fetched, prepared, and tried once at a reboot you start; the router keeps the new kernel only if it comes up working | Arrives with a later 2.0 phase |
| **FR_OS itself** | Signed releases, installed from the **Update** screen, or automatically for security releases | The Update screen checks; installing arrives with a later 2.0 phase |

## Debian security updates

Every image is built with Debian's `bookworm-security` suite, and the
build fails if a security update from it is left uninstalled: an image is
never published with known-fixed Debian vulnerabilities in it.

On the router, `unattended-upgrades` installs security updates from that
suite only, daily, into the persistent root. It does not reboot, and it
leaves the kernel alone: a live system boots the kernel on its boot
medium, so an installed kernel package would never run.

## FR_OS releases

Releases are published on the project's GitHub releases. Each carries a
`SHA256SUMS` file and its Ed25519 signature `SHA256SUMS.sig`; a router
refuses a release whose signature doesn't verify against the public key
it ships with. No setting, flag or request can turn that check off.

The **Update** screen shows the installed version, and the latest release
of `update.repo` (FR_OS's own repository by default), which it asks
GitHub for when you open the screen. That request is the only time the
web console talks to an outside server.

| Setting | Key | Default |
| --- | --- | --- |
| Install security updates automatically | `update.auto_install_security` | off |
| Fetch Debian's kernel fixes daily | `update.kernel_updates` | on |

### Release names

FR_OS's major versions carry a codename, shown next to the version in
the top bar: 2.x is **Ivar**.

## How fast security fixes come

The project's targets, from a confirmed report to a signed release, are
in [SECURITY.md](../../../SECURITY.md): 7 days for a critical issue
(anything reachable from the WAN, remote code execution, an
authentication bypass), 14 days for a high one, 30 days for the rest.
