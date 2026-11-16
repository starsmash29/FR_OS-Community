# Updates

A firewall that isn't patched is the easiest way into a network. FR_OS
is updated on three levels, and each one keeps you in control.

| Level | How | State in this version |
| --- | --- | --- |
| **Debian's security fixes** (OpenSSL, OpenSSH, dnsmasq, Kea, nftables and the rest of userspace) | `unattended-upgrades`, daily, from Debian's security suite only, without reboots, into the persistent root | Works |
| **The kernel** | Debian's kernel fixes are fetched, prepared, and tried once at a reboot you start; the router keeps the new kernel only if it comes up working | Works |
| **FR_OS itself** | Signed releases, installed from the **Update** screen, or automatically for security releases; one step back with **Roll back** | Works |

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
The keys are compiled into FR_OS's programs, so there is no file on the
router to add one to.

Each release has two downloads: the ISO, and
`fr_os-<version>-amd64.tar.gz`, the programs, scripts and units the image
installs and the updater installs. Every image keeps the tarball it was
built from, with its `SHA256SUMS` (and signature), under
`/opt/fr_os/releases/<version>/`. `firewall-cli --version` prints the
installed release.

To check a download on another computer, with the public key from the
repository's `release/keys/`:

```bash
openssl pkeyutl -verify -pubin -inkey fros-release-2.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

The **Update** screen shows the installed version, and the latest release
of `update.repo` (FR_OS's own repository by default), which it asks
GitHub for when you open the screen. The router also asks twice a day
(`fr-update-check.timer`) and keeps the answer, so every page can show a
"Security update available" banner. Those requests, and the downloads of
a release you install, are the only times FR_OS talks to GitHub.

**Update to X** downloads the release's tarball, `SHA256SUMS` and
signature, verifies them, and installs the release beside the one
running: each release's programs live in a directory of their own,
`/usr/libexec/fr_os-releases/<version>/`, and `/usr/libexec/fr_os` points
at the one in use, switched in a single step. The services restart on
the new programs, and the web console restarts a few seconds later.
Only a newer version is ever installed: an older release would bring
back what has been fixed since.

**Roll back to X** goes back to the version the router updated from,
once: the release's files stay in `/opt/fr_os/releases/`, so it needs
no network, and they are verified again first. On the console the same
commands are `firewall-cli update check`, `firewall-cli update apply
<version>` and `firewall-cli update rollback`.

| Setting | Key | Default |
| --- | --- | --- |
| Install security updates automatically | `update.auto_install_security` | off |
| Fetch Debian's kernel fixes daily | `update.kernel_updates` | on |

Betas (`2.0.0-beta.1`) are published as pre-releases, which the Update
screen doesn't offer; install one from its ISO, or with
`firewall-cli update apply 2.0.0-beta.1`. A router on a beta is offered
the final release when it comes out.

### Release names

FR_OS's major versions carry a codename, shown next to the version in
the top bar: 2.x is **Ivar**.

## How fast security fixes come

The project's targets, from a confirmed report to a signed release, are
in [SECURITY.md](../../../SECURITY.md): 7 days for a critical issue
(anything reachable from the WAN, remote code execution, an
authentication bypass), 14 days for a high one, 30 days for the rest.
