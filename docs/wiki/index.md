# FR_OS documentation

FR_OS is an open-source firewall and router for x86-64 PCs and virtual
machines. This documentation covers FR_OS 2, the Go and Rust rewrite,
from the first boot to the internals.

> **Version.** These pages describe the code on `main`, which becomes
> FR_OS 2.0.0 "Ivar". The first downloadable build is 2.0.0-beta. Where a
> part is not finished yet, the page says so.

## Getting started

New to FR_OS? Read these in order.

| Page | What you learn |
| --- | --- |
| [What FR_OS is](getting-started/what-is-fr-os.md) | What it does, who it is for, and what it is not |
| [Hardware](getting-started/hardware.md) | What to run it on: CPU, memory, network cards, storage |
| [Installation](getting-started/installation.md) | Writing the image, booting it, keeping your settings across reboots |
| [First boot](getting-started/first-boot.md) | What the router does on its own the first time it starts |
| [Your first 30 minutes](getting-started/first-30-minutes.md) | Signing in, securing the account, and the first checks to make |

## Concepts

How FR_OS thinks. Read these before you change the firewall policy.

| Page | What you learn |
| --- | --- |
| [Architecture](concepts/architecture.md) | The processes, the languages, and how they talk |
| [Privilege model](concepts/privilege-model.md) | Who runs as root, who doesn't, and what each may ask for |
| [Zones and segments](concepts/zones.md) | Zones, interfaces, VLANs, the router itself, and how traffic between them is decided |
| [Applying changes safely](concepts/apply-and-rollback.md) | Validation, the apply transaction, confirmation, revert and rollback |
| [The configuration file](concepts/configuration-file.md) | `config.yaml`: where it lives, its sections, and how it is checked |

## Features

One page per feature: how to turn it on, an example, its limits and how
to check it. Start at the [feature overview](features/index.md).

| Network | Protection and visibility |
| --- | --- |
| [Firewall rules and schedules](features/firewall-rules.md) | [DNS filtering and local names](features/dns-filtering.md) |
| [NAT and port forwards](features/nat.md) | [Application control](features/app-control.md) |
| [DHCP](features/dhcp.md) | [XDP SNI filter](features/xdp-sni-filter.md) |
| [IPv6](features/ipv6.md) | [TLS fingerprints](features/tls-fingerprints.md) |
| [WireGuard VPN](features/wireguard.md) | [IoT discovery and isolation](features/iot.md) |
| [ZTNA gate](features/ztna.md) | [AI-IDS](features/ai-ids.md) |
| | [Monitoring and logs](features/monitoring.md) |

## Reference

| Page | What you find |
| --- | --- |
| [Configuration reference](reference/configuration.md) | Every key of `config.yaml`: its type, default, limits and the exact rule it is checked against |

## Web console

| Page | What you find |
| --- | --- |
| [The web console](web-console/index.md) | Reaching it, the layout, save and apply, roles and sessions |
| [Signing in and accounts](web-console/accounts.md) | Sign-in, first-run setup, second factors, users, the audit log |
| [Dashboard and applying](web-console/dashboard.md) | The apply buttons, the confirmation banner, the alerts and cards |
| [Network screens](web-console/network.md) | Interfaces, Segments, Rules, NAT, DHCP, VPN |
| [Protection screens](web-console/protection.md) | AI IDS/IPS, TLS SNI Filter, Ad-Block, IoT Devices, Applications, TLS Fingerprints, ZTNA Gate |
| [System screens](web-console/system.md) | Update, System, Attack surface, Security score |

## Operations

| Page | What you find |
| --- | --- |
| [firewall-cli](operations/firewall-cli.md) | Every command of the router's command line |
| [Backup and recovery](operations/backup-and-recovery.md) | What to keep, how to restore, how to get back in |
| [Updates](operations/updates.md) | Debian fixes, the kernel, FR_OS releases and their signatures |
| [Troubleshooting](operations/troubleshooting.md) | Symptoms, checks and the commands that help |

## Security and development

| Page | What you find |
| --- | --- |
| [Security model](security/index.md) | What stands between an attacker and your network |
| [Development](development/index.md) | The code, the toolchains, building, the rules every change follows |
| [Testing](development/testing.md) | Unit tests, differential tests against 1.x, the XDP replay, the boot test |

## Help

- [Frequently asked questions](faq.md)
- [Glossary](glossary.md)

## Conventions

- Paths such as `/etc/fr_os/config.yaml` are on the router.
- Commands shown with `#` run as root on the router's console or over SSH;
  commands shown with `$` run on your own computer.
- "The console" means the web console (the webUI) unless a page says the
  machine's text console.
