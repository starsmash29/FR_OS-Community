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

## Coming next

These sections are being written and will appear here as they are
finished:

- **Configuration reference:** every key of `config.yaml`, with its type,
  default, limits and the exact validation rule.
- **Features:** one page per feature (firewall rules, NAT, DHCP, IPv6,
  DNS filtering, application control, XDP SNI filter, TLS fingerprints,
  IoT, AI-IDS, WireGuard, ZTNA, schedules, monitoring), each with how to
  turn it on, examples, limits and troubleshooting.
- **Web console guide:** every screen, field by field.
- **Operations:** the `firewall-cli` command reference, backups,
  updates, logs and troubleshooting.
- **Security:** the security model and the requirements every feature
  meets.
- **Development:** building, testing, the differential tests against
  FR_OS 1.x, and contributing.
- **FAQ and glossary.**

## Conventions

- Paths such as `/etc/fr_os/config.yaml` are on the router.
- Commands shown with `#` run as root on the router's console or over SSH;
  commands shown with `$` run on your own computer.
- "The console" means the web console (the webUI) unless a page says the
  machine's text console.
