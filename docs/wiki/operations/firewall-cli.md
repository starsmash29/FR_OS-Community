# firewall-cli

`firewall-cli` is the router's own command line. The router's units use
it (the boot's apply, the schedule check, the blocklist refresh, first
boot), and so can you, as root on the router.

```console
# firewall-cli COMMAND [options]
```

`CONFIG` is optional wherever it appears and defaults to
`/etc/fr_os/config.yaml`.

| Exit status | Meaning |
| --- | --- |
| `0` | Done. |
| `1` | Refused or failed; the reason is on standard error, starting with `config error:`, `apply error:`, `nft error:` or `error:`. |
| `2` | The command line itself was wrong; the usage is printed. |

## Getting a shell on the router

`firewall-cli` changes the running system, so it runs as root.

- **SSH** is keys only: `PasswordAuthentication no`, `PermitRootLogin
  no`, and only members of the group `fr_os-ssh` may sign in. The group is
  created empty, so nobody can sign in over SSH until you add a user with
  a key to it. SSH listens only where the web console does (the
  management zones' addresses).
- The **machine's console** (screen and keyboard, or the serial port
  `ttyS0` at 115200 baud) shows the ports and the web console's address
  on its login screen.

## Configuration

### validate

```console
# firewall-cli validate [CONFIG]
OK: /etc/fr_os/config.yaml is valid (12 rule(s))
```

Checks a configuration file exactly as an apply would, and changes
nothing. Use it after every edit by hand. Any user can run it on a copy of
the file.

### render

```console
# firewall-cli render [CONFIG]
```

Prints the nftables script the configuration builds, without loading it.
Useful to see exactly what a rule becomes.

### apply

```console
# firewall-cli apply [CONFIG] [--dry-run] [--fail-closed] [--confirm-within SECONDS]
```

| Option | Effect |
| --- | --- |
| *(none)* | Applies the configuration as one transaction, like **Apply now**. Every step's message is printed. |
| `--dry-run` | Runs every check and step without changing anything. |
| `--confirm-within SECONDS` | Holds the apply for confirmation (60 to 3600 seconds); unless it is confirmed in time, the router goes back to the configuration applied before. Confirm on the web console's banner. |
| `--fail-closed` | The boot's mode (`fr-firewall.service`): never leave the router unfiltered. See below. |

An apply is refused while another one waits for confirmation, and a
configuration that would move the web console's or SSH's addresses is
refused here: move them on the **System** screen, where the change is held
until you confirm it from the new address.

**Fail-closed** (`--fail-closed`) is what runs at boot:

1. No configuration file: the **fail-closed baseline** is loaded: only
   loopback and replies to the router's own connections get in, and
   nothing is forwarded.
2. An apply was waiting for confirmation when the router went down: it is
   reverted first. A reboot is not a confirmation.
3. The configuration applies: done.
4. It fails: the router boots into the last configuration that applied in
   full, if there is one and it is different, and raises a security alert.
5. That fails too, or there is none: the configuration is applied as far
   as it goes, the ruleset first, and a security alert is raised.
6. If no FR_OS ruleset is loaded after all that, the baseline is loaded.
   A working ruleset is never replaced by a failed one: loading a ruleset
   is atomic.

### schedule-check

```console
# firewall-cli schedule-check [CONFIG]
```

Run hourly by `fr-schedule-check.timer`. It records which rules matched
(for the rule check's "unused for 90 days") and re-applies the
configuration when the time zone's offset changed, such as at a
daylight-saving change, so scheduled rules keep their local times. Only
the configuration that was applied is re-applied: if `config.yaml` was
edited since, it applies nothing, says so and exits `1`; apply it
yourself.

## DNS filtering

### adblock-refresh

```console
# firewall-cli adblock-refresh [CONFIG] [--scheduled]
```

Downloads the blocklists, removes duplicates and reloads the resolver.
Sources that failed are listed as a warning; the others are used. With
`--scheduled` (the daily `fr-adblock-refresh.timer`), nothing is
fetched while ad-blocking is off: the router downloads nothing you did not
turn on.

### dns-log-trim

```console
# firewall-cli dns-log-trim
```

Empties the resolver's query log when it grows past 16 MiB. Run by
`fr-dns-log-trim.timer`.

## Accounts

### set-admin-password

```console
# firewall-cli set-admin-password [--username NAME] [--generate [--show-on-console]]
```

| Form | Effect |
| --- | --- |
| `set-admin-password --username alice` | Asks for a new password twice and creates or resets the admin account `alice` (default `admin`). The password rules of the web console apply. Raises a security alert, like the same change in the console. |
| `--generate` | Generates a password and prints only the password, without prompts. |
| `--generate --show-on-console` | What first boot runs: generates the password and shows it on the machine's console login screen (a root-only file) until it is changed. The first sign-in then asks for a new user name and password. |

This is also the way in when the router has no web console account, or
you lost the admin password.

### mfa-reset

```console
# firewall-cli mfa-reset alice
Second factors of 'alice' removed; they sign in with the password alone until they add one
```

Removes an account's security keys and authenticator app, for a lost
factor. When the second-factor policy is on, the admin must add a new
one after signing in.

### initial-password

```console
# firewall-cli initial-password
```

Takes the generated first-boot password off the console's login screen
once the account's password has been changed. Run by
`fr-initial-password.path`.

### ensure-accounts

```console
# firewall-cli ensure-accounts
```

Creates FR_OS's system accounts and state directories if they are missing
(`fr-accounts.service`, at every boot). Safe to run again.

## Network ports

### detect-interfaces

```console
# firewall-cli detect-interfaces [--include-virtual]
```

Lists the physical network ports: name, driver, MAC address, link and
speed. `--include-virtual` adds the virtual and software devices.

### detect-wan-lan

```console
# firewall-cli detect-wan-lan
```

First boot's choice of WAN and LAN: it sends a DHCP request on every
port with a link and takes the one that gets an offer as the WAN. It
prints the decision and the reason. See
[First boot](../getting-started/first-boot.md).

### assign-interfaces

```console
# firewall-cli assign-interfaces --wan DEVICE --lan DEVICE [--opt ZONE:DEVICE]...
                               [--hostname NAME] [--lan-address ADDRESS/PREFIX] [--out FILE] [--force]
```

Writes a minimal working configuration for the ports you name: a WAN, a
LAN with its address (default `10.73.1.1/24`) and DHCP pool, outbound
NAT on the WAN, rules for SSH and the web console from the LAN and from
the LAN to the internet, and nothing exposed from the WAN. `--opt dmz:enp3s0` adds another
zone on another port (repeatable). `--hostname` defaults to `fr-router`.
It refuses to replace an existing configuration without `--force`;
`--out` writes elsewhere. Then run `firewall-cli apply`.

### console-ports

```console
# firewall-cli console-ports [--print] [--watch]
```

Writes the port summary the console's login screen shows (each port, its
link, its role and addresses, and the web console's address). `--print`
prints it instead; `--watch` keeps it current on every link change
(`fr-console-ports.service`).

## Persistence

```console
# firewall-cli persistence status
# firewall-cli persistence auto [--reboot]
# firewall-cli persistence create DISK [--wipe] --yes
```

| Command | Effect |
| --- | --- |
| `status` | Whether the router is installed, live with persistence, or live without, and its boot medium. |
| `auto` | What first boot runs: creates the persistence partition in the free space after the image on the boot USB stick, if there are at least 256 MiB. With `--reboot`, reboots once to start using it. |
| `create DISK --yes` | Creates the persistence filesystem on another disk, for a read-only boot medium. **It erases that disk**, so `--yes` is required; `--wipe` also clears its old partition table. Reboot afterwards; what changed during this boot is not copied. |

See [Installation](../getting-started/installation.md#persistence).

## Kernel

A live router with persistence can take Debian's kernel fixes without a
new image: a kernel is staged on the persistence partition, tried once
at the next reboot, and kept only if the router comes up on it with the
firewall, its ports and the console working; otherwise the image's own
kernel boots again.

```console
# firewall-cli kernel status
# firewall-cli kernel prepare [--version RELEASE] [--config CONFIG]
# firewall-cli kernel try [--no-reboot]
# firewall-cli kernel stage KERNEL INITRD --version RELEASE
# firewall-cli kernel unstage
```

| Command | Effect |
| --- | --- |
| `status` | The running kernel, the staged one and its state, and the staged files' SHA-256 digests. |
| `prepare` | What `fr-kernel-prepare.timer` runs daily while `update.kernel_updates` is on (the default): if Debian's `linux-image-amd64` points at a newer kernel than the router has, installs it with apt from the Debian archive and makes its initrd from the image's own. It never stages or reboots. `--version` prepares that kernel instead, whatever the setting. |
| `try` | Stages the prepared kernel and reboots into its trial; `--no-reboot` leaves the trial for the next reboot. **Update → Try it** does the same. |
| `stage`, `unstage` | Stage a kernel and initrd of your own, or go back to the image's kernel at the next reboot. Neither reboots. |

`kernel confirm-boot` is the boot-time check `fr-kernel-confirm.service`
runs; it is not for the console.

## Not in this version

These appear in some messages but are not commands of this version yet:
confirming or reverting a held apply from the command line (use the
console's banner), moving the management addresses from the command line
(use **System → webUI address**), creating the metrics token from the
command line (use **System → Multi-site monitoring**), and installing
release updates (a later 2.0 phase).
