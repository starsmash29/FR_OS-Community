# Backup and recovery

Everything that makes your router *yours* is in `/etc/fr_os/`. The rest
of the system is the image, which you can always write again.

## What to back up

| File | What it holds | Secret? |
| --- | --- | --- |
| `/etc/fr_os/config.yaml` | The whole configuration | Holds password **hashes** (ZTNA accounts) and the metrics token's hash, never a password. Keep it private. |
| `/etc/fr_os/webui/auth.json` | The web console's accounts, password hashes and second factors | Yes |
| `/etc/fr_os/webui/cert.pem`, `key.pem` | The web console's TLS certificate and key | The key is |
| `/etc/fr_os/wireguard/private.key` | The router's VPN key. Without it, every VPN device needs a new configuration. | Yes |
| `/etc/fr_os/ipv6_ula.json` | The router's stable IPv6 (ULA) prefix. Without it, a new one is made and VPN devices' IPv6 tunnel addresses change. | No |

Not needed in a backup: the ruleset backups, the files the apply writes
(Kea, dnsmasq, sshd drop-ins, `applied-config.yaml`, the sensors' copies),
the logs, and the state the daemons rebuild (fingerprint inventory, app
usage, IoT inventory, hit counters).

Copy them as root and keep the copy somewhere safe, encrypted if it
leaves your hands:

```console
# tar -C / -czf /root/fr_os-backup-$(date +%F).tar.gz \
    etc/fr_os/config.yaml etc/fr_os/webui/auth.json \
    etc/fr_os/webui/cert.pem etc/fr_os/webui/key.pem \
    etc/fr_os/wireguard/private.key etc/fr_os/ipv6_ula.json
```

There is no "export configuration" button in the web console, on
purpose: a config backup that can be downloaded from the network is what
attackers took from other firewalls to crack offline.

## Restoring onto a fresh install

1. Install the image and let first boot finish.
2. Copy the files back into place with their owners and modes:

   ```console
   # tar -C / -xzf fr_os-backup-2026-11-14.tar.gz
   # chown root:fr_os-webui /etc/fr_os/config.yaml && chmod 0640 /etc/fr_os/config.yaml
   ```

3. Check and apply:

   ```console
   # firewall-cli validate
   # firewall-cli apply
   # systemctl restart fr-webui
   ```

If the new machine's ports have other names, fix `device:` in the
`interfaces` section first (`firewall-cli detect-interfaces` lists them).

## Recovering from a bad change

| Situation | What to do |
| --- | --- |
| An apply cut you off | Wait: a held apply goes back by itself when its confirmation time runs out (300 seconds by default). Or reboot: a reboot reverts a held apply first. |
| The apply went back, but the change was nearly right | **Load it to fix it** on the banner makes the rejected configuration the saved one again, not applied. Correct it and apply again. |
| The ruleset is wrong, the rest is fine | **Rollback firewall ruleset** on the dashboard loads the newest of the last 10 ruleset backups (`/etc/fr_os/backups/ruleset-<time>.nft`). |
| `config.yaml` doesn't validate | The dashboard says so and names the problem. `firewall-cli validate` prints the same. The running router keeps running what was applied last. |
| The configuration fails at boot | The router boots into the last configuration that applied in full, raises a security alert, and the dashboard says what failed. Fix `config.yaml` and apply. |
| Nothing works at boot | The fail-closed baseline is loaded: the router forwards nothing and lets in only loopback and replies to its own connections. Fix the configuration from the machine's console. |

## Lost access

| Lost | Way back |
| --- | --- |
| The admin password | On the router as root: `firewall-cli set-admin-password --username NAME` sets a new one. |
| A second factor | Another admin: **Users → Reset** in the *Second factor* column. Or on the router: `firewall-cli mfa-reset NAME`. |
| The web console's address | The machine's console login screen shows it, with every port's role and address. |
| The ports' roles | `firewall-cli assign-interfaces --wan DEVICE --lan DEVICE --force`, then `firewall-cli apply`. This replaces the configuration with a minimal one: back it up first. |

## A live system without persistence

On a live system without persistence, every change is lost at the next
reboot: configuration, accounts, keys. The dashboard and the System
screen warn about it. Set up persistence (see
[Installation](../getting-started/installation.md#persistence)) before you
rely on the router.
