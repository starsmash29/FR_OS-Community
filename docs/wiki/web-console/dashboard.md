# Dashboard and applying

The dashboard (`/`) is the first screen after sign-in: the state of the
router at a glance, and the buttons that apply the saved configuration.

## The header

- The router's **host name**, the FR_OS **version and codename**, the
  running **kernel** and the CPU.
- **config valid** or **config invalid**: whether the saved
  `config.yaml` passes validation right now. While it is invalid, a red
  message says so and nothing can be applied; fix it on the screen the
  message names.
- **Management session**: how the HTTPS connection you are using right
  now was negotiated: *Quantum-safe (hybrid X25519MLKEM768)*, *PQC
  enabled, not yet active* (the setting is on but the console has not been
  restarted with it), or *Classical only*. See the
  [System screen](system.md#post-quantum-key-exchange).

## The apply buttons

| Button | What it does |
| --- | --- |
| **Apply now** | Applies the saved configuration as one transaction: the firewall ruleset, IPv4 forwarding, WireGuard, interface addresses, IPv6, DHCP, the resolver, the XDP filter, and the key exchange and listen addresses of the console and SSH. If any step fails, every step already done is undone. |
| **Dry-run only** | Runs every check and step without changing anything, and says what would happen. Use it before a large change. |
| **Rollback firewall ruleset** | Loads the newest of the last 10 ruleset backups. Only the ruleset: the rest of the configuration stays as it is. |

The dashboard says how many ruleset backups are available, under
*System resources*.

The whole flow, step by step, is in
[Applying changes safely](../concepts/apply-and-rollback.md).

## The confirmation banner

With `management.confirm_apply_seconds` set (300 seconds by default), an
apply that changes something is **held**. A red banner appears on every
page:

> **This apply is waiting for confirmation.** Unless it is confirmed, the
> router goes back to the config applied before it in 287 s (applied by
> alice).

| Button | Effect |
| --- | --- |
| **Confirm** | The apply stands. |
| **Go back now** | The router goes back to the configuration applied before, at once. |
| *(nothing)* | When the time runs out, the router goes back by itself. That is the point: if the apply cut you off, you can't press anything, and the router undoes it for you. |

When an apply also moved the web console, the banner names the new
address: confirm from there.

After a revert, a plain banner says the apply was not confirmed and
offers **Load it to fix it**: the configuration that was rejected becomes
the saved one again, not applied, so you can correct it.

## Security alerts

A card lists the security alerts since you last marked them as seen: a
new admin, a password reset, a second factor removed, a sign-in from a new
address, a new VPN device, management opened to the internet, a config
that failed at boot. Check each one was you or someone you trust, then
**Mark as seen**. Each admin marks them for themselves. All of them stay
in the audit log on the Users screen.

## The cards

| Card | Shows |
| --- | --- |
| **Security score** | The percentage of the hardening checklist that passes, the open items, and a link to the [Security score](system.md#security-score) screen. A live system without persistence is warned about here: every change would be lost at the next reboot. |
| **Counters** | Firewall rules, port forwards and zones; interfaces with link up and configured; DHCP zones; quarantined hosts and whether the AI-IDS engine runs; blocked domains and whether DNS filtering is on. |
| **Protection services** | Which protection features are on and whether their daemons run, with links. Shown once the saved config is valid. |
| **System resources** | CPU, memory and storage use, uptime, the ruleset backups available, and where to turn on Prometheus metrics. |
| **Interfaces** | Each configured interface: zone, device, address, link. |
| **Recently dropped** | The last 50 packets the default policy dropped and logged: when, input or forward chain, from, to, protocol and port, interface. The log is rate-limited (`logging.drops_per_minute`). |
