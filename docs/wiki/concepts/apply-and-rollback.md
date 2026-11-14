# Applying changes safely

Changing a firewall remotely is the moment you are most likely to lock
yourself out. FR_OS treats every change as a transaction with several
safety nets. This page goes through them in the order they act.

## Save and apply are two steps

Editing a screen in the web console **saves** the configuration
(`/etc/fr_os/config.yaml`); it does not change the running router. The
running router changes only when you press **Apply now** on the
dashboard. You can make several edits and apply them together. The
dashboard also offers **Dry-run only**, which goes through every step
without changing anything, and it warns when the saved configuration does
not pass validation.

## 1. Validation

Before anything is saved, the whole configuration is checked by the
loader: every key, every value, and how they fit together (a rule that
names an undefined zone, a DHCP pool outside its network, two interfaces
on one device, a management change that would cut off the address you are
using). A refused configuration is not saved, and the message names the
field and the reason, for example:

```
Rule 'webui-from-lan': dst_port requires proto tcp or udp, got 'any'
```

## 2. Preflight

When you apply, FR_OS first checks everything it can without changing
anything:

| Check | How |
| --- | --- |
| The ruleset | Built and checked by `nft -c` |
| Network devices | Every device the configuration names exists |
| DHCP | The Kea configuration checked by `kea-dhcp4 -t` |
| The DNS resolver | Its configuration checked by `dnsmasq --test` |
| The XDP SNI filter | The ports it should attach to |
| IPv6 | What the IPv6 steps need |

A configuration that fails here changes nothing at all, and the error says
so: *"Nothing was applied ... The running system is unchanged."*

## 3. The transaction

The apply then runs its steps in a fixed order:

1. the firewall ruleset;
2. IPv4 forwarding;
3. the WireGuard tunnel;
4. the interface addresses;
5. IPv6;
6. DHCP (Kea);
7. the DNS resolver;
8. the XDP SNI filter;
9. the web console's TLS key exchange;
10. SSH's key exchange;
11. the addresses SSH and the web console listen on.

**The ruleset goes first**, so the router is filtered before anything else
comes up. It is loaded with `nft -f` as one atomic kernel transaction, and
it carries over the live members of the runtime sets (the brute-force
jail, the IDS quarantine, signed-in ZTNA clients, isolated IoT devices) in
the same transaction, so a reload never lets a banned host through, even
for a moment.

**Every step records how to undo itself before it changes anything.** If a
step fails, the steps done so far are undone in reverse order, the
firewall last, so the router stays filtered throughout. The error names the
failed step and says exactly what was put back and what could not be:

```
Apply failed at DHCP (Kea): ... Rolled back to the previous state: the
firewall, IPv4 forwarding, interface addresses. Nothing else was changed.
```

**On success**, the configuration that was applied in full is recorded
(root-only). It is what later applies roll back to, and what the router
boots into if `config.yaml` fails at boot.

## 4. Confirmation

A configuration that applied cleanly can still be wrong: a rule that cuts
off your own access works perfectly. Confirmation is the net for that.

With `management.confirm_apply_seconds` set (the default is **300
seconds**; 0 turns it off; otherwise 60 to 3600), an apply from the web
console is **held**:

- a banner on every page shows that the apply waits for confirmation;
- you press **Confirm** while you can still reach the console, and the
  apply stands;
- or you press **Go back now** to revert at once;
- or you do nothing (because you can't reach the console any more), and
  when the time runs out `fr-apply-revert` puts the previous configuration
  back.

After a revert, the rejected configuration is kept, and the banner offers
**Load it to fix it**: it becomes the saved configuration again, without
being applied, so you can correct it and try once more.

An apply is not held when there is nothing to go back to (the first apply,
or the same configuration again).

**A reboot is not a confirmation.** If the router restarts while an apply
waits (for example because you power-cycled it to get access back), the
boot reverts the held apply before anything else.

Only one apply can wait at a time. An apply, its confirmation and its
revert share one lock, so a confirmation can never land halfway through a
revert.

### Moving the management address

Changing the addresses the web console and SSH listen on is a special
case: you will reach the console at a new address. That change is applied
on its own and must be confirmed **from the new address**, or the router
goes back.

## 5. Rollback

Every time a ruleset is loaded, the one that was running is saved first,
under `/etc/fr_os/backups/` as `ruleset-<time>.nft`. The last 10 are kept.
**Rollback firewall ruleset** on the dashboard loads the newest backup.

Rollback restores the **ruleset** only. To go back to a whole earlier
configuration (DHCP, VPN, IPv6 and the rest), revert a held apply, or
restore an earlier `config.yaml` and apply it.

## At boot

`fr-firewall.service` applies the configuration at boot in **fail-closed**
mode:

| Situation | What the router does |
| --- | --- |
| No configuration yet (a new image before first boot) | Loads the **baseline**: nothing in except loopback and replies to the router's own connections, nothing forwarded |
| An apply was waiting for confirmation | Reverts it first |
| `config.yaml` applies | Normal boot |
| `config.yaml` fails | Rolls it back and boots into the **last configuration applied in full**, if there is one and it differs |
| That fails too, or there is none | Applies `config.yaml` as far as it goes, ruleset first, so the router is filtered |
| No FR_OS ruleset could be loaded at all | Loads the **baseline** |

A working ruleset is never replaced by the baseline: `nft -f` is atomic,
so a failed reload keeps the previous ruleset.

## From the command line

On the router, as root:

```console
# firewall-cli validate                  # check /etc/fr_os/config.yaml
# firewall-cli render                    # print the nftables script it would load
# firewall-cli apply --dry-run           # run every step without changing anything
# firewall-cli apply                     # apply it
# firewall-cli apply --confirm-within 120   # apply and hold it for 120 seconds
```

Each command takes another configuration file as its last argument
instead of `/etc/fr_os/config.yaml`. An apply from the command line is
held only with `--confirm-within`. While an apply waits for confirmation,
a new apply is refused.
