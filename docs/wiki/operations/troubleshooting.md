# Troubleshooting

Start with three questions, in this order:

1. **Does the configuration validate?** The dashboard's *config valid*
   badge, or `firewall-cli validate`.
2. **Did the last apply succeed?** The dashboard's messages, or
   `journalctl -u fr-apply-helper -n 50`.
3. **Is the packet dropped?** The dashboard's *Recently dropped*, or
   `journalctl -k -g 'fr_os/drop/'`.

## Reaching the router

| Symptom | Check |
| --- | --- |
| The web console doesn't answer | Are you in a management zone? By default every zone that doesn't face the internet is one, but a segment added on the Segments screen is not. Use `https://`, not `http://`. The machine's console login screen shows the right address. |
| It answered before an apply, not after | If the apply is held for confirmation, wait: it goes back by itself. Otherwise the change moved or closed management: see [Backup and recovery](backup-and-recovery.md#recovering-from-a-bad-change). |
| The console's login screen warns that the LAN port has no link | The LAN cable is probably in another port. FR_OS never moves port roles by itself; move the cable, or assign the ports with `firewall-cli assign-interfaces`. |
| Sign-in is refused with a correct password | Too many failures: the source is jailed for an hour, or the account locked for the rest of a 15-minute window except from known sources. Wait, or sign in from a device that signed in before. |
| A security key can't be added or used | Browsers allow keys only on a host name, not an IP address. Open the router by its name, or use the authenticator app. |
| The browser warns about the certificate | The certificate is the router's own. Compare its SHA-256 with the one on **System → Multi-site monitoring**, then trust it. |

## The internet

| Symptom | Check |
| --- | --- |
| No internet from the LAN | The WAN has an address (dashboard, *Interfaces*); `nat.masquerade` names the WAN zone; a rule accepts from `lan` to `wan`. The skeleton first boot writes has all three. |
| Names don't resolve, addresses work | With the router's resolver serving the LAN (`adblocker.serve_lan`), the pools' DNS servers are its upstreams: check they answer. `journalctl -u fr-adblock-dns`. |
| The WAN gets no address | FR_OS's WAN takes DHCP; PPPoE and a static WAN gateway are not supported in this version. Behind a provider's router that does PPPoE, connect to that router's LAN. |
| No IPv6 | `ipv6.enabled`, and the provider must offer it on the WAN. The Interfaces screen shows the default route and the delegated prefix, if any. `journalctl -u fr-dhcp6`. See [IPv6](../features/ipv6.md). |

## LAN services

| Symptom | Check |
| --- | --- |
| Clients get no address | The zone has exactly one interface with a static address, and a DHCP pool inside its network. `journalctl -u kea-dhcp4-server`. |
| A reservation isn't used | The device may use a randomised MAC on that network; turn that off for your network on the device. |
| Ads and blocked names still load | `adblocker.enabled` and `serve_lan`; the client uses the router as its DNS (renew its lease); **Enforce** (`force_dns`) on, so it can't ask another resolver. A browser with its own DNS over HTTPS can still escape; the XDP filter catches the TLS name. |
| A blocked app still works | Its connections opened before the block run until they close. With **Also block apps in the XDP SNI filter**, a client that has the address cached is stopped too. |
| An IoT device is not isolated | It may be classified *unknown*: isolate it by hand on the IoT Devices screen. Isolation only covers traffic through the router; put IoT devices in their own segment. |

## The VPN

| Symptom | Check |
| --- | --- |
| A device never completes a handshake | The endpoint in its configuration is your public address or name; the UDP port reaches the router (forward it on an upstream router); the device's configuration came from this router after its last key change. Carrier-grade NAT without a public address can't receive VPN connections. |
| The handshake works, nothing is reachable | Rules from the `vpn` zone: the VPN screen adds `vpn-to-lan`, `webui-from-vpn` and `ssh-from-vpn` when you turn it on, if they were missing. |
| IPv6 goes around a full tunnel | The device is marked **No IPv6 in its configuration**: re-add it. See [WireGuard VPN](../features/wireguard.md#ipv6-through-the-tunnel). |

## The XDP filter and the sensors

| Symptom | Check |
| --- | --- |
| The SNI filter blocks nothing | It is attached to the LAN-side interfaces (it sees only what an interface receives); the name is under 32 bytes; the client isn't using QUIC (rejected while the filter is on), Encrypted Client Hello, or a port other than 443. |
| *generic* mode instead of *native* | The network driver doesn't support XDP in the driver. The filter works the same; FR_OS turns GRO off on that port while it is attached. |
| A sensor screen shows "not running" | `systemctl status fr-ai-ids` (or `fr-appid`, `fr-tls-fp`, `fr-xdp-sni-logger`), and `journalctl -u` the same unit. Each runs as `fr_os-sensor` in a tight sandbox; a crash says why in its log. |
| AI-IDS flags a server that scans on purpose | Put its MAC in `excluded_macs` and give it a DHCP reservation. |

## Useful commands

```console
# firewall-cli validate                      # does the config check?
# firewall-cli render | less                 # what the ruleset becomes
# firewall-cli apply --dry-run               # what an apply would do
# nft list ruleset | less                    # what is loaded now
# journalctl -u fr-apply-helper --since -1h  # what the helper did
# journalctl -k -g 'fr_os/'                  # drops and logged rules
# systemctl --failed                         # units that failed
```

## Reporting a bug

Open an issue in the repository with the FR_OS version (top bar), what
you did, what you expected and what happened, and the relevant log lines.
Remove addresses and names you don't want to share. **A security
problem is never a public issue**: report it privately as described in
[SECURITY.md](../../../SECURITY.md).
