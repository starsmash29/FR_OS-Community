# IoT discovery and isolation

Cameras, smart speakers, plugs and TVs need the internet but rarely need
your laptop. IoT discovery finds them on your network, says **why** it
thinks each one is an IoT device, and can fence them in automatically.

## Turn it on

```yaml
iot:
  enabled: true
  zones: [lan]
  auto_isolate: true
  isolation_mode: internet_only
  trusted_macs: ["aa:bb:cc:dd:ee:01"]    # never isolated
  isolated_macs: ["aa:bb:cc:dd:ee:02"]   # always isolated
```

First boot turns this on for the LAN, with automatic isolation to
internet-only.

## How a device is found

`fr-iot-scan` runs 2 minutes after boot and then every 10 minutes, as
`fr_os-sensor`. Each scan combines:

- the **DHCP leases** (address, MAC, the host name the device announced),
  asked of the apply-helper;
- the kernel's **neighbour table**, for devices with static addresses;
- the **IEEE MAC registry**, for the vendor of each MAC;
- an **mDNS** query on each IoT zone, for the services devices advertise
  (`_googlecast`, `_hap` for HomeKit, `_matter`, `_sonos`, `_shelly`, printers, ...). The
  query is sent so that answers come straight back to one local port,
  which is the only port the firewall opens for it.

## How a device is scored

A plain point system, so you can predict and override it. Every signal
adds or takes away points and becomes a reason the **IoT Devices** screen
shows:

| Signal | Points |
| --- | --- |
| The vendor ships mostly IoT hardware | +3 |
| The vendor ships IoT and general devices | +1 |
| It advertises IoT services over mDNS | +3 |
| It advertises computer services over mDNS | −3 |
| Its DHCP host name looks like an IoT device | +2 |
| Its DHCP host name looks like a phone or computer | −2 |
| Its MAC is randomised (locally administered), as phones and laptops do | −2 |

A score of **3 or more** is *IoT*, **−2 or less** is *general*, anything
between is *unknown*.

## Isolation

An isolated device's MAC goes into the `iot_isolated` nftables set. The
rules for it come before every rule you write, so no admin rule can
reopen it by accident; only `trusted_macs` are exempt.

| Mode | The device may reach |
| --- | --- |
| `internet_only` | DHCP and DNS on the router, and the zones NAT masquerades out of (the internet). Nothing else on your network, and not the router's console. |
| `block` | DHCP and DNS on the router. Nothing routed. |

What gets isolated: every MAC in `isolated_macs`, plus, with
`auto_isolate`, every device scored *IoT*, minus `trusted_macs`. Isolating
a device also ends the sessions it already has open to the router.

On the **IoT Devices** screen you can trust, isolate or clear a device
with one click. *Trust* and *isolate* write its MAC to `trusted_macs` or
`isolated_macs` (and take it out of the other list); *clear* takes it out
of both, so the score decides again. The config is saved and the isolation
set is updated at once, without a full apply. **Scan now** runs a scan
without waiting for the timer.

## Limits

- Isolation acts on traffic that passes **through the router**. Two devices
  on the same switch can still talk to each other directly. For that, put
  IoT devices in their own [segment](../concepts/zones.md#segments).
- A device that randomises its MAC changes identity; isolation follows the
  MAC.
- The score uses what devices say about themselves. A device that
  announces nothing is *unknown* until you decide.
