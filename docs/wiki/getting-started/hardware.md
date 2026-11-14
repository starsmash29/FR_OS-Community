# Hardware

FR_OS runs on ordinary x86-64 hardware: an old desktop, a fanless mini PC
with several Ethernet ports, a rack server, or a virtual machine. It does
not run on ARM boards or consumer Wi-Fi routers.

> The figures below are planning baselines carried over from FR_OS 1.x.
> Measured figures for FR_OS 2 will be published with the release notes.

## Minimum and recommended

| Component | Minimum (basic routing) | Recommended (every feature on) |
| --- | --- | --- |
| CPU | 64-bit x86 (amd64), 2 cores | 4 cores |
| Memory | 2 GB | 4 to 8 GB |
| Storage | A 4 GB USB stick | An SSD of 16 GB or more |
| Network | 2 Ethernet ports | 3 or more, or 2 with a VLAN-capable switch |
| Firmware | BIOS or UEFI | UEFI |

**Why memory matters.** The base router is light. The DNS blocklists, the
application catalogue, the TLS fingerprint inventory and the AI-IDS
baselines are held in memory, and the router keeps the whole running
system in RAM while it boots from the live image, so more memory gives
more headroom.

## Network cards

- **Two ports at least.** One faces upstream (the WAN), one faces your
  network (the LAN). More ports give you more zones without VLANs.
- **Driver support.** Any card Debian 12 supports works for routing. Intel
  (`igb`, `igc`, `e1000e`, `ixgbe`) and Realtek (`r8169`, with the
  `firmware-realtek` package included in the image) cards are common in
  mini PCs.
- **XDP.** The XDP SNI filter attaches in native mode when the driver
  supports it, and falls back to generic mode when it doesn't. Generic mode
  works on every card but is slower, and FR_OS turns off GRO on a port in
  generic mode so that the filter sees each TLS handshake segment. Native
  mode is supported by most Intel server and 2.5 GbE drivers and by
  `virtio_net` in VMs.
- **Wi-Fi.** FR_OS does not configure Wi-Fi access points. Connect an
  access point to a LAN port (or one port per zone, or a VLAN trunk).

## Storage and persistence

The FR_OS image is a live system. Without persistence, everything written
after boot (the configuration, the admin password, SSH host keys, DHCP
leases) lives in RAM and is lost at the next reboot. On first boot from a
USB stick or disk with free space after the image, FR_OS adds a
persistence partition by itself and reboots once; from then on the router
keeps its state. See [Installation](installation.md#persistence).

Leave at least a few gigabytes of free space after the image on the boot
medium for the persistence partition, logs and ruleset backups.

## Virtual machines

FR_OS runs well in KVM/QEMU, Proxmox, VMware and VirtualBox. Give the VM:

- two virtual network cards (use `virtio` where you can), one bridged to
  the upstream network and one to an isolated internal network;
- 2 vCPUs and 2 GB of memory to start;
- a virtual disk of 8 GB or more to boot from, so that the persistence
  partition fits.

A VM is the best place to try FR_OS for the first time: you can snapshot
it, break it and start again.

## Serial console

The image starts a login on the first serial port (`ttyS0`, 115200 baud)
as well as on the screen, so a headless box or a VM without a display can
be set up over a serial cable or the hypervisor's serial console.
