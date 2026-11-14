# Installation

> **Preview.** The installer image arrives with FR_OS 2.0.0-beta. This page
> describes how it is built to work; details may change until the beta is
> published, and the release notes win where they differ.

FR_OS ships as one hybrid ISO image for amd64. The same file boots from a
USB stick or a disk, on BIOS and on UEFI machines, and in virtual
machines. It is a Debian 12 (bookworm) live system with FR_OS's Go and Rust
binaries and systemd units already inside; nothing is downloaded during
installation.

## 1. Download and verify

Download the image, its checksum file and its signature from the
[Releases](https://github.com/starsmash29/FR_OS-Community/releases) page.
Always check the image before you write it: a firewall from a tampered
image protects nobody.

```console
$ sha256sum --check FR_OS-*.iso.sha256
FR_OS-2.0.0-beta-amd64.iso: OK
```

The release notes say how to verify the signature, and with which public
key.

## 2. Write the image

**USB stick or disk** (everything on the target is erased):

```console
$ lsblk                          # find the stick, for example /dev/sdX
$ sudo dd if=FR_OS-2.0.0-beta-amd64.iso of=/dev/sdX bs=4M conv=fsync status=progress
```

On Windows or macOS, a raw image writer such as balenaEtcher or Rufus (in
"DD image" mode) does the same.

Use a stick or disk bigger than the image: the free space after it
becomes the persistence partition (see below). 8 GB or more is a good
size.

**Virtual machine:** a VM boots best from a virtual disk, so that
persistence works: write the ISO onto a virtual disk of 8 GB or more (for
example `qemu-img convert -f raw -O qcow2 FR_OS-2.0.0-beta-amd64.iso fr_os.qcow2`
followed by `qemu-img resize fr_os.qcow2 8G`) and boot from it. Booting the
ISO as a CD works too, but a CD is read-only, so nothing is kept across
reboots unless you add a second disk for persistence (see below).

## 3. Connect the cables

Before the first boot, connect:

- one port to the **upstream** network (your ISP modem or the office
  network): this will become the WAN;
- one port to the **network you want to protect**: a switch, an access
  point or a single test computer. This will become the LAN.

First boot tells the two apart on its own (see
[First boot](first-boot.md#2-how-the-wan-is-found)), so you don't need to
know which port is which. For the first test, connect a single computer to
the LAN rather than your whole network.

## 4. Boot

Select the stick or disk in the firmware's boot menu. The boot menu offers:

| Entry | Use |
| --- | --- |
| **FR_OS** | The normal boot. |
| **FR_OS (fail-safe mode)** | For hardware that hangs on boot: turns off ACPI, SMP, mode setting and other features. Use it only to diagnose. |

The beta image is not signed for Secure Boot. If the firmware refuses to
start it, turn Secure Boot off in the firmware settings.

The router boots with a fail-closed firewall (nothing in, nothing
forwarded) until it has a configuration, then runs its first-boot setup.

## Persistence

The image is a live system: everything written after boot is kept in
memory. To keep your configuration across reboots, FR_OS uses Debian's
live-boot persistence: a partition labelled `persistence` on which the
whole root filesystem is overlaid.

**It is automatic.** On the first boot from a USB stick or disk, before
the first-boot setup runs, FR_OS looks at the boot medium. If there is at
least 256 MiB of free space after its last partition, it adds a new
partition there, formats it, and reboots once. Existing partitions are
never touched. After that reboot, the first-boot setup runs on the
persistent system, so the password and settings it makes survive.

You can check the state at any time:

```console
# firewall-cli persistence status
```

**When it is skipped.** Automatic persistence is skipped (and the reason
logged on the console) when the medium is read-only (a CD), has too little
free space, or its partition table is full. You can then put the
persistence partition on a second, empty disk:

```console
# firewall-cli persistence create /dev/sdb
```

On a disk that already has partitions, `persistence create` refuses unless
you pass `--wipe` (it then asks for confirmation, or takes `--yes`).

## Next

The router is now running its [first boot](first-boot.md).
