#!/usr/bin/env bash
# Builds the FR_OS hybrid live/installer ISO, as 1.x's
# installer/build-live-image.sh: stages FR_OS into the live-build tree's
# includes.chroot (config/hooks/0100-install-fr_os.hook.chroot installs
# it), runs `lb config` + `lb build`, then installer/make-hybrid-uefi-iso.sh
# to add real UEFI boot support on top of `lb build`'s own BIOS-only
# image (see that script's header for why).
#
#   sudo installer/build-live-image.sh --release DIR
#   sudo installer/build-live-image.sh --stage DIR
#
# --release DIR (the CI's build) names a directory with the release
# tarball installer/package-release.sh made, its SHA256SUMS and, when the
# build is signed, SHA256SUMS.sig: the image installs exactly what the
# tarball holds and keeps the three files under /opt/fr_os/releases/
# <VERSION>/, the release a router's updater can go back to without the
# network (1.x's ROADMAP SEC-15). --stage DIR is what
# installer/build-binaries.sh built, as the user with the toolchains.
# With neither it runs build-binaries.sh itself, which then needs the
# toolchains on root's PATH.
#
# Must run as root: live-build chroots, mounts, and device nodes all need
# it. Needs `live-build`, `debootstrap`, `xorriso`, `squashfs-tools`,
# `librsvg2-bin`, `syslinux-utils` and friends installed
# (`apt-get install live-build debootstrap xorriso squashfs-tools isolinux
# syslinux-efi syslinux-utils librsvg2-bin grub-pc-bin grub-efi-amd64-bin
# grub-common mtools dosfstools`), and network access to Debian's
# mirrors -- expect this to take a while (debootstrap downloads a base
# system, then every package in fr_os.list.chroot, then assembles and
# compresses a squashfs).
#
# `syslinux-utils` (for `isohybrid`, used by --binary-images iso-hybrid)
# and `librsvg2-bin` are easy to miss: nothing in the chroot package list
# needs them, since they're build-*host* tools invoked directly by
# lb_binary_syslinux/lb_binary_iso outside the chroot -- a host missing
# either fails late, well into `lb build`, with an unrelated-looking
# error ("isohybrid: not found" / "rsvg: No such file or directory").
# `grub-efi-amd64-bin`, `grub-common`, `mtools` and `dosfstools` are the
# same kind of build-host-only tool, needed by
# installer/make-hybrid-uefi-iso.sh (grub-mkstandalone, mkfs.vfat,
# mmd/mcopy) rather than by anything inside the chroot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LB_DIR="$REPO_ROOT/installer/live-build"
STAGE_DIR="$LB_DIR/config/includes.chroot/opt/fr_os-stage"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (live-build needs to chroot/mount)" >&2
    exit 1
fi

# live-build's chroot hooks run via a plain `chroot`, which inherits
# this shell's environment as-is. Some build hosts (anything behind a
# TLS-inspecting proxy) export CA-bundle override variables pointing at a
# path on the *host* filesystem, which doesn't exist in the chroot: apt
# and friends then fail with a confusing TLS error instead of using the
# chroot's own trust store. Unsetting them is a no-op on a plain build
# host and fixes it on a proxied one.
unset PIP_CERT REQUESTS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_FILE \
    NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO NIX_SSL_CERT_FILE \
    CARGO_HTTP_CAINFO DENO_CERT HTTPLIB2_CA_CERTS AWS_CA_BUNDLE \
    CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE GRPC_DEFAULT_SSL_ROOTS_FILE_PATH \
    HEX_CACERTS_PATH

STAGE_SOURCE=""
RELEASE_SOURCE=""
case "${1:-}" in
    --stage) STAGE_SOURCE="$(cd "$2" && pwd)" ;;
    --release) RELEASE_SOURCE="$(cd "$2" && pwd)" ;;
esac
RELEASES_STAGE="$LB_DIR/config/includes.chroot/opt/fr_os/releases"
rm -rf "$STAGE_DIR" "$RELEASES_STAGE"
mkdir -p "$(dirname "$STAGE_DIR")"
if [[ -n "$RELEASE_SOURCE" ]]; then
    version="$(cat "$REPO_ROOT/VERSION")"
    tarball="$RELEASE_SOURCE/fr_os-$version-amd64.tar.gz"
    echo "==> Staging the release $tarball into $STAGE_DIR"
    (cd "$RELEASE_SOURCE" && sha256sum --check --ignore-missing --strict SHA256SUMS)
    mkdir -p "$STAGE_DIR"
    tar -xzf "$tarball" -C "$STAGE_DIR" --strip-components=1
    install -d -m 0755 "$RELEASES_STAGE/$version"
    for name in "$(basename "$tarball")" SHA256SUMS SHA256SUMS.sig; do
        if [[ -f "$RELEASE_SOURCE/$name" ]]; then
            install -m 0644 "$RELEASE_SOURCE/$name" "$RELEASES_STAGE/$version/$name"
        fi
    done
elif [[ -n "$STAGE_SOURCE" ]]; then
    echo "==> Staging $STAGE_SOURCE into $STAGE_DIR"
    cp -a "$STAGE_SOURCE" "$STAGE_DIR"
else
    echo "==> Building the binaries (installer/build-binaries.sh)"
    "$REPO_ROOT/installer/build-binaries.sh" "$STAGE_DIR"
fi
chown -R root:root "$STAGE_DIR"

cd "$LB_DIR"

echo "==> lb clean"
lb clean

echo "==> lb config"
lb config

echo "==> lb build (this is the slow part)"
lb build

echo "==> Adding UEFI boot support (installer/make-hybrid-uefi-iso.sh)"
"$REPO_ROOT/installer/make-hybrid-uefi-iso.sh"

echo
echo "==> Build finished. Output:"
ls -la "$LB_DIR"/*.iso 2>/dev/null || echo "  no .iso found -- check the build log above for errors"
