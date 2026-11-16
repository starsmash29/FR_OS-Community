#!/usr/bin/env bash
# Builds what the FR_OS image installs, into a stage directory that
# installer/build-live-image.sh copies into the image (the image has no
# compiler or toolchain of its own):
#
#   bin/      the Go binaries (cmd/*, CGO_ENABLED=0: static) and the Rust
#             ones (static against musl, so they run on the image's
#             Debian whatever the build host's glibc is)
#   bpf/      the XDP SNI filter's program (crates/fros-xdp-ebpf, its
#             pinned nightly and bpf-linker 0.13.0; AGENTS.md, "Toolchains")
#   scripts/  fr-first-boot.sh and install-system-integration.sh
#   systemd/  the units, the journald and watchdog drop-ins and the
#             kernel's IPv6 settings (sysctl.d)
#   VERSION   the release it is, which the updater checks
#
# Run as the user who has the toolchains (go.mod's, rust-toolchain.toml's
# with the x86_64-unknown-linux-musl target, the eBPF crate's nightly),
# not as root:
#
#   installer/build-binaries.sh STAGE_DIR
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${1:?usage: build-binaries.sh STAGE_DIR}"
RUST_TARGET=x86_64-unknown-linux-musl
GO_BINARIES=(firewall-cli fr-apply-helper fr-apply-revert fr-update-helper fr-webui)
RUST_BINARIES=(fr-ai-ids fr-appid fr-iot-scan fr-tls-fp fr-xdp fr-xdp-sni-logger)

# The release this build is (version.Version): the repository's VERSION
# file, X.Y.Z or a beta X.Y.Z-beta.N. FROS_TEST_VERSION builds the same
# commit as another version: the boot test's update to install (a test
# build's, .github/workflows/build-installer.yml; never a release's).
VERSION="${FROS_TEST_VERSION:-$(cat "$REPO_ROOT/VERSION")}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-beta\.[0-9]+)?$ ]]; then
    echo "error: VERSION is not X.Y.Z or X.Y.Z-beta.N: $VERSION" >&2
    exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/bin" "$STAGE/bpf" "$STAGE/scripts" "$STAGE/systemd"
STAGE="$(cd "$STAGE" && pwd)"
cd "$REPO_ROOT"

echo "==> Go binaries (CGO_ENABLED=0), FR_OS $VERSION"
for name in "${GO_BINARIES[@]}"; do
    CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -buildid= -X github.com/starsmash29/fr_os-community/version.Version=$VERSION" \
        -o "$STAGE/bin/$name" "./cmd/$name"
done

echo "==> Rust binaries ($RUST_TARGET, static)"
rustup target add "$RUST_TARGET" >/dev/null
cargo build --release --locked --target "$RUST_TARGET" --bins
for name in "${RUST_BINARIES[@]}"; do
    install -m 0755 "target/$RUST_TARGET/release/$name" "$STAGE/bin/$name"
done

echo "==> The XDP program (crates/fros-xdp-ebpf)"
(cd crates/fros-xdp-ebpf && cargo build --release --locked)
install -m 0644 crates/fros-xdp-ebpf/target/bpfel-unknown-none/release/fros-xdp "$STAGE/bpf/xdp_sni_filter.o"

printf '%s\n' "$VERSION" > "$STAGE/VERSION"

echo "==> Scripts and units"
install -m 0755 scripts/fr-first-boot.sh scripts/install-system-integration.sh "$STAGE/scripts/"
for unit in systemd/*.service systemd/*.socket systemd/*.timer systemd/*.path systemd/*.conf; do
    if [[ -f "$unit" ]]; then
        install -m 0644 "$unit" "$STAGE/systemd/"
    fi
done

# Every unit's ExecStart names a binary the stage has (what a unit runs
# from /usr/libexec/fr_os must be installed there).
missing=0
while read -r path; do
    if [[ ! -e "$STAGE/bin/$(basename "$path")" && ! -e "$STAGE/scripts/$(basename "$path")" ]]; then
        echo "error: a unit runs $path, which the stage doesn't have" >&2
        missing=1
    fi
done < <(grep -ho '^ExecStart=/usr/libexec/fr_os/[^ ]*' "$STAGE"/systemd/*.service | cut -d= -f2 | sort -u)
[[ $missing -eq 0 ]]

ls -la "$STAGE/bin" "$STAGE/bpf"
