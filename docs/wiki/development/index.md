# Development

FR_OS 2 is written in **Go** (the control plane) and **Rust** (everything
that parses traffic, and the XDP program). This page is the map: where
the code is, how to build it, and the rules every change follows. The
binding rules are in [AGENTS.md](../../../AGENTS.md); this page explains
them.

| Page | Covers |
| --- | --- |
| [Testing](testing.md) | The test suites, the differential tests against FR_OS 1.x, the XDP replay, the boot test |

## The code

| Path | Language | What |
| --- | --- | --- |
| `config/` | Go | The configuration schema, loading and every validation rule |
| `nft/` | Go | The nftables ruleset builder and the rule schedules |
| `helper/` | Go | The apply-helper (root): socket server, peer policy, commands; `firewall-cli` |
| `apply/` | Go | Making the system match a configuration, as one transaction; first boot's system work |
| `render/` | Go | The files an apply writes: Kea, dnsmasq, dhcpcd, RA, sysctl, WireGuard, sshd |
| `webui/` | Go | The web console, server-rendered with `html/template` |
| `ipc/` | Go | The wire format to the helper |
| `cmd/` | Go | One binary per service: `firewall-cli`, `fr-apply-helper`, `fr-apply-revert`, `fr-webui` |
| `internal/` | Go | Private packages: the 1.x reference loader, the YAML reader and writer |
| `crates/fros-ipc` | Rust | The same wire format, for the Rust side |
| `crates/fros-sensor` | Rust | What the sensors share: log following, the helper client, exact arithmetic |
| `crates/fros-tlsfp` | Rust | ClientHello parsing, JA3/JA4, the inventory; `fr-tls-fp` |
| `crates/fros-appid` | Rust | Application identification; `fr-appid` |
| `crates/fros-aiids` | Rust | The AI-IDS engine; `fr-ai-ids` |
| `crates/fros-iot` | Rust | IoT discovery and scoring; `fr-iot-scan` |
| `crates/fros-xdp-ebpf` | Rust (aya, eBPF) | The XDP SNI filter's kernel side |
| `crates/fros-xdp` | Rust | Its userland: `fr-xdp` (load, pin, sync) and `fr-xdp-sni-logger` |
| `systemd/` | | The units, each with its sandbox |
| `installer/` | shell, Python | Building the image, the QEMU boot test |
| `scripts/` | shell | First boot and system integration |
| `reference/`, `testdata/` | | The pinned FR_OS 1.x commit and its recorded behaviour |

**Go and Rust never link into one binary**: no cgo, no FFI. Each service
is its own process, under its own account, and they talk over Unix
sockets, one JSON object per line. Both sides run the same test vectors
for that format (`testdata/ipc/vectors.json`); a change to one side
changes the other in the same pull request.

## Toolchains

| For | Version | Pinned in |
| --- | --- | --- |
| Go | 1.27 (toolchain 1.27.3) | `go.mod` |
| Rust, userland | stable 1.97.0 | `rust-toolchain.toml` |
| Rust, the eBPF crate | nightly-2026-11-01, with `rust-src` | `crates/fros-xdp-ebpf/rust-toolchain.toml` |
| `bpf-linker` | 0.13.0, built against that nightly's LLVM | `.github/workflows/ci.yml` |

Debian 12 (bookworm) is the target system.

## Building

```console
$ go build ./cmd/...                     # the Go binaries
$ cargo build --release                  # the Rust userland
$ (cd crates/fros-xdp-ebpf && cargo build --release)   # the XDP program
```

The image:

```console
$ installer/build-binaries.sh /tmp/stage         # as you, with the toolchains
$ sudo installer/build-live-image.sh --stage /tmp/stage
```

`build-binaries.sh` builds the Go binaries static (`CGO_ENABLED=0`), the
Rust ones static against musl, and the XDP object, and stages them with
the scripts and units. `build-live-image.sh` runs Debian's live-build and
then makes the ISO bootable under both BIOS and UEFI; it needs root,
`live-build` and its friends (the script's header lists them), and
network access to Debian's mirrors. The image has no compiler and no
Python: only what was built.

## Rules every change follows

**Code style**

- Go: `gofmt`, `go vet`, `CGO_ENABLED=0`; JSON through `encoding/json/v2`
  only.
- Rust: `cargo fmt`, `cargo clippy` with warnings denied. Userland crates
  forbid `unsafe` (set for the whole workspace); only the eBPF crate may
  use it, and every block says why.
- Comments say *why*, with the security-lesson IDs they answer.
- Everything committed is in English.

**Security**

- Every value that reaches a command line, an nft script or a file is
  validated in one place, the config package; `--` before positional
  values.
- Every pattern is anchored at both ends; multi-line mode is never used
  for validation.
- Every read from a socket, file or the network has a size limit.
- Every service has its own unprivileged account and a full systemd
  sandbox, and listens only where it must, only when it is configured.
- Nothing talks to the internet unless an admin turned it on (G11).
- No secrets in the repository, ever.

**Dependencies**

- `go.sum` and `Cargo.lock` are committed. Prefer the standard library;
  a new dependency is named in the pull request with the reason.
- `govulncheck` and `cargo audit` run in CI; a known vulnerability blocks
  the merge.

**Licence**

FR_OS is under the GNU AGPLv3, with no additional permissions. Every
contribution is accepted under the [Contributor License
Agreement](../../../CLA.md). Third-party code keeps its licence, which
must be compatible with the AGPLv3; eBPF programs declare a
GPL-compatible licence, as the kernel requires.

## Contributing

FR_OS 2 is being built by its maintainer and is not taking outside
contributions yet. Bug reports and ideas are welcome as issues;
security problems are reported privately (see
[SECURITY.md](../../../SECURITY.md)). When contributions open, every pull
request is reviewed against AGENTS.md, runs the checks on the
[Testing](testing.md) page, and is merged only with the owner's approval.
