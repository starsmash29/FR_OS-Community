# FR_OS 2

**Turn spare hardware into a firewall and router you control.**

FR_OS is a Debian-based firewall and router OS for homelabs. FR_OS 2
rebuilds the same system in **Go and Rust**, with local management and no
cloud account or telemetry.

**Status · In development.** This repository contains the FR_OS 2 rewrite.
For the installable version, see [FR_OS 1.x](https://github.com/starsmash29/FR_OS-pblk).

[See what’s in the repo](#whats-in-the-repo) ·
[Run the tests](#run-the-tests) ·
[Architecture and development](AGENTS.md)

## Why FR_OS?

- **Manage your network locally.** The design keeps the web interface,
  configuration and traffic analysis on your own hardware.
- **Use Linux's native networking stack.** FR_OS is built around
  nftables for firewall policy and eBPF/XDP for packet filtering.
- **Keep existing rules predictable.** FR_OS 2 replays cases captured
  from a pinned FR_OS 1.x commit. For example, the nftables builder is
  tested against the exact ruleset text that 1.x produces.

## What's in the repo

| Component | Where to look |
| --- | --- |
| Configuration validation and nftables ruleset generation in Go | [Config](config/) · [Ruleset builder](nft/builder.go) |
| Privileged helper, network configuration rendering and transactional apply | [Helper](helper/server.go) · [Renderers](render/render.go) · [Apply and rollback](apply/apply.go) |
| Shared Unix-socket protocol in Go and Rust | [Go IPC](ipc/ipc.go) · [Rust IPC](crates/fros-ipc/src/lib.rs) · [Shared test cases](testdata/ipc/vectors.json) |

The [architecture plan](AGENTS.md#which-language-does-what) puts the
control plane in Go and traffic parsers and XDP components in Rust.
The two sides communicate over Unix sockets with one JSON object per line.

## Run the tests

On Linux, use the toolchain versions pinned in [go.mod](go.mod) and
[rust-toolchain.toml](rust-toolchain.toml). From the repository root:

```bash
go test ./ipc ./nft
cargo test -p fros-ipc
```

The Go and Rust IPC tests use the same wire-format cases. The Go nftables
tests compare generated rulesets with the 1.x reference. See
[AGENTS.md](AGENTS.md#differential-tests-1x-is-the-specification) for how
the reference is generated and how intentional differences are tracked.

## Security and licence

Report vulnerabilities privately through GitHub. See
[SECURITY.md](SECURITY.md) for the reporting process.

FR_OS is licensed under the [GNU AGPLv3](LICENSE). The FR_OS name is a
trademark. See [LEGAL.md](LEGAL.md) for details.
