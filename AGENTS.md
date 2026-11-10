# Contributing to FR_OS 2 — for people and AI agents

FR_OS is a Debian-based firewall/router OS. FR_OS 2 is its rewrite in
**Go** and **Rust**, replacing the Python FR_OS 1.x
([FR_OS-pblk](https://github.com/starsmash29/FR_OS-pblk)). This file
says how the code is split, the rules every change follows, and what
"done" means. They apply to every contributor: a person, a coding agent,
or an AI tool working on someone's behalf.

> **This repository is private while FR_OS 2 is being built.** External
> contributions are not taken yet; the integrating agent (Claude Code)
> implements the phases below with the owner's go-ahead.

## Which language does what

| Part | Language | Why |
|---|---|---|
| Config schema, loading, validation | Go | `encoding/json/v2` and YAML; many rules, fast iteration |
| nftables ruleset builder | Go | netlink (`google/nftables`); its output is compared byte for byte with 1.x |
| apply-helper (root) | Go | small and auditable; Unix socket + per-peer-uid command list |
| webUI | Go, `net/http` + `html/template` | server-rendered, no JavaScript framework, nothing from a CDN (G11) |
| Ad-block DNS | Go | |
| Parser daemons (TLS fingerprints, app ID, AI IDS, IoT) | Rust | they read traffic strangers send: memory safety and speed |
| XDP / eBPF programs and their loaders | Rust, [aya](https://aya-rs.dev) | one language from kernel to userland |

Go and Rust never link into one binary (no cgo, no FFI). Each runs as
its own process, under its own account, and they talk over Unix sockets
in one wire format: **one JSON object per line**, the format 1.x already
uses (`ipc`, `crates/fros-ipc`, vectors in
`testdata/ipc/vectors.json`). A line is refused unless it is UTF-8,
valid JSON, an object, at most the line limit, and has no name twice in
any object. Both sides run the same vectors; a change to one side
changes the other in the same PR.

## Differential tests: 1.x is the specification

FR_OS 2 must do what 1.x does unless a change is decided and written
down. `reference/generate.sh` runs 1.x's own test suite, at the commit
in `reference/PIN`, with a capture plugin (`reference/fros_capture.py`)
that records every config check, every YAML text loaded and every
ruleset 1.x produced, into `testdata/reference/`. Next to 1.x's suite it
runs `reference/test_fros_edge_cases.py` and
`reference/test_fros_yaml_cases.py`, which only feed 1.x odd values
(what Python's ipaddress, datetime and isinstance, and PyYAML's YAML 1.1,
let through) so their answers are recorded too;
`reference/test_fros_helper_cases.py`, which sends 1.x's apply-helper
requests of every shape, from peers of every role, and records its
replies; then `reference/test_fros_ruleset_cases.py`, which has 1.x
build a ruleset from every config the run saw accepted, and from
schedules, clocks and runtime members of every shape;
`reference/test_fros_render_cases.py`, which has 1.x render every file
its apply writes (Kea, dnsmasq, dhcpcd, the RA instance, the kernel's
IPv6 settings, WireGuard, sshd, the PQC fragments) from each accepted
config, and the QR codes its webUI draws; and last
`reference/test_fros_apply_cases.py`, which runs 1.x's applies,
confirmations, reverts, rollbacks and saves, and the commands that
act on one host (a ban, a quarantine, a ZTNA sign-in, IoT isolation,
the conntrack sample, the activity log) and the ones that read the
system for the webUI's views (the firewall's drops, WireGuard,
the XDP counters, IPv6, the listening sockets, the RAM modules, the IoT
scan), and moving the webUI's address and refreshing the ad-block
lists, through its
apply-helper against a fake system (every path under a directory of its
own, every program and every download answered from a table, steps
made to fail one by one) and records the programs run, the replies and the files left;
and `reference/test_fros_webui_cases.py`, which takes 1.x's webUI
through sessions of requests (sign-in, accounts, second factors with a
software security key, the apply buttons, the screens that edit the
config, the filtering screens with the state files the
sensor daemons leave, the security checklist, the attack surface,
the update screen, the Prometheus metrics and the XDP live log) with a recorded clock, random
bytes, helper answers, GitHub's answers to the update check and the event log `tail -F` reads, and records every answer and the files left. The
Go packages replay those cases:

- the config package must load the same YAML to the same values, write
  the same YAML for them (yaml.safe_dump), and accept and refuse the
  same configs, with the same message;
- the ruleset builder must produce the same nft script, byte for byte;
- the apply-helper must give the same reply to the same request, and run
  nft with the same arguments;
- the renderers must write the same files, byte for byte;
- the webUI must give the same answer to the same request (pages
  compared as HTML tokens), ask the helpers the same and leave the same
  files;
- an apply must run the same programs, with the same input and timeout,
  in the same order, answer the same, and leave the same files.

A difference is a bug in 2.x or a decision. A decision gets a line in
the PR and an entry in `testdata/reference/decisions.md` saying which
cases change and why. Never edit a recorded case by hand: change PIN (or
the edge-case inputs) and regenerate.

## Ground rules (not negotiable)

**Licence**
- FR_OS is under the GNU AGPLv3 ([LICENSE](LICENSE)), with no additional permissions or exceptions.
- Every contribution is accepted under the [Contributor License Agreement](CLA.md).
- Third-party code keeps its licence and must be compatible with the AGPLv3; name it in the PR. eBPF programs declare a GPL-compatible licence, as the kernel requires.
- The Community Edition does not take compliance auditing features (automated compliance reporting, audit-trail exports, regulatory log management). The FR_OS name is a trademark ([LEGAL.md](LEGAL.md), section 3).

**Language and style**
- Everything committed is in **English**: code, comments, docs, commit messages and UI text.
- Go: `gofmt`, `go vet`, no `cgo` (`CGO_ENABLED=0`). JSON goes through `encoding/json/v2` only, never `encoding/json` v1.
- Rust: `cargo fmt`, `cargo clippy` with warnings denied. Userland crates `forbid(unsafe_code)` (set in the workspace); only the eBPF crates may use `unsafe`, and each block says why.
- Comments say *why*, with security-lessons or review IDs where they apply, as 1.x does.

**Secrets and trust**
- Never commit a secret: private keys, tokens, passwords, API keys, real config files.
- Never ask for, generate or handle the release signing key.
- FR_OS stays 100% local: no telemetry, no cloud calls, no vendor login (security-lessons G11). Anything that talks to the internet is opt-in and documented in the PR.

**Privilege boundaries** (security-lessons A1, I1)
- The webUI and the parser daemons never run privileged code. Root work goes through the apply-helper; each command is allowed per peer uid.
- Every service gets its own unprivileged account and a full systemd sandbox.
- A service listens only where it is needed and is off unless configured (I1, K7).

**Untrusted input**
- Every value that reaches an argv, an nft script or a config file is validated in one place (the config package), with `--` before positional values (F1).
- Anchor every regex at both ends. In Go and Rust `^`/`$` match only at the ends of the text unless multi-line mode is on; never turn it on for validation.
- Every read from a socket, file or the network has a size limit.

**Dependencies**
- `go.sum` and `Cargo.lock` are committed; the toolchains are pinned (`go.mod`'s `toolchain` line, `rust-toolchain.toml`).
- A new dependency is named in the PR with why it is needed. Prefer the standard library.
- CI runs `govulncheck` and `cargo audit`; a known vulnerability blocks the merge.
- Never install anything unpinned on the router.

**Tests and history**
- Never weaken, skip, delete or quarantine a test to get green. A failing test is a finding.
- No force-push to shared branches, and no rewriting of others' history.

## Toolchains

- Go 1.27 (`go.mod`). `encoding/json/v2` is in the standard library from 1.27 without an experiment flag.
- Rust stable 1.97 for userland (`rust-toolchain.toml`).
- The aya eBPF crates build with nightly Rust and `bpf-linker`; how CI installs `bpf-linker` (pinned) is decided with the first eBPF crate.

## Definition of done

A PR is ready for review when all of the following hold.

- **Tests.** Every change comes with tests. Prefer the real thing over mocks: real `nft`, real network namespaces, real sockets; root-only tests skip themselves without root.
  ```bash
  go vet ./... && go test ./...
  cargo fmt --all --check && cargo clippy --all-targets && cargo test
  ```
  Root-only sandbox end to end (Linux, root, nft, ip, unshare): `go test ./webui/ -run TestGoWebUIGoHelperSandbox -v`.
- **Differential tests** pass, or every difference is a recorded decision.
- **Boot test**, when the change touches the image, boot, services, networking or the installer: the installer workflow with `boot_test=true` passes. If you can't run it, say so in the PR.
- **PR description**: what changed and why; how it was tested, with commands and results; what is *not* done or not verified.

## Review and merge

Every PR is reviewed by the maintainer's integrating agent (Claude Code), which checks it against this file, runs the checks above, and merges only after the owner's "Mehet" (go). A PR that falls behind `main` gets `main` merged into it, not rebased.

## Repository map

| Path | What |
|---|---|
| `cmd/` | Go binaries (one per service) |
| `ipc/` | Go wire format (importable by other modules, unlike `internal/`) |
| `config/` | Config schema and checks: `config.Parse`, held to 1.x's `parse_config`; `config.ReadFile` and `config.LoadYAML`, held to PyYAML's `safe_load`, and `config.DumpYAML`, held to its `safe_dump` |
| `nft/` | The nftables ruleset builder: `nft.Build`, held to 1.x's `build_ruleset` byte for byte, and the rule schedules |
| `helper/` | The apply-helper: socket server, peer policy (`SO_PEERCRED`), and the commands, held to 1.x's `frfw.helper` reply for reply, and an apply held for confirmation (1.x's `frfw.apply_confirm`); `cmd/fr-apply-helper` runs it, `cmd/fr-apply-revert` is the unit that goes back from an apply not confirmed in time |
| `apply/` | Making the system match a config, as one transaction: the steps of an apply in 1.x's order with their preflight and undo (`System.ApplyAll`), the undo journal and the error an apply reports, file/service/link state captured for rollback, atomic writes, systemctl, loading a ruleset with its backup (held to 1.x's `frfw.provision`, `frfw.transaction` and `frfw.apply`) |
| `render/` | The text of the files an apply writes (Kea, dnsmasq, dhcpcd, RA, sysctl, WireGuard, sshd, PQC), held to 1.x's renderers byte for byte |
| `webui/` | The webUI (`net/http` + `html/template`): sign-in, sessions held to 1.x's itsdangerous cookies, CSRF, second factors (TOTP, WebAuthn), accounts, the dashboard (with its security score, rule check and attack-surface verdicts), the firewall screens (rules, NAT, interfaces, DHCP, segments), the filtering screens (ad-block and local DNS, application control, TLS fingerprints, the XDP SNI filter, IoT, AI-IDS), the ZTNA gate (its admin settings and its public sign-in and status pages), the WireGuard VPN screen, the system screen, the security checklist, the attack surface, the update screen (read-only), the Prometheus metrics (behind their bearer token) and the XDP filter's live log (server-sent events, one `tail -F` per session), replayed against 1.x's recorded sessions (`webui.jsonl`), and its QR codes held to segno's (`qr.jsonl`); `cmd/fr-webui` serves it over HTTPS. The Go webUI is what ships (`systemd/fr-webui.service` runs `/usr/libexec/fr_os/fr-webui` as `fr_os-webui`); FR_OS 1.x is reference only |
| `appid/` | The application catalog (app control's domain names) |
| `internal/` | Go packages private to this module; `internal/reference` loads the 1.x reference, `internal/pyyaml` is the YAML reader and writer (a port of PyYAML) |
| `crates/` | Rust workspace; `crates/fros-ipc` is the wire format |
| `systemd/` | The units, each with its sandbox (`systemd/sandbox_test.go` checks it, security-lessons I1) |
| `reference/` | The pinned 1.x commit, the capture plugin and the extra edge-case inputs |
| `testdata/` | Shared test vectors and the recorded 1.x reference |
| `docs/security-lessons.md` | The security requirements every feature meets (IDs like `I1`, `G3`), carried over from 1.x |
| `.github/workflows/` | CI |
