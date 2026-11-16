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
apply-helper, and the `firewall-cli` commands the router's units run
(the boot's fail-closed apply, an apply from the console, validate,
render, the schedule check, the query log trim, the ad-block refresh,
ensure-accounts with the accounts given, and first boot's: the ports
and the WAN/LAN choice with each port's DHCP probe answered from the
table, the skeleton config, the admin password generated or typed, a
second factor's reset, the console's password and port summary, and
the persistence partition on a sysfs tree of disks, and a kernel
staged on that partition: its status, staging and unstaging, and the
boot-time check of its trial, with the free space, the webUI's answer
and the check's clock as pseudo-calls, and the kernel to stage: Debian's
newer one installed with apt answered from the table and its initrd
made from an image initrd built for the case, then tried; and the
update-helper's kernel requests), against a fake
system (every path under a directory of its own, every program and
every download answered from a table, steps made to fail one by one) and records the
programs run, the replies (a command's exit status and output) and the
files left;
`reference/test_fros_webui_cases.py`, which takes 1.x's webUI
through sessions of requests (sign-in, accounts, second factors with a
software security key, the apply buttons, the screens that edit the
config, the filtering screens with the state files the
sensor daemons leave, the security checklist, the attack surface,
the update screen, the Prometheus metrics and the XDP live log) with a recorded clock, random
bytes, helper answers, GitHub's answers to the update check and the event log `tail -F` reads, and records every answer and the files left;
`reference/test_fros_tlsfp_cases.py`, which feeds 1.x's TLS
fingerprinting library ClientHellos and TLS record streams of every
shape (prefixes, wrong lengths, odd extensions, seeded random damage),
segments in and out of order, and its inventory with state files valid
and broken, and records each answer;
`reference/test_fros_appid_cases.py`, which feeds 1.x's application
identification its catalog broken every way, names to match, usage
counts with state files valid and broken, and the lines of the
resolver's query log and the SNI event file;
`reference/test_fros_aiids_cases.py`, which feeds 1.x's AI-IDS the
names its DGA heuristic scores, the numbers its statistics average, and
seeded traffic of every kind, and records every verdict; and
`reference/test_fros_iot_cases.py`, which feeds 1.x's IoT discovery
MAC addresses, the IEEE registry and the neighbour table in every
shape, mDNS answers built, damaged and random, devices to score, and
whole scans with every helper answer, mDNS result and file injected,
and records the inventory file each scan writes;
`reference/test_fros_xdpuser_cases.py`, which feeds 1.x's XDP userland
blocklist names, the filter's event and hello-copy records whole, cut
and random, and lines for its event file, and records each key, decoded
record, JSON line and file; `reference/test_fros_tlsfpd_cases.py`,
which runs 1.x's TLS fingerprinting daemon on hello copies at given
clocks, with state files valid and broken and a fake apply-helper
answering every shape of reply, and its helper client alone, and
records each request, count, state file and reply; and
`reference/test_fros_sensord_cases.py`, which records what 1.x's
application identification and AI-IDS daemons take from each config,
and runs them on log lines, conntrack samples and evaluations at given
clocks, with usage files and event logs valid and broken, a routing
table and resolv.conf, and a fake apply-helper answering every shape
of reply, and records each request, printed line, flagged event, usage
file and event log; and 1.x's IoT scan asking that fake helper, and
its mDNS discovery on a real socket against a fake responder on
loopback (damaged, foreign and too many answers, the router's own),
recording each request, message, inventory file, query and service
found; and `reference/test_fros_netdetect_cases.py`, which records the
DHCPDISCOVER frame 1.x's first boot sends and the network it reads from
offers built, masked every way and damaged at random. And
`reference/test_fros_release_cases.py` has 1.x's release check verify
signatures with keys of every shape, find the checksum a SHA256SUMS lists
for a name, and check whole releases, and
`reference/test_fros_update_cases.py` has 1.x's updater install and roll
back signed releases (from the cache or downloaded, refused for their
version, their signature, their tarball or the state file, failing at
each step), through the update-helper and `firewall-cli update`, and
check for a newer release with every answer GitHub can give. One recording needs
root and runs on its own: `reference/generate-xdp.sh` compiles 1.x's
XDP program (`bpf/xdp_sni_filter.c`) and has the kernel run it
(`BPF_PROG_TEST_RUN`) on the frames of `reference/test_fros_xdp_cases.py`
(ClientHellos for every name shape and field value, cut at every byte,
behind VLAN tags, IPv4 options and fragments, IPv6 extension headers,
and split over segments in order, out of order, with bad checksums, past
every limit of the follower, then damaged at random), recording each
frame's verdict, the counters it moved, the events and hello copies it
reported and the flows it left. The Go packages and the Rust
crates replay those cases:

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
  in the same order, answer the same, and leave the same files, and
  `firewall-cli` must exit the same and print the same;
- the TLS fingerprinting crate must parse the same fields, compute the
  same JA3 and JA4, give the same error text, reassemble the same
  message and write the same state file, byte for byte, and its
  daemon must ask the apply-helper the same and count the same;
- the application identification crate must parse the same catalog
  (or give the same error text), attribute every name to the same app,
  and write the same usage state file, byte for byte, and its daemon
  must follow the same sources and write the same usage file;
- the AI-IDS crate must give the same DGA verdict and flag the same
  hosts with the same score, to the last bit of every float, and its
  daemon must score the same sources, ask the apply-helper the same,
  print the same and write the same event log;
- the IoT crate must read the same vendors and neighbours, find the
  same mDNS service types, score every device the same, ask the
  helpers the same and write the same inventory file, byte for byte;
- the DHCP probe must send the same DISCOVER frame, byte for byte, and
  read the same network from every answer;
- the XDP program must give every frame the same verdict, move the
  same counters, report the same events and hello copies, and leave
  the same flow state, in the same maps;
- the release check must accept the same signatures from the same
  keys, read the same checksum for a name, and refuse with the same
  error;
- the updater must refuse the same releases with the same error,
  download the same files and run its steps in the same order, answer
  and print the same, and leave the same state file, check cache and
  release cache.

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
- The aya eBPF crates (`crates/*-ebpf`) build with the nightly pinned in their own `rust-toolchain.toml` and `bpf-linker` 0.13.0, built against that nightly's LLVM (`cargo install bpf-linker@0.13.0 --locked --no-default-features --features llvm-23,no-llvm-linking`, linking rustc's `libLLVM` as `.github/workflows/ci.yml` does). They are not workspace members; each has its own `Cargo.lock`.

## Definition of done

A PR is ready for review when all of the following hold.

- **Tests.** Every change comes with tests. Prefer the real thing over mocks: real `nft`, real network namespaces, real sockets; root-only tests skip themselves without root.
  ```bash
  go vet ./... && go test ./...
  cargo fmt --all --check && cargo clippy --all-targets && cargo test
  ```
  The XDP program, built and replayed as root: `(cd crates/fros-xdp-ebpf && cargo build --release) && CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' FROS_XDP_REQUIRED=1 cargo test -p fros-xdp`. An apply attaching it to a veth, as root: `cargo build -p fros-xdp --bin fr-xdp && sudo -E FROS_XDP_REQUIRED=1 go test ./apply/ -run TestXdpRealAttach -v`.
  Root-only sandbox end to end (Linux, root, nft, ip, unshare): `go test ./webui/ -run TestGoWebUIGoHelperSandbox -v`.
- **Differential tests** pass, or every difference is a recorded decision.
- **Boot test**, when the change touches the image, boot, services, networking or the installer: the *Build installer ISO* workflow (`.github/workflows/build-installer.yml`, which runs on a PR touching `installer/`, `scripts/` or `systemd/`, and by hand with `boot_test=true`) passes: it builds the image and boots it in QEMU with BIOS and with UEFI (`installer/qemu-boot-test.py`). When the router gains new behaviour, add a check for it there. If you can't run it, say so in the PR.
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
| `helper/` | The apply-helper: socket server, peer policy (`SO_PEERCRED`), and the commands, held to 1.x's `frfw.helper` reply for reply, and an apply held for confirmation (1.x's `frfw.apply_confirm`); `cmd/fr-apply-helper` runs it, `cmd/fr-apply-revert` is the unit that goes back from an apply not confirmed in time, and `cmd/firewall-cli` is the router's own commands (`Server.CLI`, held to 1.x's `frfw.cli`): the boot's apply in fail-closed mode (`fr-firewall.service`), validate, render, the schedule check and rule hit counters, the query log trim, the ad-block refresh and ensure-accounts, and first boot's commands (`detect-interfaces`, `detect-wan-lan`, `assign-interfaces`, `set-admin-password`, `mfa-reset`, `initial-password`, `console-ports`, `persistence`), and the staged kernel's (`kernel status`, `stage`, `unstage`, `confirm-boot`, which `fr-kernel-confirm.service` runs on every boot GRUB starts, `prepare`, which `fr-kernel-prepare.timer` runs daily, and `try`); and the update-helper (`UpdateServer`, held to 1.x's `frfw.helper.update_server`: installing a signed release and rolling back, and the Update screen's kernel status, check, try and cancel, for root and `fr_os-webui` only), which `cmd/fr-update-helper` runs on `/run/fr_os/update.sock` |
| `apply/` | Making the system match a config, as one transaction: the steps of an apply in 1.x's order with their preflight and undo (`System.ApplyAll`), the undo journal and the error an apply reports, file/service/link state captured for rollback, atomic writes, systemctl, loading a ruleset with its backup, the XDP SNI filter (attach, keep, replace, GRO, blocklist, switches; 1.x's `frfw.xdp.sync_sni_filter`), the sensor daemons' JSON view of the config (`apply.SensorView`, `sensor-view.json`), and first boot's system work: the ports from sysfs, the DHCP probe on a packet socket and the WAN/LAN choice, the skeleton config, the console's port summary (refreshed on rtnetlink events) and initial password, and the persistence partition, and a kernel staged on it, tried once at the next boot and kept only when the router comes up on it (the GRUB environment block, the staged slot, the boot-time check), and the kernel to stage: Debian's newer one installed through apt, its initrd the image's own with its modules exchanged (`PrepareKernel`, `TryPreparedKernel`), and installing a signed release: the update check and its cache (`CheckLatest`), and `Updater`, which downloads or takes from the cache, verifies, unpacks and installs a release into a directory of its own, switches `/usr/libexec/fr_os` to it and rolls back (held to 1.x's `frfw.provision`, `frfw.transaction`, `frfw.apply`, `frfw.xdp`, `frfw.netdetect`, `frfw.skeleton`, `frfw.console_ports`, `frfw.initial_password`, `frfw.persistence`, `frfw.kernel_boot`, `frfw.kernel_update` and `frfw.update`) |
| `render/` | The text of the files an apply writes (Kea, dnsmasq, dhcpcd, RA, sysctl, WireGuard, sshd, PQC), held to 1.x's renderers byte for byte |
| `webui/` | The webUI (`net/http` + `html/template`): sign-in, sessions held to 1.x's itsdangerous cookies, CSRF, second factors (TOTP, WebAuthn), accounts, the dashboard (with its security score, rule check and attack-surface verdicts), the firewall screens (rules, NAT, interfaces, DHCP, segments), the filtering screens (ad-block and local DNS, application control, TLS fingerprints, the XDP SNI filter, IoT, AI-IDS), the ZTNA gate (its admin settings and its public sign-in and status pages), the WireGuard VPN screen, the system screen, the security checklist, the attack surface, the update screen (installing a release, rolling back and its kernel card's buttons, through the update-helper), the Prometheus metrics (behind their bearer token) and the XDP filter's live log (server-sent events, one `tail -F` per session), replayed against 1.x's recorded sessions (`webui.jsonl`), and its QR codes held to segno's (`qr.jsonl`); `cmd/fr-webui` serves it over HTTPS. The Go webUI is what ships (`systemd/fr-webui.service` runs `/usr/libexec/fr_os/fr-webui` as `fr_os-webui`); FR_OS 1.x is reference only |
| `release/` | Checking that a release really comes from FR_OS's maintainers: the public keys it trusts (`release/keys/`, compiled in), the Ed25519 signature over `SHA256SUMS` and the tarball's checksum in it, held to 1.x's `frfw.release_signing` (`release.jsonl`); `release/verify`, the check CI runs on what it signs, and `release/reviewgate`, the J2 review gate (1.x's `scripts/check_release_review.py`), both run with `go run` and never installed. How a release is made: `docs/RELEASING.md` |
| `version/`, `VERSION` | The release a build is (`VERSION`, stamped into the Go programs by `installer/build-binaries.sh`), its codename, and how versions compare (`X.Y.Z` and `X.Y.Z-beta.N`) |
| `appid/` | The application catalog (app control's domain names) |
| `internal/` | Go packages private to this module; `internal/reference` loads the 1.x reference, `internal/pyyaml` is the YAML reader and writer (a port of PyYAML) |
| `crates/` | Rust workspace; `crates/fros-ipc` is the wire format; `crates/fros-sensor` is what the sensor crates share to answer as 1.x's Python does (its JSON dialect, dict order, text classes, exact float arithmetic, dnsmasq's log prefix); `crates/fros-tlsfp` is TLS client fingerprinting (ClientHello parsing, JA3/JA4, reassembly across segments, the fingerprint inventory and its state file), held to 1.x's `frfw.tlsfp` (`tlsfp.jsonl`), and `fr-tls-fp`, its daemon, held to 1.x's `frfw.tlsfp.daemon` (`tlsfpd.jsonl`); `crates/fros-appid` is application identification (the catalog, name matching, per-app usage and its state file, the log readers), held to 1.x's `frfw.appid` (`appid.jsonl`), and `fr-appid`, its daemon, held to 1.x's `frfw.appid.daemon` (`sensord.jsonl`); `crates/fros-aiids` is the AI-IDS anomaly engine, its DGA heuristic and log readers, held to 1.x's `frfw.ai_ids` (`aiids.jsonl`), and `fr-ai-ids`, its daemon (the sources it scores, conntrack samples and quarantines through the apply-helper, its event log), held to 1.x's `frfw.ai_ids.daemon` (`sensord.jsonl`); `crates/fros-sensor`'s `follow` follows a log file as `tail -n 0 -F` does, for both; `crates/fros-iot` is IoT discovery (MAC vendors from the IEEE registry, the neighbour table, mDNS service discovery, the IoT scoring, the scan and its inventory file, read from the sensor's JSON view of the config), held to 1.x's `frfw.iot` (`iot.jsonl`), and `fr-iot-scan`, its oneshot scan (the helper's `dhcp_leases` and `iot_sync_isolation`, the mDNS socket, the inventory written), held to 1.x's `frfw.iot.scanner` and `frfw.iot.mdns.discover` (`sensord.jsonl`); `crates/fros-xdp-ebpf` is the XDP SNI filter's kernel side in aya (the filter, the split-hello follower and the IPv6 path, with 1.x's maps), held to 1.x's `bpf/xdp_sni_filter.c` frame for frame (`xdp.jsonl`) by `crates/fros-xdp`'s replay; `crates/fros-xdp` is its userland: `fr-xdp`, which loads and pins it, gives the pinned program's id, syncs the blocklist and writes the switches and reads the counters for the Go apply (fixed argv, absolute paths after `--`), and the event and hello-copy records and the event file, held to 1.x's `frfw.xdp` (`xdpuser.jsonl`), the ring buffer reader and the privilege drop the readers share, and `fr-xdp-sni-logger`, which writes the filter's events to the event file; `crates/fros-sensor`'s `helper` is 1.x's apply-helper client |
| `systemd/` | The units, each with its sandbox (`systemd/sandbox_test.go` checks it, security-lessons I1) |
| `installer/` | The image: `build-binaries.sh` (the Go binaries static, `CGO_ENABLED=0`, with `VERSION` stamped in; the Rust ones static for musl; the XDP object; the scripts and units), `package-release.sh` (the release tarball of what it built), `build-live-image.sh` (from that tarball, which the image keeps under `/opt/fr_os/releases/`: live-build, then `make-hybrid-uefi-iso.sh` for GRUB on BIOS and UEFI), the live-build tree (`live-build/`; its chroot hook installs what was built, with no Python on the router), `qemu-boot-test.py` (the boot test, held to 1.x's) and `installer_test.go` |
| `scripts/` | First boot (`fr-first-boot.sh`, run once by `fr-first-boot.service`) and `install-system-integration.sh`, shell as 1.x's, checked by `shellcheck` in CI |
| `reference/` | The pinned 1.x commit, the capture plugin and the extra edge-case inputs |
| `testdata/` | Shared test vectors and the recorded 1.x reference |
| `docs/security-lessons.md` | The security requirements every feature meets (IDs like `I1`, `G3`), carried over from 1.x |
| `.github/workflows/` | CI |
