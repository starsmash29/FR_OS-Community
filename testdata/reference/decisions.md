# Where FR_OS 2 deliberately differs from 1.x

Each entry: the date, the owner's decision, which recorded cases change
(their ids, or how to find them), and why. The differential tests read
nothing from here; reviewers do. The config test's `decided`
(config/reference_test.go) picks out each decision's cases.

## 2026-11-08: a host name with a trailing newline is refused

Proposed in FR_OS-Community PR #2; decided with the owner's "Mehet".

- Cases: configs whose `xdp_sni_filter.blocklist` or `adblocker.allowlist`
  has an entry ending in "\n". 1.x accepts them; 2.x refuses them.
- Why: 1.x checks these names with a pattern ending in `$`, which in
  Python also matches before one trailing newline, and stores the name
  with the newline: it would reach the resolver's config file and the XDP
  map key (security-lessons F1). AGENTS.md: anchor every pattern at both
  ends. The 1.x bug is reported for a fix there after 2026-11-09.

## 2026-11-08: integers beyond 64 bits are refused where 1.x has no bound

Proposed in FR_OS-Community PR #2; decided with the owner's "Mehet".

- Cases: configs whose `dhcp.<zone>.lease_time` or
  `adblocker.xdp_critical_limit` is 2**63 or more. 1.x accepts any
  positive integer there; 2.x refuses those beyond int64.
- Why: Python's integers have no size limit, Go's do; no lease or limit
  that large means anything to dnsmasq or the XDP program.

## 2026-11-08: YAML: what a config can't hold is refused

Proposed in FR_OS-Community PR #3 (phase 1b); decided with the owner's
"Mehet". 1.x loads config.yaml with PyYAML's yaml.safe_load; 2.x ports
it (internal/pyyaml, config.LoadYAML) and loads the same values, with
PyYAML's messages, except for these texts, which 2.x refuses:

- **The tags `!!binary`, `!!set`, `!!omap` and `!!pairs`.** Cases:
  yaml.jsonl values with a `bytes`, `set` or `tuple` tag. No config
  value is bytes, a set or a list of pairs, and a set has no order
  (1.x's messages would print it in a different order on each run).
- **An alias inside the node it names** (`a: &x [*x]`). Cases:
  yaml.jsonl with `"recursive": true`. PyYAML builds a list that
  contains itself; nothing in a config can use one, and walking it never
  ends.
- **Nesting deeper than 64 levels.** Cases: yaml.jsonl values nested
  deeper than that. PyYAML's composer recurses, so 1.x crashes with a
  RecursionError a few hundred levels down; 2.x stops well before.
- **More than a million nodes once the aliases are followed**, and a
  config.yaml over 4 MiB (config.ReadFile). No case. A few lines of
  aliases can stand for billions of nodes ("billion laughs"); 1.x reads
  any size (AGENTS.md: every read has a size limit).
- **An escape for a lone surrogate** (`"\ud800"`). Cases: yaml.jsonl
  values with a `surrogates` tag. Python's str holds one, UTF-8 can't;
  no name or address has one.
- **Two `!!float nan` keys in one mapping are one key.** Cases: the
  mappings with two NaN keys. Python keeps both (NaN is not equal to
  itself), except for `.nan`, which PyYAML hands out as one object.

Where 1.x crashes with a Python exception that is not a YAMLError (such
as `!!int x`, `0b_`, `2026-02-30` or `2026-11-01T10:00:00+24:00`), 2.x
refuses the text with its own message; the recorded case says only that
1.x crashed. The same holds for parse_config's crashes on YAML values,
such as sorting unknown keys of different types.

## 2026-11-08: a port given as `true` is refused

Proposed in FR_OS-Community PR #4 (phase 1c); decided with the owner's
"Mehet".

- Cases: configs whose rule `dst_port`, or port forward `dst_port` or
  `to_port`, is `true`. 1.x accepts them (in Python `True` is the
  integer 1) and keeps the value as it is, so the nft script says
  `tcp dport True` and `dnat ip to 10.0.0.5:True`, which nft refuses at
  apply time; 2.x refuses the config instead. `false` was already
  refused by both (port 0 is out of range).
- Why: the config check is the one place a value is validated before it
  reaches the nft script (security-lessons F1); a config that can't be
  applied should not be accepted.

## 2026-11-08: messages

Not a difference today: every refused case is refused with 1.x's own
message, word for word, and the config test checks that. A later change
of wording is recorded here.

## 2026-11-08: the helper's requests

Proposed in FR_OS-Community PR #6 (phase 2a); decided with the owner's
"Mehet".

The apply-helper reads a request as every FR_OS 2 line is read (package
`ipc`, AGENTS.md "one wire format"). 1.x read it with `readline` and
`json.loads`, which let more through. The cases are marked `decided` in
helper.jsonl (reference/test_fros_helper_cases.py); 2.x answers each
with `invalid request: ...` where 1.x answered the command:

- **No newline at the end.** 1.x parsed what came before the end of the
  stream; every 1.x client ends its line with one.
- **Longer than 64 KiB.** 1.x read the first 65536 bytes and parsed
  them, so a longer line whose first 64 KiB happened to be a whole
  object (here: trailing spaces) was taken. 2.x refuses the line.
- **A name twice** (`{"cmd": "apply", "cmd": "ping"}`). 1.x took the last
  one; a peer must not have one side read one command and the other side
  another.
- **NaN and Infinity**, which JSON doesn't have.
- **A lone surrogate** (`"\ud800"`), which isn't text.
- **A byte order mark** before the object. 1.x's `json.loads` of bytes
  skips one.

Where 1.x's message quotes Python's own JSON or codec error ("Expecting
value: line 1 column 1 (char 0)", "'utf-8' codec can't decode ..."), and
in "could not parse nft JSON output: ..." (and, since phase 2c-1, "could
not parse ip neigh output: ..."; since phase 2c-2, "could not read the
IPv6 state: ..."), 2.x says what is wrong in its own words after the
same prefix; the test checks the prefix. Every other
message, refusals and command errors included, is 1.x's word for word.

A command 1.x knows and 2.x doesn't run yet answers `command '<cmd>' is
not in FR_OS 2 yet`; 1.x never sends that, and none is recorded.

## 2026-11-08: applies (phase 2b-3)

Proposed in FR_OS-Community's phase 2b-3 PR; to be decided with the
owner's "Mehet". The apply sessions are apply.jsonl
(reference/test_fros_apply_cases.py); apply/reference_apply_test.go
replays them.

- **The sensors' config copy** (`/etc/fr_os/sensor-config.yaml`, ROADMAP
  SEC-11) is written as one line of flow-style YAML under the same
  header, where 1.x writes PyYAML's block style (`safe_dump`). Cases:
  every session that saves or applies; the replay compares the copy as
  data (the parser daemons read the same values). Why: FR_OS 2 has a
  YAML reader, not PyYAML's emitter; flow YAML with every string
  double-quoted and escaped reads back the same in PyYAML and in
  `config.LoadYAML` (config/flowyaml_test.go checks every value the
  recording loaded), and porting the block emitter would be a second
  YAML implementation to keep right.
- **The schedule record's fingerprint** (`schedule_state.json`,
  `config_fingerprint`) is the SHA-256 of the parsed config as
  deterministic JSON, where 1.x hashes Python's `repr` of it. Cases:
  sessions applying a config with a scheduled rule; the replay compares
  the record without that field. Why: `repr` of Python dataclasses can't
  be reproduced in Go; the fingerprint only has to change when the
  parsed config does. A router upgraded from 1.x re-applies once at its
  next schedule check.
- **Where 1.x let an exception through** (the peer got no reply), FR_OS 2
  replies `{"ok": false, "message": ...}` with what went wrong. Cases:
  steps recorded with `raised`. Why: a client waiting for an answer
  should get one.
- **The host's OpenSSL version** (PQC, hybrid TLS needs 3.5) comes from
  `openssl version` (the library's, when it prints one), where 1.x reads
  its own interpreter's `ssl.OPENSSL_VERSION_INFO`. The replay gives
  both the same version. Why: Go links no OpenSSL; the webUI's libssl
  is the host's, which `openssl version` reports.

## 2026-11-09: moving the webUI, and refreshing the ad-block lists (phase 2c-3)

- **A date reached by two YAML aliases** is written twice by
  `config.DumpYAML`, where PyYAML's `safe_dump` anchors the one date
  object (`&id001` and `*id001`). Cases: the yaml.jsonl texts
  `a: &d 2026-11-01` / `b: *d` and `a: &t 2026-11-01 10:00:00` /
  `b: [*t]` (`dumpDecided` in config/yamldump_test.go). Why: a date is
  a value in Go, not an object with an identity; the text reads back to
  the same values, and no setting of a config takes a date. Lists and
  mappings keep their identity, and are anchored as in PyYAML.
- **Ad-block downloads** have a 15 s limit to connect, for the TLS
  handshake and for the response's headers, and 120 s and 64 MiB for
  the whole download, where 1.x has 15 s for each blocking socket
  operation and no size limit (AGENTS.md: every read from the network
  has a size limit). A download that fails in any way counts as a failed
  source, where 1.x lets a timeout while it reads the body through (the
  peer gets no reply). The sources that failed are listed in the order
  the config gives them, where 1.x lists them in the order their
  downloads ended (Python's `as_completed`). Cases: none; the recording
  answers every download from its table, and has at most one failed
  source in a list of several. Why: a refresh must end, and say which
  sources failed in an order that doesn't change from one run to the
  next.

## 2026-11-09: a second ruleset backup in the same second gets a file of its own

1.x names a ruleset backup `ruleset-<UTC second>.nft`, so a backup
written in the same second as the one before (an apply and its revert,
or two applies, one right after the other) replaced it, and that
rollback point was gone. FR_OS 2 gives the first backup of a second 1.x's
name and the later ones `_01`, `_02`, ... (`apply.writeNewBackup`); these
sort after it, so the newest backup is still the last one, the one
`rollback` loads, and 1.x's own `list_backups` counts them. Cases: none
of the recorded ones writes two backups in one second; the run of the
1.x webUI against the Go helper (2026-11-09) showed it. Why: losing a
rollback point silently is worse than a name 1.x never makes. The 1.x
bug is to be reported there too.

## 2026-11-09: the webUI (phase 3a-1: sign-in, accounts, second factors, the apply buttons)

`webui` replays every recorded webUI session (`webui.jsonl`) step for
step: status, headers, body, helper requests and the files left. Where
it differs from 1.x on purpose:

- **Pages are compared as HTML tokens**, entities decoded and
  whitespace collapsed, not byte for byte: Jinja and `html/template`
  write the same page with different spacing and escapes. JSON bodies,
  redirects and cookies are compared exactly.
- **Not ported yet:** every screen other than the dashboard and the
  account pages answers `501 {"detail":"Not ported to FR_OS 2 yet"}`
  after signing in, until 3b-3d.
- **No `/docs`, `/redoc` or `/openapi.json`.** 1.x's FastAPI serves
  them to anyone, signed in or not, which lists every route and form
  field; FR_OS 2 doesn't (they answer 404). The 1.x finding is to be
  reported there.
- **Static files** carry an ETag of their content and no
  Last-Modified (Starlette uses the file's size and time); the replay
  ignores both headers.
- **Session cookies** compress their payload with Go's zlib, whose
  output can differ from C zlib's for the same input; either reads the
  other's, and the replay's cookies are short enough not to be
  compressed. Cases: none differ.
- **Security keys** are checked with go-webauthn, which normalizes the
  origin and accepts `crossOrigin`, as py_webauthn does. The sign count
  must go up unless both counts are 0 (1.x's rule).
- **fr-webui** makes its self-signed certificate with crypto/x509 (RSA
  2048, 10 years, the same names) instead of running `openssl req`, and
  recognizes 1.x's own pre-phase-20 certificate by parsing it (CN and
  issuer exactly `fr-router`, no subjectAltName) instead of by
  substring of `openssl x509` output. Go's TLS doesn't read OpenSSL's
  config, so the unit has no `OPENSSL_CONF`; Go's default key exchange
  already prefers X25519MLKEM768, and with PQC on the listener is TLS
  1.3-only, as in 1.x.
- **A POST to /apply while the apply-helper is down** is a 500, as in
  1.x; a clearer message is left for later.

## 2026-11-09: the dashboard and the QR code (phase 3a-2)

The dashboard (`GET /`) is replayed in every session of webui.jsonl:
a full config, one whose services can't be reached, an invalid config,
a clean one, and the apply-helper gone. Cases: none differ. Decided:

- **Integrity is always unknown.** 1.x checks FR_OS's installed files
  against a recorded hash list; FR_OS 2 has no such list yet, so the
  security score's integrity item is "unknown" and counts neither way
  (in the recorded sessions 1.x's is unknown too: the fake root has no
  list).
- **`systemctl is-active` gets 10 seconds.** 1.x waits for it without a
  limit (ai_ids.daemon, tlsfp.daemon); FR_OS 2 gives it 10 seconds and
  shows the daemon as not running after that. The program and its
  arguments are the same.
- **The "quantum-safe" badge** is read from the same OpenSSL fragment as
  in 1.x. Go's TLS doesn't read it and always offers X25519MLKEM768, so
  with PQC off the session can be hybrid while the badge says
  "Classical only"; the badge says what the config asks for, as in 1.x.
- **The dashboard is a 500 when the apply-helper is gone**, as in 1.x
  (its HelperError isn't caught there; an OSError would be). A page
  that shows what it can without the helper is left for later, and the
  1.x behaviour is to be reported there.
- **QR codes** are drawn by FR_OS 2's own encoder, held to segno 1.6.6
  (qr.jsonl: each mode, versions 2-33, every remainder length, a raised
  error level, both scales). It refuses what no page draws: a text short
  enough for a Micro QR Code, and one that isn't Latin-1 (segno would
  use Shift JIS or UTF-8); the TOTP page then shows no code, only the
  secret. Cases: the three such texts in qr.jsonl.

## 2026-11-09: the filtering screens (phase 3b-2)

The ad-block and local DNS, application control, TLS fingerprint, XDP
SNI filter, IoT and AI-IDS screens are replayed in eighteen sessions
of webui.jsonl (each screen shown, saved, refused and off, its state
files missing, unreadable or odd, the apply-helper answering, refusing
and gone). Cases: none differ. Decided:

- **`ip -j link show` gets 10 seconds**, as `systemctl is-active` does
  (3a-2). 1.x waits for it without a limit (frfw.xdp._run_ip); FR_OS 2
  shows the filter as not attached after that. The program and its
  arguments are the same.
- **The XDP live log stream** (`/xdp/logs/stream`, server-sent events
  from the journal) is left for phase 3c with the other read-only
  views; the XDP page and its script are ported, so the page shows
  "Connecting" until then.
- **The harness** now records the case's root form-encoded in a
  redirect (a helper error's socket path in `?error=`) as `@ROOT@`
  form-encoded, and the replay compares pages and headers with its own
  root put back the same way. No recorded case changes otherwise.

## 2026-11-09: the ZTNA gate, the VPN and the system screen (phase 3b-3)

The ZTNA gate (admin settings, the public sign-in and status pages, an
account locked out), the WireGuard VPN screen (devices with their own
key and with a key pair the router makes, shown once with its QR code)
and the system screen are replayed in thirteen sessions of webui.jsonl.
Cases: none differ. Decided:

- **The TLS library the system screen names** is "Go crypto/tls
  (X25519MLKEM768)". 1.x shows the host's OpenSSL version, the library
  its webUI speaks TLS through; FR_OS 2's webUI uses Go's crypto/tls,
  which always offers the hybrid group, so the screen says that. The
  harness sets 1.x's `ssl.OPENSSL_VERSION` to the same text.
- **Software integrity is not verifiable** on FR_OS 2 yet: it keeps no
  list of its files' hashes. The card says "FR_OS 2 keeps no list of its
  files' hashes yet"; the harness has 1.x's integrity check give that
  report, so the dashboard's integrity item stays "unknown" as in 3a-2.
- **A VPN device's key pair** is made from the case's recorded random
  bytes in the harness (X25519 from 32 bytes), as FR_OS 2 makes it from
  its own random source.
- **The harness keeps mount points unmoved**: the live medium and the
  persistence mounts are paths as the kernel reports them in
  /proc/mounts, not files under the case's root, so 1.x's
  `persistence.LIVE_MEDIUM_MOUNT` and `LIVE_PERSISTENCE_PREFIX` are no
  longer rerooted. No earlier case had a live system, so none changes.

## 2026-11-10: the security checklist, the attack surface and the update screen (phase 3c-1)

The security checklist, the attack-surface view and the update screen
(with its two settings) are replayed in twenty-one sessions of
webui.jsonl. The update check's request to GitHub answers from the
case's table like the helpers do. Cases: none differ. Decided:

- **FR_OS 2 looks for its releases in starsmash29/FR_OS-Community**
  unless `update.repo` names another repository; 1.x's default is its
  own repository, FR_OS-pblk. The harness sets 1.x's
  `update.DEFAULT_REPO` to the same, so the page and the request match.
  As in 1.x, the screen asks GitHub when an admin opens it, and nothing
  else in the webUI goes to the internet.
- **The update-helper's actions are not ported yet**: installing a
  release, rolling back, and checking, trying or cancelling a kernel
  answer 501 until the update-helper is ported in its own phase. The
  page shows the same forms as 1.x; no recorded step posts them. The
  kernel card asks the update-helper's `kernel_status`, and with no
  update-helper says it did not answer, as 1.x does when it is down.
- **GitHub's answer is bounded** at 1 MiB; a larger one is a failed
  check. An answer that isn't JSON is reported with Go's parser
  message, which differs from Python's; no case records one.
- **The release's version digits are ASCII.** 1.x's `\d` also takes
  other Unicode digits in a tag; FR_OS 2 reads such a tag as not
  MAJOR.MINOR.PATCH, so a different tag still means a new release.

## 2026-11-10: the Prometheus metrics and the XDP live log (phase 3c-2)

`/metrics` and `/xdp/logs/stream` are replayed in fourteen sessions of
webui.jsonl: ten scrapes (metrics off, refused tokens, a malformed
digest, the cache, a quiet machine, odd values, a value that fails the
answer, an invalid config, the helper gone) and four live logs (lines
of every shape, a line too long, no `tail`, an empty log). The live
log's `tail -F` answers from the case's program table and ends when its
output does. Cases: none differ. Decided:

- **The scrape cache is keyed by the config's repr**, not by
  `json.dumps(sort_keys=True)`. It serves the same text for the same
  config for 15 s; unlike json.dumps it never fails (1.x answers 500
  when a mapping's names mix types and can't be sorted). No case has
  such a config.
- **A live-log line nested deeper than 512 levels is dropped.** 1.x's
  json.loads raises RecursionError near Python's recursion limit, which
  ends the stream. The SNI logger's lines don't nest.
- **A sensor state file over 16 MiB reads as missing**, as on the
  filtering screens (3b-2).

## 2026-11-13: TLS client fingerprinting (phase 4a)

Proposed in FR_OS-Community PR #27; decided with the owner's "Mehet".

`crates/fros-tlsfp` replays every case of tlsfp.jsonl
(`reference/test_fros_tlsfp_cases.py`): ClientHellos, record streams,
reassembly, the inventory and its state file. Hellos, records,
reassembly and the inventory's own updates: none differ. Restoring the
inventory from its state file: nine cases differ, listed by name in
`DECIDED` (crates/fros-tlsfp/tests/reference.rs). Decided:

- **Where 1.x's restore raises an exception it doesn't catch, FR_OS 2
  starts with an empty inventory.** 1.x's daemon dies on such a file
  (an int too large for a float, a non-dict `clients` or
  `network_first_seen`, a number in place of `events`, bytes that
  aren't UTF-8, an int over 4,300 digits, nesting deeper than Python's
  recursion limit) and systemd restarts it onto the same file, for
  good. The recorded cases keep 1.x's exception name; the replay
  expects an empty inventory for them. They all pass.
- **A list or dict inside a row's `ja3` or `sni` skips the row.** 1.x
  writes its Python repr (`"[]"`, `"{'k': 'v'}"`) into the list, which
  would need Python's repr of any string, Unicode tables included.
  Cases: "ja3 item list", "ja3 item empty list", "ja3 item dict",
  "ja3 item empty dict", "ja3 nested".
- **Numbers written as text take ASCII digits only.** Python's `int()`
  and `float()` also read other Unicode decimal digits ("\u0669" is 9).
  Cases: "started '\u0669'", "first_seen '\u0669'", "count '\u0669'".
- **A lone surrogate escape ("\ud83d") reads as U+FFFD.** Python keeps
  it in the string; a Rust string can't hold one. Case: "lone high in
  key" (a client named by one). A lone surrogate in a value the
  inventory ignores changes nothing.
- **Nesting is capped at 10,000 levels**, refused as Python's recursion
  limit refuses deeper nesting. Where exactly Python's limit falls
  depends on its version and stack; the cases nest 5,000 levels (read
  by both) and 100,000 (refused by both).

The state file's size cap, and what the daemon does with what it
restores, came with the daemon (phase 4e-1, below).

## 2026-11-13: application identification and AI-IDS scoring (phase 4b)

Proposed in the FR_OS-Community PR for phase 4b.

`crates/fros-appid` replays every case of appid.jsonl
(`reference/test_fros_appid_cases.py`): the catalog parser and its
error texts, name matching, blocking lists, the usage tracker and its
state file, the daemon's de-duplication and its two line readers.
`crates/fros-aiids` replays every case of aiids.jsonl
(`reference/test_fros_aiids_cases.py`): the DGA heuristic, Python's
`statistics.mean`/`pstdev` and `round`, every `evaluate()` of the
anomaly engine, and the AI-IDS daemon's two line readers. The shared
Python rules (JSON dialect, dict order, text classes, exact float
arithmetic) moved into `crates/fros-sensor`, which fros-tlsfp now uses
too; no tlsfp case changes.

Python's exact arithmetic is reproduced, not approximated: the mean and
standard deviation of a host's baseline are exact fractions rounded
once (num-bigint), `round(x, n)` rounds the float's exact value ties to
even, and the entropy sum is Neumaier-compensated as Python 3.12+'s
`sum`. All recorded scores match to the last bit. `str()` and `repr()`
of any JSON value (catalog entries, error texts) are Python's, with its
Unicode tables generated from the recording Python
(`crates/fros-sensor/gen_unicode_tables.py`).

Nine cases differ, listed by name in `DECIDED`
(crates/fros-appid/tests/reference.rs, crates/fros-aiids/tests/reference.rs).
Decided:

- **A lone surrogate escape reads as U+FFFD**, as in phase 4a. Cases:
  usage "lone surrogate key"; appid and AI-IDS sni_line with
  `"\ud800x"` / `"\udc00"`.
- **Numbers written as text take ASCII digits only**, as in phase 4a;
  such a usage row is skipped. Cases: usage `first_seen "١"`,
  `last_seen "١"`, `bucket count "١"`.
- **A usage hit count or bucket past i128 skips the row.** Python keeps
  `int(1e308)`, a 309-digit int; nothing the daemon writes comes near
  i128. Case: usage `bucket count 1e+308`.
- **An SNI event line nested past Python's recursion limit is skipped.**
  In 1.x the RecursionError escapes the line reader and ends that
  reader's thread, so the daemon stops reading the event file until it
  restarts. Cases: appid and AI-IDS sni_line `[[[[...`.

Where 1.x's usage restore raises an exception it doesn't catch (an int
too large for a float, an infinite hit count), `UsageTracker::restore`
returns that exception's name, as recorded (these cases pass); what
the daemon does then (1.x's dies at start) is decided with the daemon
(phase 4e-2, below), as for the TLS inventory.

Which sources the AI-IDS daemon scores (internal networks, IPv6 hosts
by MAC), its conntrack sampling and its quarantine came with the daemon
(phase 4e-2, below); the line readers here only parse, and the case file records
them with every source passed through.

## 2026-11-13: IoT discovery (phase 4c)

Proposed in the FR_OS-Community PR for phase 4c.

`crates/fros-iot` replays every case of iot.jsonl
(`reference/test_fros_iot_cases.py`): MAC normalization and vendor
lookups; the IEEE registry read through a port of CPython's `csv`
reader (quoting, line ends, bad UTF-8, the 131,072-character field
limit and its `_csv.Error`); the kernel's neighbour table (Python's
`splitlines`, `split` and `int(flags, 16)`, its UnicodeDecodeError on
bad UTF-8); the mDNS query and its parser over handcrafted, damaged and
random packets; the IoT scoring; whole scans (messages, devices, the
helper calls and the inventory file byte for byte); and the resync
from an inventory. No case differs; `DECIDED` is empty.

Decided:

- **The scanner reads a per-sensor JSON view, never the YAML config.**
  The Go side writes it at apply time (phase 4e): the IoT zones'
  interfaces in config order with their static address as
  `a.b.c.d/len` or null, `trusted_macs`, `isolated_macs`,
  `auto_isolate` and `isolation_mode`. The case file records each
  scan's view and has 1.x scan a config built from it, so the view is
  all a scan reads.
- **The files the scanner reads have a size limit** (AGENTS.md: every
  read has one; 1.x has none): an IEEE registry past 64 MiB reads as
  missing (today's is about 3 MB), the neighbour table is read up to
  16 MiB. No case reaches either.

The helper calls (`dhcp_leases`, `iot_sync_isolation`), the mDNS
socket (`discover`), writing the inventory file and what the daemon
does when a scan hits an exception 1.x doesn't catch (recorded here by
name, as `Crash`) came with the daemon (phase 4e-3, below).

## 2026-11-13: the XDP program's kernel side (phase 4d-1)

`crates/fros-xdp-ebpf` is 1.x's `bpf/xdp_sni_filter.c` in Rust (aya):
the filter (`xdp_sni_filter`), the split-hello follower
(`xdp_sni_split`) and the IPv6 path (`xdp_sni_filter6`), reached
through `split_prog` as in 1.x, with 1.x's maps: the same names, types,
key and value sizes, layouts and stat indices. `crates/fros-xdp`'s
replay loads it and has the kernel run it on every frame of xdp.jsonl
(`reference/test_fros_xdp_cases.py`, recorded by
`reference/generate-xdp.sh` from 1.x's C program at PIN): each frame's
verdict, the counters it moved, the events and hello copies it
reported (every field the C program sets) and the flows left in
`sni_flows` and `hello_flows`. No case differs; `DECIDED` is empty.

How the program reads differs, not what it answers:

- **Past the TCP header, the packet is read with `bpf_xdp_load_bytes`**
  into per-CPU scratch space and parsed there at masked offsets; 1.x
  read the ClientHello through packet pointers. A read fails where the
  frame ends either way (the program isn't a frags one: the frame is
  one buffer), so the frame and datagram bounds (SEC-7, SEC-20) fall in
  the same places. The first segment's copy is 16 KiB, more than any
  read of the parse can reach.
- **The first segment's extension walk and the name's normalization
  run as `bpf_loop` callbacks**, as 1.x's follower walk already did.
  BPF has no conditional move: unrolled, each byte's condition doubles
  the paths the verifier walks, and the program ran out of its
  1,000,000-instruction budget. Kernel needs are unchanged: 1.x already
  required `bpf_loop` (5.17) and `bpf_xdp_load_bytes` (5.18);
  `bpf_xdp_get_buff_len` is 5.18 too.

Not reached by the recording, checked by reading against the C instead:
the clamp of a declared extensions length at 4095 bytes (it needs more
than 4 KiB of extensions in one frame, a jumbo frame;
`BPF_PROG_TEST_RUN` takes at most a page), and the pass events' backlog
cap (128 KiB of unread events; the replay reads them after each frame).

The recording was checked by breaking the port on purpose: some 60 changes,
each a boundary moved by one, a check dropped or a field written wrong;
every one that changes an answer fails the replay. Those that slipped
through the first corpus (the follower's segment limit, a handshake
across records, sequence numbers wrapping, the extensions length
against what follows it, a cipher list of 513 bytes, a fragment header
after a fragment header) got cases. The loader (pinning, attaching,
GRO, the blocklist sync, reading the events) comes in phase 4d-2.

## 2026-11-13: the XDP filter's loader and its apply (phase 4d-2)

An apply now turns the XDP SNI filter on, keeps it, replaces it and
turns it off as 1.x's `frfw.xdp.sync_sni_filter` does: the same state
file (`xdp_state.json`), the same attach order (native, then generic),
GRO off where it runs in generic mode and back on where FR_OS turned it
off, the blocklist synced before any attach, the switches, the readers
restarted, and the same undo. The apply cases record it (the "xdp" and
"xdp_failure" sessions of `reference/test_fros_apply_cases.py`); the
decision that refused every such apply is gone, and the sessions that
had it now replay in full. What the userland reads from the program
(the event and hello-copy records, the event logger's line and its
file) is recorded in xdpuser.jsonl (`reference/test_fros_xdpuser_cases.py`)
and replayed by `crates/fros-xdp/tests/xdpuser.rs`; the blocklist keys
of the same file by `apply/reference_xdp_keys_test.go`.

- **bpftool is `fr-xdp`** (`crates/fros-xdp`, `/usr/libexec/fr_os/fr-xdp`):
  bpftool loads through libbpf, which no longer reads the legacy `maps`
  section aya's maps are declared in, and decodes map dumps only through
  BTF the aya maps don't carry. The replay holds the apply to the
  recording through one translation of the calls, written out in
  `apply/reference_xdp_test.go`: `prog loadall ... pinmaps` is
  `fr-xdp load`, `-j prog show pinned` is `fr-xdp prog-id` (the same
  JSON), the settings update is `fr-xdp settings` with the bits in
  decimal, the stats dump is `fr-xdp stats` (the same JSON), and the
  blocklist's dump with its deletes and updates is one `fr-xdp
  blocklist` call whose input is every key wanted, one hex line each.
  Its failures carry 1.x's messages (`Dumping ... failed:`, `Deleting
  from ... failed:`, `Updating ... failed:`). 1.x's message for a
  missing bpftool is FR_OS 2's for a missing fr-xdp (it ships with
  FR_OS, so a missing one is an incomplete installation). Cases: the
  xdp sessions that run bpftool, and `xdp/no bpftool`.
- **GRO is read and set with the SIOCETHTOOL ioctl in Go**
  (`apply/gro_linux.go`), as 1.x does from Python; the recording
  represents each ioctl as a call `["ioctl", "SIOCETHTOOL", device,
  command(, value)]` (rc the errno), which the replay's GRO hooks make.
  No case differs.
- **Attaching and detaching stay `ip link set dev X xdpdrv|xdpgeneric
  pinned P`**, as in 1.x: iproute2 attaches a program aya pinned
  (`apply/xdp_root_test.go` does it on a veth, as root). No case
  differs.
- **The blocklist keys are built in Go** (`apply.LPMKey`), as 1.x builds
  them in the apply, so a name the kernel map can't hold is refused
  with 1.x's message at the preflight, before anything changes. No case
  differs.
- The event logger daemon (who owns the event file, and dropping its
  privileges) came in phase 4e-1, below.

## 2026-11-14: the SNI event logger and the TLS fingerprinting daemon (phase 4e-1)

`fr-xdp-sni-logger` and `fr-tls-fp` are 1.x's `frfw.xdp.run_event_logger`
and `frfw.tlsfp.daemon`, in Rust. `testdata/reference/tlsfpd.jsonl`
(`reference/test_fros_tlsfpd_cases.py`) records 1.x's daemon fed ring
buffer records at given clocks, asking a fake apply-helper that answers
given bytes, and writing its state file; and 1.x's helper client
(`frfw.helper.client.send_command`) alone. `crates/fros-tlsfp/tests/daemon.rs`
replays it: the same requests, counts and state files, byte for byte.

- **The sensors read a JSON view of the config, not the YAML copy.**
  Next to `sensor-config.yaml` an apply writes `sensor-view.json`
  (root:fr_os-sensor 0640, `apply.SensorView`): what each daemon reads,
  checked by the config package, or `{"config_error": message}` for a
  config the checks refuse. It holds `tls_fingerprint` now; the
  daemons of phases 4e-2 and 4e-3 add their own members. The Rust daemons would otherwise need a
  second YAML reader and a second copy of the checks. With a
  `config_error` the daemon keeps the settings it has, as 1.x's daemon
  keeps them when its own parse fails. The apply replay checks the view
  against the recorded YAML copy; no case differs.
- **A state file that can't be restored is put aside, and the daemon
  starts afresh** (owner's decision): renamed to
  `tls_fingerprints.json.broken`, logged, and an empty inventory with a
  new learning period. 1.x dies at start on a file it can't restore
  (not JSON, too deeply nested, members of the wrong type), and systemd
  restarts it into the same crash. The cases 1.x dies on
  (`crash` at the case) are replayed with 1.x's steps recorded without
  the file. A file larger than 16 MiB is put aside unread, where 1.x
  reads any size (`oversized_state_put_aside`).
- **A helper reply that isn't a JSON object is a failed quarantine**:
  `quarantine failed: the apply-helper's reply is not an object: ...`.
  1.x dies on it (`AttributeError` on `.get`); the cases where it does
  (`crash` at the step) end there, checked for that message.
- **A state file that can't be written is logged and tried again at the
  next flush.** 1.x dies and loses what it holds.
- **A reply 1.x's client lets an exception through for** (bytes that
  don't decode in the encoding `json.loads` guesses, nesting past the
  recursion limit) is recorded as `raised` with the exception's name,
  and is `HelperError::Raised` here; the daemon reports it as a failed
  quarantine, where 1.x dies. A lone surrogate in a reply becomes
  U+FFFD, as everywhere in FR_OS 2.
- **The logger and the daemon drop privileges as 1.x's
  `frfw.privdrop`**: fr_os-sensor (nobody when it doesn't exist),
  fr_os-feeds besides, checked to have left root; the event file is
  opened as root first, its group the process's own, mode 0640.
  `apply/xdp_root_test.go`'s `TestXdpReadersRealAttach` runs both on a
  real attach, as root: the drop is logged to the root-owned event file,
  the hello fingerprinted with 1.x's JA4 and JA3, and neither keeps root.

## 2026-11-14: the application identification and AI-IDS daemons (phase 4e-2)

`fr-appid` and `fr-ai-ids` are 1.x's `frfw.appid.daemon` and
`frfw.ai_ids.daemon`, in Rust. `testdata/reference/sensord.jsonl`
(`reference/test_fros_sensord_cases.py`) records what each takes from a
config (op `view`), 1.x's appid daemon started on a usage file and fed
log lines at given clocks (op `appid`), and 1.x's AI-IDS daemon fed log
lines, conntrack samples and evaluations at given clocks, asking a fake
apply-helper on a Unix socket that answers given bytes (op `aiids`).
`apply/reference_sensorview_test.go`, `crates/fros-appid/tests/daemon.rs`
and `crates/fros-aiids/tests/daemon.rs` replay it: the same view, the
same usage files, requests, printed lines, flagged events and event
logs, byte for byte. The `tests/e2e.rs` of both crates run the real
binaries on real files and, for fr-ai-ids, a real Unix socket.

- **The sensors' view gains `app_control` and `ai_ids`.** `app_control`
  is the sources fr-appid follows (1.x's `source_units`: "dns" with
  app control, ad-block DNS and its query log on; "sni" with the XDP
  filter and `observe_sni` on). `ai_ids` is the switch, the excluded
  MACs (lowercase) and the reservation addresses they resolve to
  (`resolve_excluded_ips`), the networks scored (`internal_networks`),
  the configured addresses never quarantined (`infrastructure_ips`
  without the routing table and resolv.conf, which the daemon reads at
  each evaluation, as 1.x), the threat categories whose answers count,
  whether the resolver writes its query log, and the quarantine time.
  Every recorded view matches.
- **The log files are followed natively, not with `tail -n 0 -F`**
  (`fros_sensor::follow`): new lines only, a file missing at start read
  from its start once it appears, an emptied or replaced file read
  again from its start, polled from the daemon's own loop. A line
  longer than 64 KiB is dropped whole, at most 1 MiB is read per poll
  (AGENTS.md: every read has a limit; `tail` has none), and bytes that
  aren't UTF-8 read as U+FFFD, where 1.x's reader thread dies on them
  and the daemon reads that log no more until it restarts.
- **A usage file 1.x dies on at start is put aside, and fr-appid starts
  afresh**, as the TLS inventory (phase 4e-1): one that isn't UTF-8,
  nests too deep or holds counts 1.x's restore raises on, and one past
  16 MiB, unread. A file that isn't JSON or holds no usage starts empty,
  as in 1.x. The cases 1.x dies on (`crash` at the case) are replayed
  with the steps of 1.x started without the file
  (`oversized_usage_put_aside` checks the size cap). A usage file that
  can't be written is logged and tried again at the next flush.
- **fr-ai-ids reads the view again at every window, and starts over as a
  new process when its part changed** (owner's go-ahead on the plan).
  1.x reads its config once, at start, and the webUI tells the
  administrator to restart the service. Started with `ai_ids.enabled`
  off it exits, as 1.x does; turned off while running, it starts over
  and so exits. A missing view, or one written from a refused config,
  keeps the settings it has. fr-appid starts over when its sources
  change, as 1.x re-executes itself.
- **Where 1.x dies on what the apply-helper answers, fr-ai-ids logs it
  and goes on**: a reply that isn't an object (to a sample or a
  quarantine: `AttributeError`), flows that are a number, a bool or
  null (`TypeError`), a flow whose fields are lists or objects (Python
  can't hash the key; that flow is skipped), and a reply 1.x's client
  lets an exception through for (`HelperError::Raised`). Cases:
  "conntrack flows a number", "conntrack reply a list", "helper reply
  not an object" (`crash` at the step): the recorded requests and lines
  are a prefix of what FR_OS 2 sends and prints, and the replay stops
  there.
- **An event log 1.x can't read is read as empty**: one that isn't
  UTF-8 (1.x dies, `UnicodeDecodeError`), nests too deep, or is past 1
  MiB (1.x writes at most 50 events). The new event is then all it
  holds. Case: "event log not utf-8" (`crash` at the step);
  `event_log_not_utf8_starts_afresh`. An event log that can't be written
  is logged; the quarantine stands.
- **A lone surrogate in the event log is written back as U+FFFD**, as
  everywhere in FR_OS 2. Case: "event log odd values".
- **The routing table and resolv.conf are read up to 1 MiB, bytes that
  aren't UTF-8 as U+FFFD**; a default route whose gateway `int(x, 16)`
  reads as negative or past 32 bits is skipped, where 1.x dies
  (`OverflowError` from `to_bytes`). The kernel writes neither.

## 2026-11-14: the IoT scan (phase 4e-3)

`fr-iot-scan` is 1.x's `frfw.iot.scanner.main`, in Rust: one scan,
started by `fr-iot-scan.timer` (2 minutes after boot, then every 10,
as 1.x) and by the webUI's "Scan now" (the helper's `iot_scan`).
`testdata/reference/sensord.jsonl` records the IoT part of each
config's view (op `view`), 1.x's scan with its two helper calls going
through its real client to a fake apply-helper answering given bytes
(op `iotscan`), and 1.x's mDNS discovery on a real UDP socket aimed at
a fake responder on loopback that answers from given addresses and
ports (op `mdns`). `apply/reference_sensorview_test.go` and
`crates/fros-iot/tests/system.rs` replay it: the same view; the same
requests, messages and inventory, or the same exception; the same
query (less its random id), sent as many times, and the same services
found, or the same error. `crates/fros-iot/tests/e2e.rs` runs the real
binary against a fake helper and a fake responder.

- **The sensors' view gains `iot`**, the shape phase 4c decided: the
  switch, every interface in an IoT zone in config order with its
  static address or null (1.x's `_iot_interfaces`), the trusted and
  isolated MACs as the config normalizes them, `auto_isolate` and the
  isolation mode. Every recorded view matches.
- **Where 1.x's scan dies, `fr-iot-scan` prints
  `error: scan failed: <exception>`, exits 1 and leaves the last
  inventory as it was** (owner's go-ahead on the plan): a helper reply
  that isn't UTF-8 or nests too deep (`HelperError::Raised`), one that
  isn't an object, and the scan's other `Crash` cases. 1.x dies with a
  traceback and, as here, writes nothing. A view that is missing, not
  JSON, written from a refused config or without a valid `iot` member
  is an `error:` line and exit 1 too (1.x dies reading its config).
- **mDNS goes through `socket2`** (`=0.6.3`, MIT/Apache-2.0), for the
  one option std doesn't set: `IP_MULTICAST_IF`, so the query leaves
  through each IoT interface in turn. Everything else is 1.x's: the
  socket bound to port 53530 on every address, TTL 255, the query
  once per address, answers until 2 seconds are up or 512 have come,
  read into a 9000-byte buffer (a longer datagram is cut, as 1.x's
  `recvfrom`), only from port 5353 and never from the router's own
  addresses, at most 64 service types per host. The query id is random,
  as 1.x's; the cases record the query without it.
- **The inventory is written as 1.x writes it** (`<path>.tmp`, then
  moved over the file, its directory made first); a write that fails
  is an `error:` line after the messages and exit 1, where 1.x dies.

## 2026-11-14: firewall-cli, the router's own commands (phase 4f-1)

`firewall-cli` is the part of 1.x's `frfw.cli` the router's units run:
the boot's apply in fail-closed mode (`fr-firewall.service`), an apply
from the console (held with `--confirm-within`, or not), `validate`,
`render`, the hourly `schedule-check` with the rule hit counters, the
`dns-log-trim`, the `adblock-refresh` and `ensure-accounts`
(`fr-accounts.service`). `reference/test_fros_apply_cases.py` records
it as steps `{"cli": argv}` of the apply sessions, against the same
fake system (`cli/...`): the exit status, what it printed on stdout and
stderr, the programs it ran and the files it left. For ensure-accounts
the case gives the accounts there are (`accounts`), which useradd,
groupadd, usermod and gpasswd change in both fakes, with each chown
recorded as a call; a setup file may be `{"size": n}` (n zero bytes,
for the query log past its 16 MiB) or carry `@FP@`, the fingerprint of
the setup's config as each implementation computes its own.
`apply/reference_apply_test.go` replays every step through
`helper.Server.CLI`.

- **A command line argparse refuses (exit 2) is held to its exit status
  only.** Cases: `cli/usage`. Why: argparse's usage text lists every
  command 1.x has; 2.x prints its own, of the commands it has.
- **Where 1.x dies with a traceback, 2.x prints `error: <text>` (or
  `KeyError: <name>` for an account that isn't there) and exits 1, as
  1.x does.** Cases: steps recorded with `raised`
  (`cli/accounts/no root account`, `cli/accounts/no feeds group yet`).
- **The config's fingerprint now covers every value.** `Ordered`
  mappings (interfaces, zones, DHCP zones, ...) were written to the JSON
  the fingerprint hashes by their keys alone, so two configs that
  differ only inside them had one fingerprint: the schedule check would
  have re-applied an edit saved but never applied, and the boot would
  not have tried the last applied config when it differs from
  config.yaml only there (`cli/boot, fails, the last applied works`).
  They are written with their values now. The fingerprint is still
  2.x's own (above, "The schedule record's fingerprint"), so no recorded
  case changes.
- **The rule hit counters' error for nft output that isn't JSON is
  2.x's parser's text** after the same `rule hit counters not
  recorded: ` (no case records one).
- **Not ported in 4f-1:** `initial-password` moves to phase 4f-2 with
  the first boot, whose admin account store it reads; the commands no
  unit runs (`apply-status`, `apply-confirm`, `apply-revert`,
  `rollback`, `management-addresses`, the status views, the update and
  kernel commands) come with the phases that need them.
- **The recording appends the `cli/` cases to the committed ones.** A
  whole regeneration in this container gives a different sample of
  accepted configs (1.x's suite fails some environment-bound tests
  here) and another order of the XDP blocklist's keys (Python's hash
  seed); the recorder's other cases came out the same, so they were
  kept as they are.

## 2026-11-14: first boot's commands (phase 4f-2a)

The `firewall-cli` commands first boot and its units run, held to 1.x's
`frfw.cli`: `detect-interfaces`, `detect-wan-lan` (with each port's DHCP
probe, SEC-8, and the LAN address out of the offered network's way,
NET-12), `assign-interfaces`, `set-admin-password` (`--generate`,
`--show-on-console`, or by hand), `mfa-reset`, `initial-password`,
`console-ports` (`--print`, `--watch`, or a refresh) and `persistence
status|auto|create`. `reference/test_fros_apply_cases.py` records them
as `cli/first boot/...` sessions against the fake system: a sysfs tree
of ports and block devices (setup entries `{"link": target}` are
symbolic links, and the tree records them so, never followed), the
programs' answers (`ip`, `agetty`, `blkid`, `sfdisk`, `blockdev`,
`mkfs.ext4`, `mount`, ...) from the table, each DHCP probe as the
pseudo-call `["dhcp-offer", device]` (its output the network offered,
none for no answer), and a step's password prompts answered from its
`passwords`. `reference/test_fros_netdetect_cases.py` records the probe's
frames (`netdetect.jsonl`): the DHCPDISCOVER 1.x sends, byte for byte,
and the network it reads from offers built, masked every way and
damaged at random; `apply/reference_netdetect_test.go` replays them, and
`apply/netdetect_root_test.go` sends the real probe over a veth to a
responder, as root, in a network namespace of its own.

- **Where 1.x dies with a traceback, 2.x exits 1 with a line saying
  what (as in phase 4f-1).** Cases: `cli/first boot/wan/lan, the
  upstream everywhere` (no LAN address left outside 0.0.0.0/0),
  `cli/first boot/admin password, by hand` (the end of input at the
  prompt, Python's EOFError), `cli/first boot/persistence, no size`
  (blockdev printed nothing).
- **The persistence filesystem's mount point is removed only when
  empty.** 1.x mounts it in a `tempfile.TemporaryDirectory`, whose
  cleanup is `shutil.rmtree`: had the `umount` failed, it would have
  deleted what it just wrote on the new filesystem. 2.x removes the
  empty directory alone. No recorded case changes: the mount point is in
  the temporary directory, outside the case's tree.
- **The ports' DHCP probes are compared as a set.** 1.x asks every port
  at once (a thread pool), and so does 2.x (a goroutine each); the
  recording ran them in order, one after another, so the replay puts
  each run of `["dhcp-offer", device]` calls in device order before
  comparing. Every other call keeps its place.
- **The recording appends the `cli/first boot/` cases to the committed
  ones**, for the reason phase 4f-1 gives.

The scripts first boot runs, `scripts/fr-first-boot.sh` and
`scripts/install-system-integration.sh`, stay shell, line for line
1.x's, with firewall-cli from `/usr/libexec/fr_os`; they start only the
units 2.x has (the update and kernel units come with phases 4f-3 and
4f-4), and the integration script writes no OpenSSL PQC fragment
(fr-webui sets no `OPENSSL_CONF`). The new units
(`fr-first-boot.service`, `fr-persistence-setup.service`,
`fr-initial-password.path` and `.service`, `fr-console-ports.service`)
hold the sandbox `systemd/sandbox_test.go` checks; two exceptions are
named there with their reason: `fr-persistence-setup.service` sees the
devices (it partitions the boot medium), and `fr-first-boot.service` may
open a packet socket (the DHCP probe).

## 2026-11-14: the installer image (phase 4f-2b)

No recorded case changes: the image is checked by booting it, not by
replay.

- **The binaries are static.** The Go binaries are built with
  `CGO_ENABLED=0`, the Rust ones for `x86_64-unknown-linux-musl`, so
  they run on the image's Debian bookworm whatever glibc the build host
  has (CI builds on ubuntu-24.04).
- **No Python on the router.** 1.x installed python3, pip, PyYAML and
  its wheel; 2.x installs none of them. `bpftool` and `libbpf1` go too:
  `fr-xdp` loads and pins the XDP program itself. `ifupdown` and
  `isc-dhcp-client` come in by name, as they did with 1.x's Python
  dependencies pulling them in.
- **The boot test boots four times, not ten.** 1.x's boots 5 to 10 test
  a kernel update with its fallback (phase 4f-3), and its checks of the
  signed build (SEC-15's integrity check, SEC-22/29's planted files,
  SEC-12's refused update) test the signed release and the update
  helper (phase 4f-4); they come back with those phases. Every other
  check of boots 1 to 4 is kept as 1.x has it.


## 2026-11-14: a staged kernel, tried once (phase 4f-3a)

`firewall-cli kernel status|stage|unstage|confirm-boot`, held to 1.x's
`frfw.cli` and `frfw.kernel_boot` (ROADMAP SEC-14, SEC-23): the GRUB
environment block on the persistence partition, the staged slot
(`fr_os-boot/staged/`, its `SHA256SUMS` and `expect.json`), and the
boot-time check `fr-kernel-confirm.service` runs. `reference/
test_fros_apply_cases.py` records them as `cli/kernel/...` sessions
against the fake system, with the persistence partition's mount point
under the case's tree (`Paths.LiveRoot` in 2.x) and the running kernel
fixed at `6.1.0-26-amd64`. The system calls that are not programs are
the recording's pseudo-calls, as the DHCP probe is: `["statvfs", path]`
(its output the free bytes), `["connect", "127.0.0.1", "443", "3"]` (rc
0: the webUI answered within 3 s) and `["sleep", "2.0"]`, the check's
interval, which moves a clock of its own from 0 (so a check that never
passes makes its 91 tries in the recording, and in no time).

- **No recorded case changes.** Every message, alert, exit status and
  file left is 1.x's.
- **The recording appends the `cli/kernel/` cases to the committed
  ones**, for the reason phase 4f-1 gives.
- **The boot test's boots 5 to 8 come back** (phase 4f-2b left them
  out): a staged kernel tried and kept, tried and failed by the
  router's own check (the webUI masked, the LAN port down), the
  fallback boot with its alerts, and a trial that panics. Two
  differences from 1.x's: the host stages the kernel with the test's
  own few lines (the slot and block as `firewall-cli kernel stage`
  writes them; the host has no 2.x library to call, and the replay
  holds the command itself), and boot 5 waits for
  `fr-kernel-confirm`'s line on the serial console instead of the
  Update screen's kernel card, which reads the update-helper (phase
  4f-3b). Boots 9 and 10 come with 4f-3b.

## 2026-11-15: a kernel prepared, then tried (phase 4f-3b)

`firewall-cli kernel prepare|try`, `fr-kernel-prepare.service` and its
timer, and the update-helper's kernel commands (`kernel_status`,
`kernel_check`, `kernel_try`, `kernel_cancel`, `ping`), held to 1.x's
`frfw.kernel_update`, `frfw.cli` and `frfw.helper.update_server`
(ROADMAP SEC-14, step 3). `reference/test_fros_apply_cases.py` records
them as `cli/kernel/...` sessions too: apt, dpkg and depmod answer from
the table, and an update-helper request is a step `{"update": request}`,
sent to 1.x's `_handle_request` and in 2.x to `helper.UpdateServer`.
The image's initrd in the setup is a small one the recording makes
(newc archives, gzip'd, with live-boot and one kernel's modules); the
new kernel's modules are setup files under `usr/lib/modules`.

- **No recorded case changes.** Every message, alert, exit status, file
  left and reply is 1.x's; the webUI's kernel buttons (`update/kernel`)
  answer as 1.x's, so they no longer answer 501.
- **The initrd the router makes is compared uncompressed**: its early
  archives as they are and its main archive gunzipped (`"initrd"` in
  the recorded file, `apply.SplitInitrd` on 2.x's). gzip's bytes are
  zlib's own; Go's compress/gzip writes a different stream for the same
  archive, which the kernel unpacks the same.
- **The setup's files all carry one mtime** (`setup_mtime`): the
  initrd's new entries take the image initrd's, so the recording and
  the replay set it alike.
- **A table answer may leave files** (`"writes"`, under the directory
  after its `-b`): depmod's `modules.dep`, which the checks of the
  initrd read back.
- **xz and zstd are the programs**, as 1.x's zstd already was: Go's
  standard library has no reader for either. An initrd's archive is
  read and decompressed up to 1 GiB (1.x: no bound).
- **1.x lets two errors through**: apt's timeout (`TimeoutExpired`) and
  a torn archive's `ValueError` (a field of its header cut short), and a
  failed `systemctl start` behind "Check now" (`CalledProcessError`).
  The CLI fails (exit 1) and the update-helper sends no reply, as
  there.
- **`apply` and `rollback` are unknown commands** to the update-helper
  until the signed release update (phase 4f-4); the webUI's install and
  rollback buttons still answer 501. The update-helper's other
  requests are read as the apply-helper's are ("the helper's
  requests").
- **The boot test's boots 9 and 10 come back**, as 1.x's: "Check now"
  with fr-kernel-prepare pointed at the running kernel, "Try it", and
  the trial on the router-built initrd, confirmed on the Update screen
  against what worked before it (SEC-23).
