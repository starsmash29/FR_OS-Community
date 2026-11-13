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
- **The XDP SNI filter** is not in FR_OS 2 yet (phase 4, Rust/aya): an
  apply of a config with `xdp_sni_filter.enabled`, or while a filter is
  attached, is refused at its preflight, before anything changes, where
  1.x loads it. Cases: sessions whose config enables the filter (marked
  `decided` when the recording has one). Why: an apply that said it had
  loaded a filter it can't load would be a lie; refusing changes
  nothing.
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
restores, come with the daemon (phase 4e).

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
(phase 4e), as for the TLS inventory.

Which sources the AI-IDS daemon scores (internal networks, IPv6 hosts
by MAC), its conntrack sampling and its quarantine come with the daemon
(phase 4e); the line readers here only parse, and the case file records
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
name, as `Crash`) come with the daemon (phase 4e).

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
