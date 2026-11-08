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
in "could not parse nft JSON output: ...", 2.x says what is wrong in its
own words after the same prefix; the test checks the prefix. Every other
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
