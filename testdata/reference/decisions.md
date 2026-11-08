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
