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

## 2026-11-08: messages

Not a difference today: every refused case is refused with 1.x's own
message, word for word, and the config test checks that. A later change
of wording is recorded here.
