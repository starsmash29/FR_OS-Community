package webui

import (
	"maps"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
)

// The rule check's cases from 1.x's tests/test_rule_check.py. The
// dashboard replay sees only the findings the checklist counts; these
// cover the rest (redundant, unused, expired, and rules wrongly called
// shadowed).

const day = 24 * 3600

func lintConfig(t *testing.T, rules string) *config.Config {
	t.Helper()
	raw, err := config.LoadYAML(`version: 1
hostname: router
zones: {wan: {}, lan: {}, dmz: {}}
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.1.1/24}
  dmz: {device: eth2, zone: dmz, address: 10.0.2.1/24}
nat: {masquerade: [{out_zone: wan}]}
rules:
` + rules)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type kindSeverity struct{ kind, severity string }

func firstFindings(t *testing.T, rules string, hits *config.Map, now float64) map[string]kindSeverity {
	t.Helper()
	if hits == nil {
		hits = config.NewMap()
	}
	found, err := lintRules(lintConfig(t, rules), hits, now)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]kindSeverity{}
	for _, f := range found {
		if _, seen := out[f.Rule]; !seen { // a rule's most important finding comes first
			out[f.Rule] = kindSeverity{f.Kind, f.Severity}
		}
	}
	return out
}

func TestAnyToAnyAndInternetWideRules(t *testing.T) {
	got := firstFindings(t, `
- {name: wan-web, action: accept, from_zone: wan, to_zone: dmz, proto: tcp, dst_port: 443}
- {name: partner, action: accept, from_zone: wan, to_zone: dmz, src_address: 203.0.113.0/24}
- {name: lan-out, action: accept, from_zone: lan, to_zone: wan}
- {name: wan-to-dmz, action: accept, from_zone: wan, to_zone: dmz}
- {name: everything, action: accept}
`, nil, 1_800_000_000)
	want := map[string]kindSeverity{
		"everything": {"any-to-any", "warning"},
		"wan-to-dmz": {"open-from-internet", "warning"},
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestShadowedAndRedundant(t *testing.T) {
	got := firstFindings(t, `
- {name: block-dmz, action: drop, from_zone: lan, to_zone: dmz}
- {name: dmz-ssh, action: accept, from_zone: lan, to_zone: dmz, proto: tcp, dst_port: 22}
- {name: web-range, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 80-443}
- {name: web, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 443}
- {name: udp-443, action: accept, from_zone: lan, to_zone: wan, proto: udp, dst_port: 443}
`, nil, 1_800_000_000)
	want := map[string]kindSeverity{"dmz-ssh": {"shadowed", "warning"}, "web": {"redundant", "info"}}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNotShadowed(t *testing.T) {
	for _, earlier := range []string{
		`{name: a, action: accept, from_zone: lan, to_zone: dmz, src_address: 192.168.1.0/25}`,
		`{name: a, action: accept, from_zone: lan, to_zone: dmz, schedule: {days: [mon], start: "08:00", end: "17:00"}}`,
		`{name: a, action: accept, from_zone: lan, to_zone: dmz, expires: "2099-01-01T00:00Z"}`,
		`{name: a, action: accept, from_zone: lan, to_zone: dmz, require_ztna: true}`,
		`{name: a, action: accept, from_zone: lan, to_zone: self}`,
	} {
		later := `{name: b, action: drop, from_zone: lan, to_zone: dmz}`
		if earlier == `{name: a, action: accept, from_zone: lan, to_zone: dmz, src_address: 192.168.1.0/25}` {
			later = `{name: b, action: drop, from_zone: lan, to_zone: dmz, src_address: 192.168.1.0/24}`
		}
		got := firstFindings(t, "- "+earlier+"\n- "+later+"\n", nil, 1_800_000_000)
		if _, ok := got["b"]; ok {
			t.Errorf("%s: b reported as %v", earlier, got["b"])
		}
	}
}

func TestUnusedAndExpired(t *testing.T) {
	const now = 1_800_000_000
	raw, err := config.ParseJSON([]byte(`{
		"old": {"since": 1791360000, "last_hit": 1791792000, "packets": 0},
		"new": {"since": 1799136000, "last_hit": null, "packets": 0},
		"busy": {"since": 1782720000, "last_hit": 1799913600, "packets": 9}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := firstFindings(t, `
- {name: old, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 21}
- {name: new, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 22}
- {name: busy, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 443}
- {name: done, action: accept, from_zone: lan, to_zone: wan, proto: tcp, dst_port: 25, expires: "2020-01-01T00:00Z"}
`, raw.(*config.Map), now)
	want := map[string]kindSeverity{"old": {"unused", "info"}, "done": {"expired", "info"}}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	// 1.x's rule_hits.unused: 90 days to the second.
	entry, _ := raw.(*config.Map).Get("new")
	for _, c := range []struct {
		now  float64
		want bool
	}{{1799136000 + 90*day, true}, {1799136000 + 90*day - 1, false}} {
		if got, _ := unusedRule(entry, c.now); got != c.want {
			t.Errorf("unused at %v: %v", c.now, got)
		}
	}
}
