package webui

import (
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The rule check (security-lessons K2, 1.x's frfw.rule_lint): mistakes in
// the firewall rules a person reading them one by one easily misses --
// an accept rule matching everything, one open to the whole internet, a
// rule an earlier one shadows or makes redundant, one that matched
// nothing for 90 days, and an expired temporary rule.
//
// "Matches everything the other does" is judged conservatively, field by
// field: the check never calls a rule shadowed when it isn't, but can
// miss one shadowed by a combination of rules.

const (
	severityWarning = "warning"
	severityInfo    = "info"
)

// unusedSeconds: a rule that hasn't matched for this long is reported
// (frfw.rule_hits.UNUSED_SECONDS).
const unusedSeconds = 90 * 24 * 3600

type finding struct {
	Rule, Kind, Severity, Message string
}

func portRange(spec string) (int, int) {
	lo, hi, found := strings.Cut(spec, "-")
	a, _ := strconv.Atoi(lo)
	if !found {
		return a, a
	}
	b, _ := strconv.Atoi(hi)
	return a, b
}

// netCovers: every network of inner inside one of outer's (nil: any).
func netCovers(outer, inner []string) bool {
	if outer == nil {
		return true
	}
	if inner == nil {
		return false
	}
	for _, i := range inner {
		in := netip.MustParsePrefix(i)
		if !slices.ContainsFunc(outer, func(o string) bool {
			out := netip.MustParsePrefix(o)
			return out.Addr().Is4() == in.Addr().Is4() && out.Bits() <= in.Bits() && out.Contains(in.Addr())
		}) {
			return false
		}
	}
	return true
}

func sameSchedule(a, b *config.RuleSchedule) bool {
	if a == nil || b == nil {
		return a == b
	}
	return slices.Equal(a.Days, b.Days) && a.Start == b.Start && a.End == b.End &&
		a.CutEstablished == b.CutEstablished
}

// covers: does a match every packet b matches? (Both in the same chain.)
func covers(a, b *config.Rule) bool {
	if a.FromZone != "" && a.FromZone != b.FromZone {
		return false
	}
	if a.ToZone != "" && a.ToZone != b.ToZone {
		return false
	}
	if a.Proto != config.ProtoAny && a.Proto != b.Proto {
		return false
	}
	if a.DstPort != "" {
		if b.DstPort == "" || b.Proto != a.Proto {
			return false
		}
		alo, ahi := portRange(a.DstPort)
		blo, bhi := portRange(b.DstPort)
		if !(alo <= blo && bhi <= ahi) {
			return false
		}
	}
	if !(netCovers(a.SrcAddress, b.SrcAddress) && netCovers(a.DstAddress, b.DstAddress)) {
		return false
	}
	if a.SrcMac != "" && a.SrcMac != b.SrcMac {
		return false
	}
	if a.RequireZtna && !b.RequireZtna {
		return false
	}
	if a.Schedule != nil && !sameSchedule(a.Schedule, b.Schedule) {
		return false
	}
	if a.Expires != nil && (b.Expires == nil || *b.Expires > *a.Expires) {
		return false
	}
	return true
}

// lintChains are the rules in the order each chain evaluates them (the
// ruleset builder's: scheduled cut_established rules first), input then
// forward.
func lintChains(rules []*config.Rule) [][]*config.Rule {
	cuts := func(r *config.Rule) bool { return r.Schedule != nil && r.Schedule.CutEstablished }
	var out [][]*config.Rule
	for _, input := range []bool{true, false} {
		var first, rest []*config.Rule
		for _, r := range rules {
			if (r.ToZone == config.SelfZone) != input {
				continue
			}
			if cuts(r) {
				first = append(first, r)
			} else {
				rest = append(rest, r)
			}
		}
		out = append(out, append(first, rest...))
	}
	return out
}

func wideOpen(r *config.Rule) bool {
	return r.DstPort == "" && r.Proto == config.ProtoAny && r.SrcAddress == nil && r.DstAddress == nil &&
		r.SrcMac == "" && !r.RequireZtna
}

// ruleHits are frfw.rule_hits's state: rule name -> its entry, or none
// when the file can't be read.
func loadRuleHits(path string) *config.Map {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.NewMap()
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return config.NewMap()
	}
	m, ok := v.(*config.Map)
	if !ok {
		return config.NewMap()
	}
	rules, _ := m.Get("rules")
	if r, ok := rules.(*config.Map); ok {
		return r
	}
	return config.NewMap()
}

// pyFloatOf is float(v) for a JSON value; a value float() refuses is an
// error (1.x's page fails).
func pyFloatOf(v config.Value) (float64, error) {
	if f, ok := number(v); ok {
		return f, nil
	}
	if s, ok := v.(string); ok {
		if f, ok := config.PyFloat(s); ok {
			return f, nil
		}
	}
	return 0, errInternal
}

// unusedRule is frfw.rule_hits.unused: known for 90 days and never (or
// not for 90 days) matched.
func unusedRule(entry config.Value, now float64) (bool, error) {
	if !config.Truthy(entry) {
		return false, nil
	}
	m, ok := entry.(*config.Map)
	if !ok {
		return false, errInternal // 1.x: entry.get on a non-dict raises
	}
	last := config.Value(now)
	if v, _ := m.Get("last_hit"); config.Truthy(v) {
		last = v
	} else if v, _ := m.Get("since"); config.Truthy(v) {
		last = v
	}
	f, err := pyFloatOf(last)
	if err != nil {
		return false, err
	}
	return now-f >= unusedSeconds, nil
}

// lintRules is frfw.rule_lint.lint: the findings in 1.x's order.
func lintRules(c *config.Config, hits *config.Map, now float64) ([]finding, error) {
	internet := c.InternetFacingZones()
	var out []finding
	var live []*config.Rule
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Expires == nil || float64(*r.Expires) > now {
			live = append(live, r)
		}
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Expires != nil && float64(*r.Expires) <= now {
			out = append(out, finding{r.Name, "expired", severityInfo,
				"expired: the firewall already ignores it; remove it to keep the list clean"})
			continue
		}
		if r.Action != config.Accept || r.Schedule != nil {
			continue
		}
		if r.FromZone == "" && r.ToZone == "" && wideOpen(r) {
			out = append(out, finding{r.Name, "any-to-any", severityWarning,
				"accepts everything from anywhere to anywhere: the firewall is off for it"})
		} else if (r.FromZone == "" || internet[r.FromZone]) && r.DstPort == "" && r.SrcAddress == nil && !r.RequireZtna {
			where := "every zone"
			switch {
			case r.ToZone == config.SelfZone:
				where = "the router itself"
			case r.ToZone != "":
				where = "the " + r.ToZone + " zone"
			}
			origin := "any zone, the internet included"
			if r.FromZone != "" {
				origin = "the internet (" + r.FromZone + ")"
			}
			out = append(out, finding{r.Name, "open-from-internet", severityWarning,
				fmt.Sprintf("opens all of %s to %s: limit it to a port or a source address", where, origin)})
		}
	}
	for _, chain := range lintChains(live) {
		for i, r := range chain {
			j := slices.IndexFunc(chain[:i], func(e *config.Rule) bool { return covers(e, r) })
			if j < 0 {
				continue
			}
			earlier := chain[j]
			if earlier.Action == r.Action {
				out = append(out, finding{r.Name, "redundant", severityInfo,
					fmt.Sprintf("redundant: %s above already matches all of it the same way", config.Repr(earlier.Name))})
			} else {
				out = append(out, finding{r.Name, "shadowed", severityWarning,
					fmt.Sprintf("never matches: %s above matches all of it first and %ss it",
						config.Repr(earlier.Name), earlier.Action)})
			}
		}
	}
	for _, r := range live {
		entry, _ := hits.Get(r.Name)
		unused, err := unusedRule(entry, now)
		if err != nil {
			return nil, err
		}
		if unused {
			out = append(out, finding{r.Name, "unused", severityInfo,
				"no traffic has matched it for 90 days: is it still needed?"})
		}
	}
	return out, nil
}
