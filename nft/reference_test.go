package nft

import (
	"encoding/json/v2"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReference replays every ruleset FR_OS 1.x's test suite built
// (AGENTS.md, "Differential tests"): the same config, moment, clock and
// runtime members must give the same nft script, byte for byte.
func TestReference(t *testing.T) {
	cases, err := reference.RulesetCases()
	if err != nil {
		t.Fatal(err)
	}
	// reference/generate.sh records with TZ=UTC.
	defer func(l *time.Location) { config.Local = l }(config.Local)
	config.Local = time.UTC

	decided := 0
	for _, c := range cases {
		raw, err := config.ParseJSON(c.Input)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		cfg, err := config.Parse(raw)
		if name := config.Decided(raw); name != "" {
			// 2.x refuses the config by decision (decisions.md).
			if err == nil {
				t.Errorf("%s: decision %q: accepted here", c.ID, name)
			}
			decided++
			continue
		}
		if err != nil {
			t.Errorf("%s: 1.x built a ruleset from it, refused here: %v", c.ID, err)
			continue
		}
		sec, frac := math.Modf(c.Now)
		opts := Options{Now: time.Unix(int64(sec), int64(frac*1e9))}
		if c.Clock != nil {
			opts.Clock = &Clock{UTCOffsetMinutes: c.Clock.UTCOffsetMinutes, KernelMinutesWest: c.Clock.KernelMinutesWest}
		}
		if len(c.Runtime) > 0 && string(c.Runtime) != "null" {
			rt, err := runtimeSets(c.Runtime)
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			opts.Runtime = rt
		}
		got, err := Build(cfg, opts)
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if got != c.Output {
			t.Errorf("%s: differs from 1.x at line %s", c.ID, firstDiff(c.Output, got))
		}
	}
	t.Logf("%d rulesets: %d compared, %d from configs refused by decision", len(cases), len(cases)-decided, decided)
}

// firstDiff says where two scripts part: the line number and both lines.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b || i >= len(w) || i >= len(g) {
			return fmt.Sprint(i+1) + "\n  1.x: " + a + "\n  2.x: " + b
		}
	}
	return "?"
}

// runtimeSets decodes RuntimeSets as the capture plugin writes them:
// dataclasses.asdict, so tuples become lists.
func runtimeSets(data []byte) (*RuntimeSets, error) {
	var raw map[string][]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	timed := func(name string) []Timed {
		var out []Timed
		for _, m := range raw[name] {
			pair := m.([]any)
			out = append(out, Timed{Member: pair[0].(string), Left: int64(pair[1].(float64))})
		}
		return out
	}
	rt := &RuntimeSets{
		BruteforceJail:    timed("bruteforce_jail"),
		BruteforceJail6:   timed("bruteforce_jail6"),
		BruteforceJailMac: timed("bruteforce_jail_mac"),
		IDSQuarantine:     timed("ids_quarantine"),
		IDSQuarantineMac:  timed("ids_quarantine_mac"),
	}
	for _, m := range raw["ztna"] {
		s := m.([]any)
		rt.Ztna = append(rt.Ztna, ZtnaSession{IP: s[0].(string), MAC: s[1].(string), Left: int64(s[2].(float64))})
	}
	for _, m := range raw["iot_isolated"] {
		rt.IotIsolated = append(rt.IotIsolated, m.(string))
	}
	return rt, nil
}
