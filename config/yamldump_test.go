package config

import (
	"encoding/json/v2"
	"testing"

	"github.com/starsmash29/fr_os-community/internal/reference"
)

// dumpDecided are the texts whose dump differs by decision
// (testdata/reference/decisions.md, "A date reached by two aliases"):
// PyYAML anchors the one date object; here a date is a value, written
// at each place.
var dumpDecided = map[string]bool{
	"a: &d 2026-11-01\nb: *d\n":            true,
	"a: &t 2026-11-01 10:00:00\nb: [*t]\n": true,
}

// TestYAMLDumpReference: for every text PyYAML loaded, what DumpYAML
// writes for the value LoadYAML built is what yaml.safe_dump(value,
// sort_keys=False) wrote for PyYAML's (1.x writes config.yaml so when
// the webUI address moves).
func TestYAMLDumpReference(t *testing.T) {
	cases, err := reference.YAMLCases()
	if err != nil {
		t.Fatal(err)
	}
	var same, skipped, decided int
	for _, c := range cases {
		if !c.OK || c.Dump == nil {
			continue
		}
		var want any
		if !c.Recursive {
			if err := json.Unmarshal(c.Value, &want); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
		}
		v, err := LoadYAML(c.Input)
		if err != nil || yamlDecided(c.Recursive, want) != "" { // refused or loaded otherwise here, as TestYAMLReference says
			skipped++
			continue
		}
		got, err := DumpYAML(v)
		switch {
		case dumpDecided[c.Input]:
			if err != nil || got == *c.Dump {
				t.Errorf("%s: %q: decided to differ, but here: %q, %v", c.ID, c.Input, got, err)
			}
			decided++
		case err != nil:
			t.Errorf("%s: %q: PyYAML wrote %q, here: %v", c.ID, c.Input, *c.Dump, err)
		case got != *c.Dump:
			t.Errorf("%s: %q written as\n  PyYAML: %q\n  here:   %q", c.ID, c.Input, *c.Dump, got)
		default:
			same++
		}
	}
	t.Logf("%d values written as PyYAML wrote them, %d not loaded here, %d differ by decision", same, skipped, decided)
}
