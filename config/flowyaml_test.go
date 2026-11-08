package config

import (
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestFlowYAMLRoundTrip: every value PyYAML loaded in the recording is
// read back, from what FlowYAML writes, to the same value (the sensors'
// config copy, decisions.md).
func TestFlowYAMLRoundTrip(t *testing.T) {
	cases, err := reference.YAMLCases()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cases {
		if !c.OK || c.Recursive {
			continue
		}
		v, err := LoadYAML(c.Input)
		if err != nil {
			continue // refused here by decision (TestYAMLReference)
		}
		text, err := FlowYAML(v)
		if err != nil {
			t.Errorf("%s: %q: %v", c.ID, c.Input, err)
			continue
		}
		back, err := LoadYAML(text)
		if err != nil {
			t.Errorf("%s: %q written as %q, which does not load: %v", c.ID, c.Input, text, err)
			continue
		}
		if !reflect.DeepEqual(tagged(back), tagged(v)) && !hasNaN(v) {
			t.Errorf("%s: %q written as %q, read back as %s, not %s", c.ID, c.Input, text, Repr(back), Repr(v))
		}
		n++
	}
	if n < 100 {
		t.Fatalf("only %d values", n)
	}
}

func hasNaN(v Value) bool {
	switch x := v.(type) {
	case float64:
		return math.IsNaN(x)
	case []Value:
		for _, e := range x {
			if hasNaN(e) {
				return true
			}
		}
	case *Map:
		for i, k := range x.keys {
			if hasNaN(k) || hasNaN(x.vals[i]) {
				return true
			}
		}
	}
	return false
}

func TestFlowYAML(t *testing.T) {
	m := NewMap()
	m.Set("s", "é \"q\" \\ \x01 \U0001F600")
	m.Set("f", 1e16)
	m.Set("n", nil)
	m.Set("l", []Value{true, false, math.Inf(-1)})
	got, err := FlowYAML(m)
	want := `{"s": "\u00e9 \"q\" \\ \u0001 \U0001f600", "f": 1.0e+16, "n": null, "l": [true, false, -.inf]}`
	if err != nil || got != want {
		t.Errorf("got %q (%v)\nwant %q", got, err, want)
	}
	self := []Value{nil}
	self[0] = self
	if _, err := FlowYAML(self); !errors.Is(err, errRecursive) {
		t.Errorf("a list that holds itself: %v", err)
	}
	if _, err := FlowYAML(struct{}{}); err == nil {
		t.Error("an unknown type was written")
	}
}
