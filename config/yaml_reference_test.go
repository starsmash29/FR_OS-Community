package config

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/internal/pyyaml"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestYAMLReference replays every text 1.x's suite (and
// reference/test_fros_yaml_cases.py) gave yaml.safe_load: each must load
// to the same value, or fail with PyYAML's message. Where 1.x crashed
// instead, the text must be refused.
func TestYAMLReference(t *testing.T) {
	cases, err := reference.YAMLCases()
	if err != nil {
		t.Fatal(err)
	}
	var loaded, refused, crashed, diffs int
	for _, c := range cases {
		v, err := LoadYAML(c.Input)
		var want any
		if c.OK && !c.Recursive {
			if err := json.Unmarshal(c.Value, &want); err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
		}
		if name := yamlDecided(c.Recursive, want); name != "" {
			// Refused, except two NaN keys: loaded as one.
			var limit *pyyaml.LimitError
			if !errors.As(err, &limit) && name != "NaN keys" {
				t.Errorf("%s: decision %q: %q gave %v, not a refusal", c.ID, name, c.Input, err)
			}
			diffs++
			continue
		}
		switch {
		case c.Crash != "":
			if err == nil {
				t.Errorf("%s: 1.x crashed (%s) on %q, accepted here as %s", c.ID, c.Crash, c.Input, repr(v))
			}
			crashed++
		case !c.OK && err == nil:
			t.Errorf("%s: PyYAML refused %q:\n%s\naccepted here as %s", c.ID, c.Input, c.Error, repr(v))
		case !c.OK && err.Error() != c.Error:
			t.Errorf("%s: %q refused with another message\n--- PyYAML:\n%s\n--- here:\n%s", c.ID, c.Input, c.Error, err)
		case !c.OK:
			refused++
		case err != nil:
			t.Errorf("%s: PyYAML loaded %q, refused here: %v", c.ID, c.Input, err)
		case !reflect.DeepEqual(tagged(v), want):
			got, _ := json.Marshal(tagged(v))
			t.Errorf("%s: %q loaded as\n  PyYAML: %s\n  here:   %s", c.ID, c.Input, c.Value, got)
		default:
			loaded++
		}
	}
	t.Logf("%d texts: %d loaded and %d refused as PyYAML did, %d refused where 1.x crashes, %d differ by decision",
		len(cases), loaded, refused, crashed, diffs)
}

// TestYAMLConfigReference replays every parse_config of a value
// yaml.safe_load built, from its text.
func TestYAMLConfigReference(t *testing.T) {
	cases, err := reference.YAMLConfigCases()
	if err != nil {
		t.Fatal(err)
	}
	defer func(l *time.Location) { Local = l }(Local)
	Local = time.UTC
	var accepted, refused, crashed, diffs int
	for _, c := range cases {
		raw, err := LoadYAML(c.Input)
		var limit *pyyaml.LimitError
		if errors.As(err, &limit) {
			diffs++ // the text itself is a decided case of TestYAMLReference
			continue
		}
		if err != nil {
			t.Errorf("%s: PyYAML loaded it, refused here: %v", c.ID, err)
			continue
		}
		_, err = Parse(raw)
		if name := Decided(raw); name != "" && c.OK {
			if err == nil {
				t.Errorf("%s: decision %q: accepted here", c.ID, name)
			}
			diffs++
			continue
		}
		switch {
		case c.Crash != "":
			if err == nil {
				t.Errorf("%s: 1.x crashed (%s), accepted here:\n%s", c.ID, c.Crash, c.Input)
			}
			crashed++
		case c.OK && err != nil:
			t.Errorf("%s: 1.x accepted it, refused here: %v\n%s", c.ID, err, c.Input)
		case !c.OK && err == nil:
			t.Errorf("%s: 1.x refused it (%s), accepted here:\n%s", c.ID, c.Error, c.Input)
		case !c.OK && err.Error() != c.Error:
			t.Errorf("%s: refused with another message\n  1.x: %s\n  2.x: %s", c.ID, c.Error, err)
		case c.OK:
			accepted++
		default:
			refused++
		}
	}
	t.Logf("%d configs: %d accepted and %d refused as 1.x did, %d refused where 1.x crashes, %d differ by decision",
		len(cases), accepted, refused, crashed, diffs)
}

// yamlDecided names the decision (testdata/reference/decisions.md) a
// value PyYAML loaded falls under, or "".
func yamlDecided(recursive bool, v any) string {
	if recursive {
		return "recursive aliases"
	}
	if depth(v) > pyyaml.MaxDepth {
		return "nesting depth"
	}
	var walk func(v any) string
	walk = func(v any) string {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				if n := walk(e); n != "" {
					return n
				}
			}
		case map[string]any:
			for k, e := range x {
				switch k {
				case "bytes", "set", "tuple":
					return "binary, set, omap, pairs"
				case "surrogates":
					return "surrogate escapes"
				case "map":
					nans := 0
					for _, kv := range e.([]any) {
						if f, ok := kv.([]any)[0].(map[string]any); ok && f["float"] == "nan" {
							nans++
						}
					}
					if nans > 1 {
						return "NaN keys"
					}
				}
				if n := walk(e); n != "" {
					return n
				}
			}
		}
		return ""
	}
	return walk(v)
}

// depth is how deep the composer nests for a value: a scalar is 1.
func depth(v any) int {
	inner := 0
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			inner = max(inner, depth(e))
		}
	case map[string]any:
		pairs, ok := x["map"].([]any)
		if !ok {
			return 1
		}
		for _, kv := range pairs {
			for _, e := range kv.([]any) {
				inner = max(inner, depth(e))
			}
		}
	default:
		return 1
	}
	return 1 + inner
}

// tagged is a Value as the capture plugin writes one (_tagged), decoded
// into Go's generic JSON values.
func tagged(v Value) any {
	switch x := v.(type) {
	case nil, bool, string:
		return x
	case *big.Int:
		return map[string]any{"int": x.String()}
	case float64:
		return map[string]any{"float": floatRepr(x)}
	case Date:
		return map[string]any{"date": x.str()}
	case Datetime:
		var off any
		if x.Aware {
			off = float64(x.Offset)
		}
		return map[string]any{"datetime": []any{
			float64(x.Year), float64(x.Month), float64(x.Day), float64(x.Hour), float64(x.Minute),
			float64(x.Second), float64(x.Micro), off,
		}}
	case []Value:
		out := []any{}
		for _, e := range x {
			out = append(out, tagged(e))
		}
		return out
	case *Map:
		pairs := []any{}
		for i, k := range x.keys {
			pairs = append(pairs, []any{tagged(k), tagged(x.vals[i])})
		}
		return map[string]any{"map": pairs}
	}
	panic(fmt.Sprintf("tagged: %T", v))
}
