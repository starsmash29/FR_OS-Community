package config

import (
	"math/big"
	"testing"
)

func TestParseJSONKeepsOrderAndNumbers(t *testing.T) {
	v, err := ParseJSON([]byte(`{"b": 1, "a": 1.0, "c": 123456789012345678901234567890, "d": [true, null]}`))
	if err != nil {
		t.Fatal(err)
	}
	m := v.(*Map)
	if got := m.Keys(); len(got) != 4 || got[0] != "b" || got[1] != "a" {
		t.Errorf("keys %v, want the written order", got)
	}
	if _, ok := m.get("b", nil).(*big.Int); !ok {
		t.Errorf("1 is not an integer")
	}
	if _, ok := m.get("a", nil).(float64); !ok {
		t.Errorf("1.0 is not a float")
	}
	if got := repr(v); got != "{'b': 1, 'a': 1.0, 'c': 123456789012345678901234567890, 'd': [True, None]}" {
		t.Errorf("repr %s", got)
	}
	if _, err := ParseJSON([]byte(`{"a": 1} 2`)); err == nil {
		t.Errorf("trailing data accepted")
	}
}

// Expected values are Python 3.13's repr().
func TestRepr(t *testing.T) {
	for _, c := range []struct {
		v    Value
		want string
	}{
		{1.5, "1.5"}, {1.0, "1.0"}, {1e16, "1e+16"}, {1e15, "1000000000000000.0"}, {0.0001, "0.0001"},
		{0.00001, "1e-05"}, {-2.5e-7, "-2.5e-07"}, {123456789.125, "123456789.125"}, {1.7976931348623157e308, "1.7976931348623157e+308"},
		{"it's", `"it's"`}, {`a'b"c`, `'a\'b"c'`}, {"tab\there\n", `'tab\there\n'`}, {"\x00\x7f\u0085é\u200b", "'\\x00\\x7f\\x85é\\u200b'"},
		{[]Value{}, "[]"}, {[]string{"a", "b"}, "['a', 'b']"}, {nil, "None"}, {false, "False"},
	} {
		if got := repr(c.v); got != c.want {
			t.Errorf("repr(%#v) = %s, want %s", c.v, got, c.want)
		}
	}
}

func TestTruthyAndNumbers(t *testing.T) {
	if truthy(0.0) || truthy("") || truthy([]Value{}) || truthy(NewMap()) || truthy(big.NewInt(0)) || truthy(nil) {
		t.Errorf("a falsy value is truthy")
	}
	if !numEq(true, 1) || !numEq(1.0, 1) || !numEq(big.NewInt(1), 1) || numEq("1", 1) {
		t.Errorf("1 == 1.0 == True, not '1'")
	}
	if !isInt(true) {
		t.Errorf("a bool is an int to isinstance")
	}
	if _, ok := strictInt(true); ok {
		t.Errorf("strictInt takes a bool")
	}
}

func TestPythonStrings(t *testing.T) {
	if got := pyStrip("\x1c  x \x1f"); got != "x" {
		t.Errorf("strip %q", got)
	}
	if got := pyLower("FRİ"); got != "fri̇" {
		t.Errorf("lower %q", got)
	}
	if n, ok := pyDecimal("١٢"); !ok || n != 12 {
		t.Errorf("decimal %d %v", n, ok)
	}
}
