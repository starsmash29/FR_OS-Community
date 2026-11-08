package config

import "testing"

// TestPyIntFloat: int() and float() of a str, as Python 3.13 answered
// ("" for a ValueError).
func TestPyIntFloat(t *testing.T) {
	for _, c := range []struct{ in, int, float string }{
		{"5", "5", "5.0"},
		{" 5 ", "5", "5.0"},
		{"+5", "5", "5.0"},
		{"-5", "-5", "-5.0"},
		{"1_0", "10", "10.0"},
		{"1__0", "", ""},
		{"_1", "", ""},
		{"1_", "", ""},
		{"", "", ""},
		{" ", "", ""},
		{"0x10", "", ""},
		{"1e3", "", "1000.0"},
		{"1.5", "", "1.5"},
		{"\u0661\u0662", "12", "12.0"},
		{"\u001c7", "", ""},
		{"7\u001f", "", ""},
		{"\u00a07\u2028", "7", "7.0"},
		{"007", "7", "7.0"},
		{"-0", "0", "-0.0"},
		{"+-1", "", ""},
		{"1 2", "", ""},
		{"inf", "", "inf"},
		{"-Infinity", "", "-inf"},
		{"nan", "", "nan"},
		{"+nan", "", "nan"},
		{"1e400", "", "inf"},
		{"-1e400", "", "-inf"},
		{"1e-400", "", "0.0"},
		{".5", "", "0.5"},
		{"5.", "", "5.0"},
		{".", "", ""},
		{"e5", "", ""},
		{"1e", "", ""},
		{"1e+", "", ""},
		{"1e1_0", "", "10000000000.0"},
		{"1_0.5_0", "", "10.5"},
		{"1._5", "", ""},
		{"0x1p3", "", ""},
		{"1E5", "", "100000.0"},
		{"infinit", "", ""},
		{"  -inf  ", "", "-inf"},
		{"1,5", "", ""},
		{"\u0661.\u0665", "", "1.5"},
		{"1e\u0663", "", "1000.0"},
		{"1000000000000000000000000000000", "1000000000000000000000000000000", "1e+30"},
	} {
		gotInt := ""
		if n, ok := PyInt(c.in); ok {
			gotInt = n.String()
		}
		gotFloat := ""
		if f, ok := PyFloat(c.in); ok {
			gotFloat = floatRepr(f)
		}
		if gotInt != c.int || gotFloat != c.float {
			t.Errorf("%q: int %q float %q, want %q %q", c.in, gotInt, gotFloat, c.int, c.float)
		}
	}
}

func TestTruthy(t *testing.T) {
	m := NewMap()
	full := NewMap()
	full.Set("a", nil)
	for _, c := range []struct {
		v    Value
		want bool
	}{{nil, false}, {false, false}, {true, true}, {"", false}, {"0", true}, {0.0, false}, {-0.5, true},
		{[]Value{}, false}, {[]Value{nil}, true}, {m, false}, {full, true}} {
		if Truthy(c.v) != c.want {
			t.Errorf("bool(%s) != %v", Repr(c.v), c.want)
		}
	}
}
