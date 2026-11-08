package config

import "testing"

// TestPyJSON: json.dumps's text, from Python 3.13.
func TestPyJSON(t *testing.T) {
	v, err := ParseJSON([]byte(`{"b": 1, "a": [1.5, "\u00e9", null, true, 1e16, -0.0, {}, []], "c": {"z": "\u2028\""}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		indent int
		sort   bool
		want   string
	}{
		{1, true, "{\n \"a\": [\n  1.5,\n  \"\\u00e9\",\n  null,\n  true,\n  1e+16,\n  -0.0,\n  {},\n  []\n ],\n \"b\": 1,\n" +
			" \"c\": {\n  \"z\": \"\\u2028\\\"\"\n }\n}"},
		{-1, false, `{"b": 1, "a": [1.5, "\u00e9", null, true, 1e+16, -0.0, {}, []], "c": {"z": "\u2028\""}}`},
	} {
		got, err := PyJSON(v, c.indent, c.sort)
		if err != nil || got != c.want {
			t.Errorf("indent %d sort %v:\n got %q (%v)\nwant %q", c.indent, c.sort, got, err, c.want)
		}
	}
}
