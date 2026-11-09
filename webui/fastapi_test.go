package webui

import "testing"

// Vectors from Python: unquote_plus(raw.decode("latin-1")), as Starlette
// reads a urlencoded form.
func TestFormValuesDecodeAsStarletteDecodesThem(t *testing.T) {
	for raw, want := range map[string]string{
		"a+b":    "a b",
		"%41%zz": "A%zz",
		"%C3%A9": "é",
		"%C3":    "�",
		"\xe9":   "é",
		"%ff%fe": "��",
		"a%2Bb":  "a+b",
		"%E2%82": "�",
	} {
		if got := pyUnquotePlus([]byte(raw)); got != want {
			t.Errorf("%q: %q, want %q", raw, got, want)
		}
	}
}

// pydantic's float from a form string.
func TestFloatsParseAsPydanticParsesThem(t *testing.T) {
	for text, ok := range map[string]bool{
		" 1.5 ": true, "1_000": true, "-inf": true, "NaN": true, "1e3": true,
		"1__0": false, "_1": false, "--1": false, "0x10": false, "": false, "abc": false,
	} {
		if _, got := pyFloat(text); got != ok {
			t.Errorf("%q: parsed %v, want %v", text, got, ok)
		}
	}
}
