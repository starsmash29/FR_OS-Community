package helper

import "testing"

// TestPyIsDigit: str.isdigit() counts the superscripts and circled
// digits Go's unicode.IsDigit leaves out (Python 3.13).
func TestPyIsDigit(t *testing.T) {
	for r, want := range map[rune]bool{'0': true, '²': true, '٣': true, '①': true, '¹': true, 'x': false, '½': false,
		'Ⅷ': false, ' ': false} {
		if pyIsDigit(r) != want {
			t.Errorf("%q: got %v", r, !want)
		}
	}
	if n, err := parseSpeedMHz("2667 MT/s"); err != nil || n.Int64() != 2667 {
		t.Errorf("2667 MT/s: %v %v", n, err)
	}
	if n, err := parseSpeedMHz("٣٢٠٠MT/s x"); err != nil || n.Int64() != 3200 {
		t.Errorf("Arabic-Indic digits: %v %v", n, err)
	}
	if _, err := parseSpeedMHz("²666 MT/s"); err == nil {
		t.Error("a superscript digit: int() refuses it")
	}
}
