package version

import "testing"

// Releases compare as 1.x's tuples of ints, and a beta before its final
// release (decisions.md, "phase 4f-4b").
func TestReleasesCompareAsNumbers(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"9.9.9", "0.2.1", 1},
		{"0.2.1", "0.2.1", 0},
		{"0.10.0", "0.9.9", 1},
		{"v1.0.0", "0.2.1", 1},
		{"0.2.01", "0.2.1", 0},
		{"99999999999999999999.0.0", "2.0.0", 1},
		{"2.0.0-beta.1", "2.0.0", -1},
		{"2.0.0-beta.2", "2.0.0-beta.1", 1},
		{"2.0.0-beta.10", "2.0.0-beta.9", 1},
		{"2.0.0-beta.01", "2.0.0-beta.1", 0},
		{"2.0.1-beta.1", "2.0.0", 1},
		{"v2.0.0-beta.1", "1.9.9", 1},
	} {
		a, ok := ParseRelease(c.a)
		b, ok2 := ParseRelease(c.b)
		if !ok || !ok2 {
			t.Fatalf("%q or %q not parsed", c.a, c.b)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: %d, want %d", c.a, c.b, got, c.want)
		}
		if got := b.Compare(a); got != -c.want {
			t.Errorf("%s vs %s: %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestOnlyReleaseVersionsParse(t *testing.T) {
	for _, s := range []string{"nightly", "0.2.1 ", " 0.2.1", "0.2.1\n", "2.0", "2.0.0.0", "2.0.0-beta", "2.0.0-beta.",
		"2.0.0-rc.1", "2.0.0-beta.1.2", "2.0.0+build", "V2.0.0", "vv2.0.0", "", "٢.٠.٠", "2.0.0-Beta.1"} {
		if _, ok := ParseRelease(s); ok {
			t.Errorf("%q parsed", s)
		}
	}
	if r, ok := ParseRelease("v2.0.0-beta.3"); !ok || !r.IsBeta() || r.Beta != "3" || r.Major != "2" {
		t.Errorf("v2.0.0-beta.3: %+v %v", r, ok)
	}
}
