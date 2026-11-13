package apply_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReferenceXdpKeys replays 1.x's blocklist keys
// (testdata/reference/xdpuser.jsonl, kind "key"): every name must
// normalize the same and give the same LPM key, or be refused with the
// same text, before an apply changes anything.
func TestReferenceXdpKeys(t *testing.T) {
	cases, err := reference.XdpUserCases()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cases {
		if c.Kind != "key" {
			continue
		}
		n++
		if got := apply.NormalizeSNI(c.Name); got != c.Normalized {
			t.Errorf("%s: NormalizeSNI(%q) = %q, want %q", c.ID, c.Name, got, c.Normalized)
		}
		key, err := apply.LPMKey(c.Name)
		switch {
		case c.Error != "":
			want := strings.TrimPrefix(c.Error, "XdpError: ")
			if err == nil || err.Error() != want {
				t.Errorf("%s: LPMKey(%q): got %x, %v; want error %q", c.ID, c.Name, key, err, want)
			}
		case err != nil:
			t.Errorf("%s: LPMKey(%q): %v, want %s", c.ID, c.Name, err, c.Key)
		case hex.EncodeToString(key) != c.Key:
			t.Errorf("%s: LPMKey(%q) = %x, want %s", c.ID, c.Name, key, c.Key)
		}
	}
	if n == 0 {
		t.Fatal("no key cases")
	}
}
