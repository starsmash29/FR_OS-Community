package webui

import (
	"errors"
	"testing"

	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestQRReference: every QR code is segno's, byte for byte, except the
// texts FR_OS 2 refuses (a Micro QR Code, or text that isn't Latin-1;
// decisions.md), which no page of the webUI draws.
func TestQRReference(t *testing.T) {
	cases, err := reference.QRCases()
	if err != nil {
		t.Fatal(err)
	}
	drawn := 0
	for _, c := range cases {
		svg, err := qrSVGOf(c.Text, c.Scale, "#0C141F", "#FFFFFF")
		if errors.Is(err, errQRUnsupported) {
			if c.Text != "hello" && c.Text != "12345678901234567890123456789" && c.Text != "árvíztűrő tükörfúrógép" {
				t.Errorf("%q: refused", c.Text)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.Text, err)
			continue
		}
		drawn++
		if string(svg) != c.SVG {
			t.Errorf("%q at scale %d:\n got %s\nwant %s", c.Text, c.Scale, svg, c.SVG)
		}
	}
	if drawn < 20 {
		t.Fatalf("only %d QR codes compared", drawn)
	}
}
