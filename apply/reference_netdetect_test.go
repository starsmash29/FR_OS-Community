package apply_test

import (
	"encoding/hex"
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReferenceNetdetect holds the DHCP probe's frames to 1.x's
// frfw.netdetect: the DHCPDISCOVER it sends, byte for byte, and the
// network it reads from every answer (built, masked, damaged).
func TestReferenceNetdetect(t *testing.T) {
	cases, err := reference.NetdetectCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no netdetect cases")
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			frame, err := hex.DecodeString(c.Frame)
			if err != nil {
				t.Fatal(err)
			}
			switch c.Op {
			case "discover":
				mac, err := hex.DecodeString(c.MAC)
				if err != nil {
					t.Fatal(err)
				}
				if got := apply.DiscoverFrame(mac, c.XID, c.IPID); hex.EncodeToString(got) != c.Frame {
					t.Errorf("frame\n got %x\nwant %s", got, c.Frame)
				}
			case "offer":
				network, ok := apply.OfferedNetwork(frame, c.XID)
				switch {
				case c.Network == nil && ok:
					t.Errorf("offered %q, want none", network)
				case c.Network != nil && (!ok || network != *c.Network):
					t.Errorf("offered %q (%v), want %q", network, ok, *c.Network)
				}
			default:
				t.Fatalf("unknown op %q", c.Op)
			}
		})
	}
}
