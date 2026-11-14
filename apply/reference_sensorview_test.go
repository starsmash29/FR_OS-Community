package apply_test

import (
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReferenceSensorView replays sensord.jsonl's "view" cases: for each
// config, the sensors' view holds what 1.x's fr-appid and fr-ai-ids
// derive from it, member for member.
func TestReferenceSensorView(t *testing.T) {
	cases, err := reference.SensordViewCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatalf("only %d view cases", len(cases))
	}
	for _, c := range cases {
		raw, err := config.ParseJSON(c.Config)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		got, err := config.ParseJSON([]byte(strings.TrimSpace(apply.SensorView(raw))))
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		want, err := config.ParseJSON(c.View)
		if err != nil {
			t.Fatal(err)
		}
		gm, _ := got.(*config.Map)
		wm, _ := want.(*config.Map)
		for _, key := range []string{"app_control", "ai_ids", "iot"} {
			g, _ := gm.Get(key)
			w, _ := wm.Get(key)
			gt, _ := config.PyJSON(g, -1, false)
			wt, _ := config.PyJSON(w, -1, false)
			if gt != wt {
				t.Errorf("%s: %s\n got %s\nwant %s", c.Name, key, gt, wt)
			}
		}
	}
}
