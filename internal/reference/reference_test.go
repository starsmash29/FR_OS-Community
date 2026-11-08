package reference

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheReferenceIsComplete(t *testing.T) {
	pin, err := os.ReadFile(filepath.Join(Dir(), "PIN"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(Dir(), "..", "..", "reference", "PIN"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pin)) != strings.TrimSpace(string(want)) {
		t.Fatalf("testdata/reference was made at %s, reference/PIN is %s: run reference/generate.sh", pin, want)
	}

	configs, err := ConfigCases()
	if err != nil {
		t.Fatal(err)
	}
	rulesets, err := RulesetCases()
	if err != nil {
		t.Fatal(err)
	}
	var accepted, refused int
	ids := map[string]bool{}
	for _, c := range configs {
		if ids[c.ID] {
			t.Errorf("config case %s twice", c.ID)
		}
		ids[c.ID] = true
		if c.OK {
			accepted++
		} else if c.Error == "" {
			t.Errorf("config case %s refused without a message", c.ID)
		} else {
			refused++
		}
	}
	for _, c := range rulesets {
		if !strings.HasPrefix(c.Output, "flush ruleset\n") {
			t.Errorf("ruleset case %s does not start with flush ruleset", c.ID)
		}
	}
	// Far fewer would mean the capture broke, not that 1.x shrank.
	if accepted < 100 || refused < 100 || len(rulesets) < 100 {
		t.Fatalf("only %d accepted, %d refused configs and %d rulesets", accepted, refused, len(rulesets))
	}
	t.Logf("%d accepted, %d refused configs, %d rulesets", accepted, refused, len(rulesets))
}
