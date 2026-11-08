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
	// Far fewer would mean the capture broke, not that 1.x shrank. (The
	// rulesets are unique cases at one fixed moment, about 80 today.)
	if accepted < 100 || refused < 100 || len(rulesets) < 60 {
		t.Fatalf("only %d accepted, %d refused configs and %d rulesets", accepted, refused, len(rulesets))
	}
	yamls, err := YAMLCases()
	if err != nil {
		t.Fatal(err)
	}
	yamlConfigs, err := YAMLConfigCases()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range yamls {
		if !c.OK && (c.Error == "") == (c.Crash == "") {
			t.Errorf("yaml case %s refused without exactly one of an error and a crash", c.ID)
		}
		if c.OK && (len(c.Value) == 0) == !c.Recursive {
			t.Errorf("yaml case %s loaded without exactly one of a value and recursive", c.ID)
		}
	}
	if len(yamls) < 1000 || len(yamlConfigs) < 100 {
		t.Fatalf("only %d YAML texts and %d configs from YAML", len(yamls), len(yamlConfigs))
	}
	t.Logf("%d accepted, %d refused configs, %d rulesets, %d YAML texts, %d configs from YAML",
		accepted, refused, len(rulesets), len(yamls), len(yamlConfigs))
}
