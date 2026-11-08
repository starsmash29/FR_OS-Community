package appid

import (
	"slices"
	"testing"
)

// Expected values are what 1.x's frfw.appid gives for the same catalog.
func TestCatalog(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Apps) != 41 || !c.Known("tiktok") || c.Known("nope") || c.License != "MIT" {
		t.Fatalf("catalog: %d apps, license %q", len(c.Apps), c.License)
	}
	names := c.BlockingNames([]string{"tiktok", "whatsapp", "nope"})
	if len(names) != 47 || !slices.IsSorted(names) || names[0] != "bytedapm.com" || names[2] != "musical.ly" {
		t.Errorf("blocking names: %d, starting %v", len(names), names[:3])
	}
}

func TestDuplicateID(t *testing.T) {
	if _, err := parse([]byte(`{"apps": [{"id": "a"}, {"id": "a"}]}`)); err == nil {
		t.Error("a duplicate app id is accepted")
	}
}
