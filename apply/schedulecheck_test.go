package apply_test

import (
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// The schedule check re-applies only the config that was applied, so
// any change of a value must change the fingerprint, also inside the
// config's ordered mappings (interfaces, zones, DHCP), and formatting
// alone must not.
func TestConfigFingerprintSeesEveryValue(t *testing.T) {
	base := "version: 1\nhostname: a\ninterfaces:\n  lan: {device: eth1, zone: lan, address: 10.0.0.1/24}\n" +
		"zones: {lan: {}}\n"
	fp := func(text string) string {
		t.Helper()
		raw, err := config.LoadYAML(text)
		if err != nil {
			t.Fatal(err)
		}
		c, err := config.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		f, err := apply.ConfigFingerprint(c)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	want := fp(base)
	if got := fp("# a comment\n" + base + "\n"); got != want {
		t.Error("a comment changed the fingerprint")
	}
	for _, other := range []string{
		"version: 1\nhostname: a\ninterfaces:\n  lan: {device: eth1, zone: lan, address: 10.0.0.2/24}\nzones: {lan: {}}\n",
		"version: 1\nhostname: a\ninterfaces:\n  lan: {device: eth2, zone: lan, address: 10.0.0.1/24}\nzones: {lan: {}}\n",
		"version: 1\nhostname: a\ninterfaces:\n  lan: {device: eth1, zone: lan, address: 10.0.0.1/24}\n" +
			"zones: {lan: {description: x}}\n",
	} {
		if fp(other) == want {
			t.Errorf("the same fingerprint for\n%s", other)
		}
	}
}
