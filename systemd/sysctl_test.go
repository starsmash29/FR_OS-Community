package systemd

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// TestKernelIPv6SettingsAtBoot: the image's sysctl.d file sets, for every
// interface, each IPv6 setting an apply's IPv6 step turns off for "all"
// and "default" (render.Sysctls), to the same value. The kernel then
// takes no RA and makes no SLAAC address of its own in the gap between
// an apply's ruleset, which lets the provider's RA in, and its IPv6 step
// (decisions.md, "the kernel's RA settings at boot").
func TestKernelIPv6SettingsAtBoot(t *testing.T) {
	data, err := os.ReadFile("sysctl-fr_os-ipv6.conf")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("not a setting: %q", line)
		}
		got = append(got, strings.TrimSpace(key)+"="+strings.TrimSpace(value))
	}
	var want []string
	for _, s := range render.Sysctls(&config.Config{}) {
		if rest, ok := strings.CutPrefix(s.Key, "ipv6/conf/all/"); ok && s.Value == "0" && rest != "forwarding" {
			want = append(want, "net.ipv6.conf.*."+rest+"="+s.Value)
		}
	}
	if len(want) == 0 || !slices.Equal(got, want) {
		t.Errorf("sysctl-fr_os-ipv6.conf sets %v, render.Sysctls turns off %v", got, want)
	}
}
