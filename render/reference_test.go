package render

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"maps"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/appid"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReference renders every file FR_OS 1.x rendered from the configs
// its test suite accepted (AGENTS.md, "Differential tests"): the same
// config, and the same ULA prefix in the router's state, must give the
// same text, byte for byte.
func TestReference(t *testing.T) {
	configs, err := reference.ConfigCases()
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]jsontext.Value{}
	for _, c := range configs {
		inputs[c.ID] = c.Input
	}
	cases, err := reference.RenderCases()
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := appid.Load()
	if err != nil {
		t.Fatal(err)
	}
	defer func(l *time.Location) { config.Local = l }(config.Local)
	config.Local = time.UTC // reference/generate.sh records with TZ=UTC

	base := map[string]map[string]jsontext.Value{}
	for _, c := range cases {
		if c.Config != "" && c.ULAState == nil {
			base[c.Config] = c.Output
		}
	}
	checked, decided, pqc := 0, 0, 0
	for _, c := range cases {
		if c.Pqc != "" {
			pqc++
			got := map[string]string{"tls": OpenSSLConf(c.Hybrid), "ssh": SSHKexDropin(c.Hybrid)}[c.Pqc]
			compare(t, c.ID, c.Pqc, c.Output[c.Pqc], got)
			continue
		}
		input, ok := inputs[c.Config]
		if !ok {
			t.Fatalf("%s: config %s is not in config.jsonl", c.ID, c.Config)
		}
		raw, err := config.ParseJSON(input)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		cfg, err := config.Parse(raw)
		if name := config.Decided(raw); name != "" {
			if err == nil {
				t.Errorf("%s: decision %q: accepted here", c.ID, name)
			}
			decided++
			continue
		}
		if err != nil {
			t.Errorf("%s: 1.x accepted the config, refused here: %v", c.ID, err)
			continue
		}
		var generated *netip.Prefix
		want := c.Output
		if c.ULAState != nil {
			p := netip.MustParsePrefix(*c.ULAState)
			generated = &p
			want = maps.Clone(base[c.Config])
			maps.Copy(want, c.Output)
			// Only these depend on the state.
			for _, name := range []string{"kea", "dnsmasq", "dhcpcd", "sysctl"} {
				delete(want, name)
			}
		}
		got, errs := renderAll(cfg, catalog, ULAPrefix(cfg, generated), c.ULAState == nil)
		for _, name := range slices.Sorted(maps.Keys(got)) {
			if typ, failed := c.Error[name]; failed {
				t.Errorf("%s %s: 1.x raised %s, rendered here", c.ID, name, typ)
				continue
			}
			compare(t, c.ID, name, want[name], got[name])
		}
		for name, err := range errs {
			if _, failed := c.Error[name]; !failed {
				t.Errorf("%s %s: %v", c.ID, name, err)
			}
		}
		checked++
	}
	t.Logf("%d configs' renders replayed, %d decided, %d PQC fragments", checked, decided, pqc)
	if checked == 0 || pqc != 4 {
		t.Fatal("render.jsonl has no cases")
	}
}

// renderAll is what reference/test_fros_render_cases.py renders.
func renderAll(c *config.Config, catalog *appid.Catalog, ula *netip.Prefix, all bool) (map[string]any, map[string]error) {
	out, errs := map[string]any{}, map[string]error{}
	out["ra"] = RA(c, ula)
	if wg, err := WireGuard(&c.Wireguard, testPrivateKey, ula); err != nil {
		errs["wireguard"] = err
	} else {
		out["wireguard"] = wg
	}
	out["sshd"] = SSHD(c, ula)
	if !all {
		return out, errs
	}
	if kea, err := Kea(c); err != nil {
		errs["kea"] = err
	} else {
		out["kea"] = kea
	}
	out["dnsmasq"] = Dnsmasq(c, DefaultDnsmasqPaths, catalog)
	out["dhcpcd"] = Dhcpcd(c)
	var pairs [][2]string
	for _, s := range Sysctls(c) {
		pairs = append(pairs, [2]string{s.Key, s.Value})
	}
	out["sysctl"] = pairs
	return out, errs
}

// testPrivateKey is the key the reference module renders with.
const testPrivateKey = "cHJpdmF0ZS1rZXktb2YtdGhlLXJvdXRlci0wMDAwMDA="

func compare(t *testing.T, id, name string, want jsontext.Value, got any) {
	t.Helper()
	if want == nil {
		t.Errorf("%s %s: rendered here, 1.x has no %s", id, name, name)
		return
	}
	switch g := got.(type) {
	case string:
		var w string
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatalf("%s %s: %v", id, name, err)
		}
		if g != w {
			t.Errorf("%s %s differs:\n--- 1.x\n%s\n--- here\n%s", id, name, w, g)
		}
	default:
		var w, gg any
		b, _ := json.Marshal(got)
		if err := json.Unmarshal(want, &w); err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(b, &gg)
		wb, _ := json.Marshal(w, json.Deterministic(true))
		gb, _ := json.Marshal(gg, json.Deterministic(true))
		if string(wb) != string(gb) {
			t.Errorf("%s %s differs:\n--- 1.x\n%s\n--- here\n%s", id, name, wb, gb)
		}
	}
}
