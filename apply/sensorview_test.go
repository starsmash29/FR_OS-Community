package apply_test

import (
	"testing"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// TestSensorView checks the view the Rust sensor daemons read: the TLS
// fingerprint settings of an accepted config, with the quarantine time
// from ai_ids, and the checks' message for a refused one.
func TestSensorView(t *testing.T) {
	for _, c := range []struct{ name, yaml, want string }{
		{
			"blocklist",
			`version: 1
hostname: r
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 192.168.7.1/24}
zones: {wan: {}, lan: {}}
xdp_sni_filter: {enabled: true, interfaces: [lan]}
ai_ids: {quarantine_duration_seconds: 600}
tls_fingerprint:
  enabled: true
  quarantine_on_match: true
  blocklist:
    - {fingerprint: 0123456789abcdef0123456789abcdef, label: bot}
    - t13d1516h2_8daaf6152771_02713d6af862
`,
			`{"tls_fingerprint": {"enabled": true, "blocklist": [{"fingerprint": "0123456789abcdef0123456789abcdef", "label": "bot"}, ` +
				`{"fingerprint": "t13d1516h2_8daaf6152771_02713d6af862", "label": ""}], "quarantine_on_match": true, "quarantine_duration_seconds": 600}, ` +
				`"app_control": {"sources": []}, "ai_ids": {"enabled": false, "excluded_macs": [], "excluded_ips": [], ` +
				`"internal_networks": ["192.168.7.0/24"], "infrastructure": ["192.168.7.1"], "threat_categories": [], ` +
				`"query_log": false, "quarantine_duration_seconds": 600}}` + "\n",
		},
		{
			"defaults",
			`version: 1
hostname: r
interfaces:
  wan: {device: eth0, zone: wan}
zones: {wan: {}}
`,
			`{"tls_fingerprint": {"enabled": false, "blocklist": [], "quarantine_on_match": false, "quarantine_duration_seconds": 7200}, ` +
				`"app_control": {"sources": []}, "ai_ids": {"enabled": false, "excluded_macs": [], "excluded_ips": [], ` +
				`"internal_networks": [], "infrastructure": [], "threat_categories": [], "query_log": false, ` +
				`"quarantine_duration_seconds": 7200}}` + "\n",
		},
		{
			"refused",
			`version: 1
hostname: r
interfaces:
  wan: {device: eth0, zone: wan}
zones: {wan: {}}
tls_fingerprint: {enabled: true}
`,
			"",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := config.LoadYAML(c.yaml)
			if err != nil {
				t.Fatal(err)
			}
			got := apply.SensorView(raw)
			want := c.want
			if want == "" {
				_, perr := config.Parse(raw)
				if perr == nil {
					t.Fatal("config accepted")
				}
				text, err := config.PyJSON(mapOf("config_error", perr.Error()), -1, false)
				if err != nil {
					t.Fatal(err)
				}
				want = text + "\n"
			}
			if got != want {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

func mapOf(k string, v config.Value) *config.Map {
	m := config.NewMap()
	m.Set(k, v)
	return m
}
