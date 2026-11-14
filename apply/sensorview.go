package apply

import (
	"bytes"
	"math/big"
	"net/netip"
	"slices"

	"github.com/starsmash29/fr_os-community/config"
)

// SensorView is the sensor daemons' view of a config: one JSON object
// with what each daemon reads, checked as the config package checks it.
// The Rust daemons read this, never the YAML copy: they would need a
// second YAML reader and a second set of checks (decisions.md, "phase
// 4c" and "phase 4e-1"). A config the checks refuse is
// {"config_error": message}: 1.x's daemons, which parse the copy
// themselves, then keep the settings they have (or stay idle at start).
//
//	{"tls_fingerprint": {"enabled", "blocklist": [{"fingerprint", "label"}],
//	                     "quarantine_on_match", "quarantine_duration_seconds"},
//	 "app_control": {"sources": ["dns"?, "sni"?]},
//	 "ai_ids": {"enabled", "excluded_macs", "excluded_ips", "internal_networks",
//	            "infrastructure", "threat_categories", "query_log",
//	            "quarantine_duration_seconds"}}
//
// app_control and ai_ids are what 1.x's fr-appid and fr-ai-ids derive
// from the config (testdata/reference/sensord.jsonl, "view"): the
// sources fr-appid follows, the addresses fr-ai-ids excludes, scores
// and never quarantines (but those it reads from the routing table and
// resolv.conf at run time), and the threat categories whose answers it
// counts.
func SensorView(raw config.Value) string {
	view := config.NewMap()
	c, err := config.Parse(raw)
	if err != nil {
		view.Set("config_error", err.Error())
	} else {
		tf := c.TlsFingerprint
		blocklist := make([]config.Value, len(tf.Blocklist))
		for i, e := range tf.Blocklist {
			entry := config.NewMap()
			entry.Set("fingerprint", e.Fingerprint)
			entry.Set("label", e.Label)
			blocklist[i] = entry
		}
		t := config.NewMap()
		t.Set("enabled", tf.Enabled)
		t.Set("blocklist", blocklist)
		t.Set("quarantine_on_match", tf.QuarantineOnMatch)
		t.Set("quarantine_duration_seconds", big.NewInt(c.AiIds.QuarantineDurationSeconds))
		view.Set("tls_fingerprint", t)
		view.Set("app_control", appControlView(c))
		view.Set("ai_ids", aiIdsView(c))
	}
	text, err := config.PyJSON(view, -1, false)
	if err != nil {
		// Every value above is JSON's.
		panic(err)
	}
	return text + "\n"
}

// appControlView is 1.x's frfw.appid.daemon.source_units: the resolver's
// query log when it is written, the SNI event file when the XDP filter
// reports passed names; nothing while app identification is off.
func appControlView(c *config.Config) *config.Map {
	sources := []config.Value{}
	if c.AppControl.Enabled {
		if c.Adblocker.Enabled && c.Adblocker.QueryLogging {
			sources = append(sources, "dns")
		}
		if c.XdpSniFilter.Enabled && c.AppControl.ObserveSni {
			sources = append(sources, "sni")
		}
	}
	m := config.NewMap()
	m.Set("sources", sources)
	return m
}

// threatCategories are 1.x's frfw.adblock.categories.THREAT_CATEGORIES:
// the categories whose blocked answers fr-ai-ids counts.
var threatCategories = []string{"malware", "phishing"}

// aiIdsView is what 1.x's frfw.ai_ids.daemon takes from the config:
// resolve_excluded_ips, internal_networks and infrastructure_ips (the
// config's part), each sorted as 1.x sorts it.
func aiIdsView(c *config.Config) *config.Map {
	excluded := map[string]bool{}
	for _, mac := range c.AiIds.ExcludedMacs {
		excluded[mac] = true
	}
	excludedIPs := map[string]bool{}
	infrastructure := map[string]bool{}
	for _, pool := range c.Dhcp.Zones.Values() {
		for _, r := range pool.Reservations {
			if excluded[r.MacAddress] {
				excludedIPs[r.Address] = true
			}
		}
		for _, s := range pool.DNSServers {
			infrastructure[s] = true
		}
	}
	outside := map[string]bool{}
	for _, m := range c.Nat.Masquerade {
		outside[m.OutZone] = true
	}
	networks := map[netip.Prefix]bool{}
	for _, iface := range c.Interfaces.Values() {
		if iface.Address == "" {
			continue
		}
		p := netip.MustParsePrefix(iface.Address) // checked by config.Parse
		infrastructure[p.Addr().String()] = true
		if !outside[iface.Zone] {
			networks[p.Masked()] = true
		}
	}
	if c.Wireguard.Enabled && c.Wireguard.Address != "" {
		p := netip.MustParsePrefix(c.Wireguard.Address)
		infrastructure[p.Addr().String()] = true
		networks[p.Masked()] = true
	}
	// Python orders IPv4Network by address, then mask.
	nets := make([]netip.Prefix, 0, len(networks))
	for p := range networks {
		nets = append(nets, p)
	}
	slices.SortFunc(nets, func(a, b netip.Prefix) int {
		if c := bytes.Compare(a.Addr().AsSlice(), b.Addr().AsSlice()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	threat := []config.Value{}
	for _, name := range threatCategories {
		if c.Adblocker.Categories.Has(name) {
			threat = append(threat, name)
		}
	}
	m := config.NewMap()
	m.Set("enabled", c.AiIds.Enabled)
	m.Set("excluded_macs", texts(c.AiIds.ExcludedMacs))
	m.Set("excluded_ips", texts(sortedKeys(excludedIPs)))
	netTexts := make([]string, len(nets))
	for i, p := range nets {
		netTexts[i] = p.String()
	}
	m.Set("internal_networks", texts(netTexts))
	m.Set("infrastructure", texts(sortedKeys(infrastructure)))
	m.Set("threat_categories", threat)
	m.Set("query_log", c.Adblocker.Enabled && c.Adblocker.QueryLogging)
	m.Set("quarantine_duration_seconds", big.NewInt(c.AiIds.QuarantineDurationSeconds))
	return m
}

func texts(list []string) []config.Value {
	out := make([]config.Value, len(list))
	for i, t := range list {
		out[i] = t
	}
	return out
}
