package apply

import (
	"math/big"

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
//	                     "quarantine_on_match", "quarantine_duration_seconds"}}
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
	}
	text, err := config.PyJSON(view, -1, false)
	if err != nil {
		// Every value above is JSON's.
		panic(err)
	}
	return text + "\n"
}
