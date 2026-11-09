package webui

import (
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The AI IDS/IPS screen (1.x's routes/ai_ids.py): the fr-ai-ids
// daemon's health, the hosts the kernel holds in quarantine now (through
// the apply-helper), the daemon's display-only log of what it flagged,
// and the ai_ids settings.

// recentEventsLimit is 1.x's RECENT_EVENTS_LIMIT.
const recentEventsLimit = 50

type quarantineRow struct{ Who, ExpiresIn string }

type aiEventRow struct {
	IP, MAC, Score, Reasons, ConnRate, UniqueDstRatio, SNIBlocks string
	NXDomain, DGA, Threats                                       string
}

type aiIDSData struct {
	ConfigError        string
	DaemonActive       bool
	Enabled            bool
	QuarantineDuration string
	ExcludedMACs       string
	QuarantineError    string
	HasQuarantineError bool
	Quarantined        []quarantineRow
	QuarantinedMACs    []quarantineRow
	Events             []aiEventRow
}

// recentAIEvents is reversed(load_recent_events()): the last 50, newest
// first; a file that isn't a JSON list is none.
func (s *Server) recentAIEvents() ([]config.Value, error) {
	v, ok, err := readJSONState(s.env.Paths.sensorState("ai_ids_state.json"))
	if err != nil {
		return nil, err
	}
	list, isList := v.([]config.Value)
	if !ok || !isList {
		return nil, nil
	}
	if len(list) > recentEventsLimit {
		list = list[len(list)-recentEventsLimit:]
	}
	out := make([]config.Value, len(list))
	for i, e := range list {
		out[len(list)-1-i] = e
	}
	return out, nil
}

func (s *Server) showAIIDS(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "ai_ids")
	if err != nil {
		return nil, err
	}
	d := &aiIDSData{ConfigError: configError(raw)}
	status, err := s.helper.IDSQuarantineStatus()
	if err != nil {
		return nil, err // a HelperError isn't caught here in 1.x
	}
	d.Enabled = config.Truthy(pyGet(section, "enabled", false))
	excluded, err := pyStrList(field(section, "excluded_macs"))
	if err != nil {
		return nil, err
	}
	d.ExcludedMACs = strings.Join(excluded, ", ")
	d.QuarantineDuration = pyStr(pyGet(section, "quarantine_duration_seconds", pyInt(2*3600)))
	d.DaemonActive = s.daemonActive("fr-ai-ids.service")

	ok := config.Truthy(field(status, "ok"))
	var quarantined, macs []config.Value
	if ok {
		v, defined := status.Get("quarantined")
		if !defined {
			v = []config.Value{}
		}
		w, defined := status.Get("macs")
		if !defined {
			w = []config.Value{}
		}
		if quarantined, err = jinjaIter(v, true); err != nil {
			return nil, err
		}
		if macs, err = jinjaIter(w, true); err != nil {
			return nil, err
		}
		// `not quarantined and not quarantined_macs` reads the values.
		if !config.Truthy(v) && !config.Truthy(w) {
			quarantined, macs = nil, nil
		}
	} else {
		msg := field(status, "message")
		d.HasQuarantineError = config.Truthy(msg)
		d.QuarantineError = pyStr(msg)
	}
	for _, e := range quarantined {
		d.Quarantined = append(d.Quarantined, quarantineRow{jinjaText(e, "ip"), jinjaText(e, "expires_in")})
	}
	for _, e := range macs {
		d.QuarantinedMACs = append(d.QuarantinedMACs, quarantineRow{jinjaText(e, "mac"), jinjaText(e, "expires_in")})
	}

	events, err := s.recentAIEvents()
	if err != nil {
		return nil, err
	}
	for _, e := range events {
		reasons := ""
		if v, ok := jinjaGet(e, "reasons"); ok {
			if reasons, err = jinjaJoin(v, ", "); err != nil {
				return nil, err
			}
		}
		row := aiEventRow{IP: jinjaText(e, "ip"), Score: jinjaText(e, "score"), Reasons: reasons,
			ConnRate: jinjaText(e, "conn_rate"), UniqueDstRatio: jinjaText(e, "unique_dst_ratio"),
			SNIBlocks: jinjaText(e, "sni_block_count"), NXDomain: jinjaDefault(e, "nxdomain_count", "0"),
			DGA: jinjaDefault(e, "dga_nxdomain_count", "0"), Threats: jinjaDefault(e, "dns_threat_count", "0")}
		if v, ok := jinjaGet(e, "mac"); ok && config.Truthy(v) {
			row.MAC = pyStr(v)
		}
		d.Events = append(d.Events, row)
	}
	return s.render(q, "ai_ids", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveAIIDS(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	var excluded string
	var duration config.Value
	if err = q.fields(func(p *formParams) {
		enabled, excluded = p.boolOr("enabled", false), p.strOr("excluded_macs", "")
		duration = p.intOr("quarantine_duration_seconds", pyInt(2*3600))
	}); err != nil {
		return nil, err
	}
	raw.Set("ai_ids", cmdMap("enabled", enabled, "excluded_macs", splitStripped(excluded),
		"quarantine_duration_seconds", duration))
	return s.saved(raw, "/ai-ids", "AI IDS settings saved -- restart fr-ai-ids.service (or reboot) to pick up changes")
}
