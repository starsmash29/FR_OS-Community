package webui

import (
	"sort"

	"github.com/starsmash29/fr_os-community/config"
)

// The TLS fingerprints screen (1.x's routes/tls.py): fr-tls-fp's
// display-only inventory and events, labelled from the last IoT scan;
// the tls_fingerprint settings and blocklist.

const tlsLayout = "2006-01-02 15:04"

type tlsRow struct {
	Client, Label, JA4, JA3Latest, SNI, Count, LastSeen string
	JA3Variants, ClientsWithIt                          int
	Blocked                                             bool
	lastSeen                                            float64
}

type tlsEvent struct {
	When, Type, Label, Client, JA4, SNI, Action string
}

type tlsBlockEntry struct{ Fingerprint, Label string }

type tlsData struct {
	ConfigError                string
	Enabled, QuarantineOnMatch bool
	Blocklist                  []tlsBlockEntry
	XDPEnabled                 bool
	XDPInterfaces              string
	DaemonActive               bool
	Learning                   bool
	Generated                  string
	HasStats                   bool
	Hellos, ParseErrors        string
	Rows                       []tlsRow
	Events                     []tlsEvent
}

// tlsStamp is the screen's _ts: a number as local time, else "-".
func (s *Server) tlsStamp(v config.Value) string {
	if text, ok := s.localStamp(v, tlsLayout); ok {
		return text
	}
	return "-"
}

// blockedFingerprint is `e.get("fingerprint") if isinstance(e, dict)
// else str(e)`, lower-cased; a mapping without one fails the page, as
// None.lower() does.
func blockedFingerprint(e config.Value) (string, error) {
	if m, ok := e.(*config.Map); ok {
		fp, ok := field(m, "fingerprint").(string)
		if !ok {
			return "", errInternal
		}
		return config.PyLower(fp), nil
	}
	return config.PyLower(pyStr(e)), nil
}

func (s *Server) showTLS(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "tls_fingerprint")
	if err != nil {
		return nil, err
	}
	d := &tlsData{ConfigError: configError(raw)}
	devices, err := s.inventoryDevices()
	if err != nil {
		return nil, err
	}
	labels := map[string]config.Value{}
	for _, dev := range devices {
		if ip := field(dev, "ip"); config.Truthy(ip) {
			if text, ok := ip.(string); ok {
				labels[text] = firstTruthy(dev, "hostname", "vendor", "mac")
			}
		}
	}
	state, err := readJSONMap(s.env.Paths.sensorState("tls_fingerprints.json"))
	if err != nil {
		return nil, err
	}
	if state == nil {
		state = cmdMap("generated", nil, "clients", config.NewMap(), "events", []config.Value{}, "learning", true)
	}
	entries, err := pyIter(field(section, "blocklist"))
	if err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	for _, e := range entries {
		fp, err := blockedFingerprint(e)
		if err != nil {
			return nil, err
		}
		blocked[fp] = true
	}
	clientsV := field(state, "clients")
	clients := config.NewMap()
	if config.Truthy(clientsV) {
		m, ok := clientsV.(*config.Map)
		if !ok {
			return nil, errInternal
		}
		clients = m
	}
	var rows []tlsRow
	for i, client := range clients.Keys() {
		fps, ok := clients.Values()[i].(*config.Map)
		if !ok {
			return nil, errInternal
		}
		for j, ja4 := range fps.Keys() {
			seen, ok := fps.Values()[j].(*config.Map)
			if !ok {
				return nil, errInternal
			}
			ja3V := pyGet(seen, "ja3", []config.Value{})
			sniV := pyGet(seen, "sni", []config.Value{})
			row := tlsRow{Client: pyStr(client), JA4: pyStr(ja4), Count: pyStr(pyGet(seen, "count", pyInt(0))),
				LastSeen: s.tlsStamp(field(seen, "last_seen")), JA3Latest: "-", SNI: "-"}
			if text, ok := client.(string); ok {
				if l := labels[text]; config.Truthy(l) {
					row.Label = pyStr(l)
				}
			}
			if row.lastSeen, err = sortNumber(pyGet(seen, "last_seen", pyInt(0))); err != nil {
				return nil, err
			}
			key, _ := ja4.(string)
			row.Blocked = blocked[key]
			ja3, err := jinjaIter(ja3V, true)
			if err != nil {
				return nil, err
			}
			for _, j := range ja3 {
				if text, ok := j.(string); ok && blocked[text] {
					row.Blocked = true
				}
			}
			if config.Truthy(ja3V) {
				row.JA3Latest = pyStr(ja3[len(ja3)-1])
			}
			row.JA3Variants = len(ja3)
			if config.Truthy(sniV) {
				if row.SNI, err = jinjaJoin(sniV, ", "); err != nil {
					return nil, err
				}
			}
			rows = append(rows, row)
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return -rows[i].lastSeen < -rows[j].lastSeen })
	// How many clients share each JA4: one on a single device is more
	// interesting than one every phone presents.
	sharing := map[string]int{}
	for _, r := range rows {
		sharing[r.JA4]++
	}
	for i := range rows {
		rows[i].ClientsWithIt = sharing[rows[i].JA4]
	}
	if len(rows) > 500 {
		rows = rows[:500]
	}
	d.Rows = rows

	events, err := pyIter(field(state, "events"))
	if err != nil {
		return nil, err
	}
	for i := len(events) - 1; i >= 0 && len(d.Events) < 100; i-- {
		e, ok := events[i].(*config.Map)
		if !ok {
			return nil, errInternal
		}
		d.Events = append(d.Events, tlsEvent{When: s.tlsStamp(field(e, "ts")), Type: jinjaText(e, "type"),
			Label: jinjaText(e, "label"), Client: jinjaText(e, "client"), JA4: jinjaText(e, "ja4"),
			SNI: jinjaOr(e, "sni", "-"), Action: jinjaOr(e, "action", "-")})
	}
	for _, e := range entries {
		if m, ok := e.(*config.Map); ok {
			d.Blocklist = append(d.Blocklist, tlsBlockEntry{jinjaText(m, "fingerprint"), jinjaOr(m, "label", "-")})
		} else {
			d.Blocklist = append(d.Blocklist, tlsBlockEntry{pyStr(e), "-"})
		}
	}
	xdp, err := getMapOr(raw, "xdp_sni_filter")
	if err != nil {
		return nil, err
	}
	d.XDPEnabled = config.Truthy(field(xdp, "enabled"))
	ifaces, err := pyIter(field(xdp, "interfaces"))
	if err != nil {
		return nil, err
	}
	if d.XDPInterfaces, err = jinjaJoin(append([]config.Value{}, ifaces...), ", "); err != nil {
		return nil, err
	}
	d.Enabled = config.Truthy(pyGet(section, "enabled", false))
	d.QuarantineOnMatch = config.Truthy(pyGet(section, "quarantine_on_match", false))
	d.DaemonActive = s.daemonActive("fr-tls-fp.service")
	d.Learning = config.Truthy(pyGet(state, "learning", true))
	d.Generated = s.tlsStamp(field(state, "generated"))
	if stats := field(state, "stats"); config.Truthy(stats) {
		d.HasStats = true
		d.Hellos, d.ParseErrors = jinjaOr(stats, "hellos", "0"), jinjaOr(stats, "parse_errors", "0")
	}
	return s.render(q, "tls", flash(q, &page{Username: q.user.Username, Data: d}))
}

// tlsBlocklistWithout is the blocklist without fingerprint (already
// stripped and lower-cased).
func tlsBlocklistWithout(section *config.Map, fingerprint string) ([]config.Value, error) {
	entries, err := pyIter(field(section, "blocklist"))
	if err != nil {
		return nil, err
	}
	out := []config.Value{}
	for _, e := range entries {
		fp, err := blockedFingerprint(e)
		if err != nil {
			return nil, err
		}
		if fp != fingerprint {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *Server) saveTLSSettings(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled, quarantine bool
	if err = q.fields(func(p *formParams) {
		enabled, quarantine = p.boolOr("enabled", false), p.boolOr("quarantine_on_match", false)
	}); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "tls_fingerprint")
	if err != nil {
		return nil, err
	}
	section := copyMap(previous)
	section.Set("enabled", enabled)
	section.Set("quarantine_on_match", quarantine)
	setdefault(section, "blocklist", []config.Value{})
	raw.Set("tls_fingerprint", section)
	return s.saved(raw, "/tls", "TLS fingerprinting settings saved -- click Apply on the dashboard")
}

func (s *Server) blockTLS(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var fingerprint, label string
	if err = q.fields(func(p *formParams) { fingerprint, label = p.str("fingerprint"), p.strOr("label", "") }); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "tls_fingerprint")
	if err != nil {
		return nil, err
	}
	section := copyMap(previous)
	fingerprint = config.PyLower(pyStripped(fingerprint))
	entries, err := tlsBlocklistWithout(section, fingerprint)
	if err != nil {
		return nil, err
	}
	section.Set("blocklist", append(entries, cmdMap("fingerprint", fingerprint, "label", pyStripped(label))))
	raw.Set("tls_fingerprint", section)
	// The running daemon re-reads the blocklist within 30 seconds; no Apply needed.
	return s.saved(raw, "/tls", fingerprint+" added to the blocklist")
}

func (s *Server) unblockTLS(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var fingerprint string
	if err = q.fields(func(p *formParams) { fingerprint = p.str("fingerprint") }); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "tls_fingerprint")
	if err != nil {
		return nil, err
	}
	section := copyMap(previous)
	fingerprint = config.PyLower(pyStripped(fingerprint))
	entries, err := tlsBlocklistWithout(section, fingerprint)
	if err != nil {
		return nil, err
	}
	section.Set("blocklist", entries)
	raw.Set("tls_fingerprint", section)
	return s.saved(raw, "/tls", fingerprint+" removed from the blocklist")
}
