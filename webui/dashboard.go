package webui

import (
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// The dashboard (1.x's frfw.webui.routes.dashboard, GET /): the router
// at a glance -- its name and version, the config's state, the security
// alerts (G9) and checklist score (K8), the protection services, the
// machine's resources, the interfaces and what the firewall dropped
// lately (K6).

type service struct {
	Name, Href, Desc, State string
}

type ifaceRow struct {
	Zone, Device, Address, Link string
}

type alertRow struct {
	When, Alert, Client string
}

type dropRow struct {
	When, Chain, Src, Dst, Proto, Dport, In string
	HasDport                                bool
}

type dashboardData struct {
	Hostname         string
	ConfigValid      bool
	Kernel, CPUModel string
	CPUCount         int
	PQCShown         bool
	QuantumSafe      bool
	PQCEnabled       bool
	Alerts           []alertRow
	AlertsUntil      string
	Score            *score
	LiveNoPersist    bool
	RuleCount        int
	PortForwards     int
	ZoneCount        int
	InterfaceCount   int
	DHCPZones        int
	LinksUp          int
	LinksKnown       int
	AIIDSEnabled     bool
	Quarantined      string // "" when not known
	AIIDSRunning     bool
	AdblockEnabled   bool
	BlockedDomains   string // "-" when not known
	Services         []service
	Uptime           string
	Meters           []meter
	Backups          int
	Interfaces       []ifaceRow
	DropsShown       bool
	Drops            []dropRow
}

// loadRawConfig is config_store.load_raw: config.yaml as a mapping, or
// the empty config when the file is missing or isn't one. A file that
// isn't YAML fails the page, as in 1.x.
func (s *Server) loadRawConfig() (*config.Map, error) {
	path := s.env.Paths.Config()
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		return emptyConfig(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, config.MaxConfigBytes+1))
	if err != nil || len(data) > config.MaxConfigBytes || !isUTF8(data) {
		return nil, errInternal
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	v, err := config.LoadYAML(text)
	if err != nil {
		return nil, errInternal
	}
	if m, ok := v.(*config.Map); ok {
		return m, nil
	}
	return emptyConfig(), nil
}

func emptyConfig() *config.Map {
	return cmdMap("version", 1, "hostname", "fr-router", "interfaces", config.NewMap(), "zones", config.NewMap(),
		"rules", []config.Value{}, "nat", config.NewMap(), "dhcp", config.NewMap())
}

// pyLen is len(v or {}) for a config value: a mapping, list or string;
// anything else fails the page, as len() raises in 1.x.
func pyLen(v config.Value) (int, error) {
	if !config.Truthy(v) {
		return 0, nil
	}
	switch x := v.(type) {
	case *config.Map:
		return x.Len(), nil
	case []config.Value:
		return len(x), nil
	case string:
		return len([]rune(x)), nil
	}
	return 0, errInternal
}

func (s *Server) dashboard(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	c, cerr := config.Parse(raw)
	if cerr != nil {
		c = nil
	}
	d := &dashboardData{ConfigValid: c != nil}

	d.AIIDSEnabled = c != nil && c.AiIds.Enabled
	if d.AIIDSEnabled {
		status, err := s.helper.IDSQuarantineStatus()
		if err != nil {
			return nil, err
		}
		if ok, _ := status.Get("ok"); config.Truthy(ok) {
			if n, _ := status.Get("count"); n != nil {
				d.Quarantined = pyStr(n)
			}
		}
	}

	if c != nil {
		d.PQCShown, d.PQCEnabled = true, c.Pqc.Enabled
		groups, ok, err := tlsGroups(s.env.Paths.at("/etc/fr_os/webui_pqc_openssl.cnf"))
		if err != nil {
			return nil, err
		}
		// Go's TLS always offers the hybrid group (decisions.md).
		d.QuantumSafe = c.Pqc.Enabled && ok && strings.Contains(groups, "MLKEM")
	}

	d.AdblockEnabled = c != nil && c.Adblocker.Enabled
	blocked := -1
	d.BlockedDomains = "-"
	if d.AdblockEnabled {
		if blocked, err = countBlockedDomains(s.env.Paths.at("/etc/fr_os/adblock.hosts")); err != nil {
			return nil, err
		}
		d.BlockedDomains = thousands(blocked)
	}

	if c != nil {
		links, err := s.linkStates()
		if err != nil {
			return nil, err
		}
		for _, i := range c.Interfaces.Values() {
			link := "?"
			if up, ok := links[i.Device]; ok && up != nil {
				link = map[bool]string{true: "up", false: "down"}[*up]
			}
			d.Interfaces = append(d.Interfaces, ifaceRow{i.Zone, i.Device, i.Address, link})
		}
	}

	// Security-lessons G9: unseen security alerts, admins only.
	if q.user.IsAdmin() {
		for _, e := range alertsSince(s.env.Paths.AuditLog(), alertsSeen(s.env.Paths.AlertsSeen(), q.user.Username)) {
			ts, _ := e.Get("ts")
			when := 0.0
			if config.Truthy(ts) {
				if when, err = pyFloatOf(ts); err != nil {
					return nil, err
				}
			}
			row := alertRow{When: s.localTime(when, "2006-01-02 15:04"), Alert: jinjaStr(e, "alert"), Client: "-"}
			if cl, _ := e.Get("client"); config.Truthy(cl) {
				row.Client = pyStr(cl)
			}
			if len(d.Alerts) == 0 {
				d.AlertsUntil = jinjaStr(e, "ts")
			}
			d.Alerts = append(d.Alerts, row)
		}
	}

	if c != nil && c.Logging.Drops {
		d.DropsShown = true
		if d.Drops, err = s.recentDrops(); err != nil {
			return nil, err
		}
	}

	// Security-lessons K8: the checklist's score and what's still open.
	if d.Score, err = s.securityScore(raw); err != nil {
		return nil, err
	}

	d.AIIDSRunning = s.daemonActive("fr-ai-ids.service")
	snap, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	for _, row := range d.Interfaces {
		if row.Link == "up" {
			d.LinksUp++
		}
		if row.Link != "?" {
			d.LinksKnown++
		}
	}

	d.Hostname = "?"
	if h, _ := raw.Get("hostname"); config.Truthy(h) {
		d.Hostname = pyStr(h)
	}
	get := func(key string) config.Value { v, _ := raw.Get(key); return v }
	var forwards config.Value
	if nat := get("nat"); config.Truthy(nat) {
		m, ok := nat.(*config.Map)
		if !ok {
			return nil, errInternal // 1.x: .get on a non-mapping
		}
		forwards, _ = m.Get("port_forwards")
	}
	for _, n := range []struct {
		dst *int
		v   config.Value
	}{{&d.ZoneCount, get("zones")}, {&d.InterfaceCount, get("interfaces")}, {&d.RuleCount, get("rules")},
		{&d.PortForwards, forwards}, {&d.DHCPZones, get("dhcp")}} {
		if *n.dst, err = pyLen(n.v); err != nil {
			return nil, err
		}
	}
	backups, err := apply.ListBackups(s.env.Paths.at("/etc/fr_os/backups"))
	if err != nil {
		return nil, errInternal
	}
	d.Backups = len(backups)
	d.Services = s.services(c, d.AIIDSRunning, blocked)
	if d.LiveNoPersist, err = s.liveWithoutPersistence(); err != nil {
		return nil, err
	}
	d.Kernel, d.CPUModel, d.CPUCount = snap.Kernel, snap.CPUModel, snap.CPUCount
	d.Uptime = formatDuration(snap.Uptime, snap.HasUptime)
	d.Meters = snap.meters()
	return s.render(q, "dashboard", flash(q, &page{Username: q.user.Username, Data: d}))
}

// daemonActive is `systemctl is-active -- unit` (1.x's is_daemon_active):
// a status query any user can run. 1.x waits for it without a limit; the
// port gives it 10 seconds (decisions.md).
func (s *Server) daemonActive(unit string) bool {
	_, out, err := s.env.Run([]string{"systemctl", "is-active", "--", unit}, 10)
	return err == nil && config.PyStrip(out) == "active"
}

// services are the protection features with a state badge: "running" or
// "not running" where a daemon can be checked, else "on"/"off" from the
// config.
func (s *Server) services(c *config.Config, aiIDSRunning bool, blocked int) []service {
	if c == nil {
		return nil
	}
	tlsfpRunning := c.TlsFingerprint.Enabled && s.daemonActive("fr-tls-fp.service")
	running := func(enabled, up bool) string {
		switch {
		case !enabled:
			return "off"
		case up:
			return "running"
		}
		return "not running"
	}
	on := func(enabled bool) string {
		if enabled {
			return "on"
		}
		return "off"
	}
	xdp := strings.Join(c.XdpSniFilter.Interfaces, ", ")
	if xdp == "" {
		xdp = "no interfaces"
	}
	dns := "Ads and category blocklists"
	if blocked >= 0 {
		dns = thousands(blocked) + " domains blocked"
	}
	return []service{
		{"AI IDS/IPS", "/ai-ids", "Behavioural anomaly detection with kernel quarantine", running(c.AiIds.Enabled, aiIDSRunning)},
		{"TLS SNI filter", "/xdp", "eBPF/XDP ClientHello filter on " + xdp, on(c.XdpSniFilter.Enabled)},
		{"DNS filtering", "/adblock", dns, on(c.Adblocker.Enabled)},
		{"IoT isolation", "/iot", strconv.Itoa(len(c.Iot.IsolatedMacs)) + " device(s) isolated by MAC", on(c.Iot.Enabled)},
		{"TLS fingerprinting", "/tls", "JA4/JA3 client inventory, no decryption", running(c.TlsFingerprint.Enabled, tlsfpRunning)},
		{"ZTNA gate", "/ztna", strconv.Itoa(len(c.Ztna.Users)) + " identity account(s)", on(c.Ztna.Enabled)},
	}
}

// recentDrops is what the default-deny policy dropped lately
// (security-lessons K6), the newest ten; the kernel log is root's, so
// the apply-helper reads it.
func (s *Server) recentDrops() ([]dropRow, error) {
	reply, err := s.helper.FirewallDrops()
	if err != nil {
		return nil, err
	}
	var drops []config.Value
	if ok, _ := reply.Get("ok"); config.Truthy(ok) {
		list, _ := reply.Get("drops")
		if config.Truthy(list) {
			items, isList := list.([]config.Value)
			if !isList {
				return nil, errInternal
			}
			drops = items
		}
	}
	var rows []dropRow
	for _, item := range drops[:min(len(drops), 10)] {
		e, ok := item.(*config.Map)
		if !ok {
			return nil, errInternal // 1.x: {**entry} of a non-mapping
		}
		ts, _ := e.Get("ts")
		when := 0.0
		if config.Truthy(ts) {
			if when, err = pyFloatOf(ts); err != nil {
				return nil, err
			}
		}
		or := func(key string) string {
			if v, _ := e.Get(key); config.Truthy(v) {
				return pyStr(v)
			}
			return "-"
		}
		row := dropRow{When: s.localTime(when, "2006-01-02 15:04:05"), Chain: jinjaStr(e, "chain"),
			Src: or("src"), Dst: or("dst"), Proto: or("proto"), In: or("in")}
		if v, _ := e.Get("dport"); config.Truthy(v) {
			row.HasDport, row.Dport = true, pyStr(v)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// securityScore is 1.x's score_for: the checklist worked out from the
// accounts, the saved config, the update check, the rule check and the
// attack surface.
func (s *Server) securityScore(raw *config.Map) (*score, error) {
	c, err := config.Parse(raw)
	if err != nil {
		c = nil
	}
	in := scoreInput{config: c, requireMFA: s.store.RequireMFA()}
	if c != nil {
		if in.lint, err = lintRules(c, loadRuleHits(s.env.Paths.at("/etc/fr_os/rule_hits.json")), s.env.Now()); err != nil {
			return nil, err
		}
		if in.lint == nil {
			in.lint = []finding{}
		}
		reply, err := s.helper.ListeningSockets()
		if err != nil {
			return nil, err
		}
		if ok, _ := reply.Get("ok"); config.Truthy(ok) {
			list, has := reply.Get("listeners")
			if !has {
				list = []config.Value{}
			}
			listeners, err := listenersOf(list)
			if err != nil {
				return nil, err
			}
			addrs, _ := reply.Get("addresses")
			addresses, err := addressesOf(addrs)
			if err != nil {
				return nil, err
			}
			in.surface, in.surfaceKnown = surfaceRows(c, listeners, addresses), true
		}
	}
	if in.accounts, _, err = s.store.Users(); err != nil {
		return nil, err
	}
	in.updateCheck = readUpdateCheck(s.env.Paths.UpdateCheck(), s.version)
	return evaluate(in), nil
}
