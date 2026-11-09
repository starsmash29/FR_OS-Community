package webui

import (
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/appid"
	"github.com/starsmash29/fr_os-community/config"
)

// The Applications screen (1.x's routes/apps.py): which apps clients
// use, from fr-appid's display-only usage summary, labelled from the
// last IoT scan; the app_control settings and the blocked-app list.

type appClient struct {
	IP, Label, Hits, LastSeen, Sources string
	Active                             bool
	hits                               float64
}

type appRow struct {
	ID, Name, Category, Names, Hits, ActiveClients, LastSeen string
	Clients                                                  []appClient
	Blocked                                                  bool
	active, hits                                             float64
}

type prerequisite struct {
	OK   bool
	Text string
}

type appsData struct {
	ConfigError                      string
	Enabled, ObserveSNI, BlockViaXDP bool
	Prerequisites                    []prerequisite
	DaemonActive                     bool
	Rows                             []appRow
	UsageGenerated                   string
	Source, License, Ref, Generated  string
}

// inventory is load_inventory(): the last IoT scan, or nil.
func (s *Server) inventory() (*config.Map, error) {
	return readJSONMap(s.env.Paths.sensorState("iot_inventory.json"))
}

// inventoryDevices is `(load_inventory() or {}).get("devices", [])`,
// each a mapping (1.x calls .get on them).
func (s *Server) inventoryDevices() ([]*config.Map, error) {
	inv, err := s.inventory()
	if err != nil || inv == nil {
		return nil, err
	}
	v, ok := inv.Get("devices")
	if !ok {
		return nil, nil
	}
	items, err := jinjaIter(v, true)
	if err != nil {
		return nil, err
	}
	out := make([]*config.Map, len(items))
	for i, item := range items {
		m, ok := item.(*config.Map)
		if !ok {
			return nil, errInternal
		}
		out[i] = m
	}
	return out, nil
}

// firstTruthy is `a or b or c` over a device's fields.
func firstTruthy(m *config.Map, keys ...string) config.Value {
	var v config.Value
	for _, k := range keys {
		v = field(m, k)
		if config.Truthy(v) {
			return v
		}
	}
	return v
}

// clientLabels is _client_labels: ip -> hostname, vendor or MAC from the
// last scan, for devices that have both.
func (s *Server) clientLabels() (map[string]string, error) {
	devices, err := s.inventoryDevices()
	if err != nil {
		return nil, err
	}
	labels := map[string]string{}
	for _, d := range devices {
		ip := field(d, "ip")
		label := firstTruthy(d, "hostname", "vendor", "mac")
		if ipText, ok := ip.(string); ok && ipText != "" && config.Truthy(label) {
			labels[ipText] = pyStr(label)
		}
	}
	return labels, nil
}

func appPrerequisites(raw *config.Map) ([]prerequisite, error) {
	adblocker, err := getMapOr(raw, "adblocker")
	if err != nil {
		return nil, err
	}
	xdp, err := getMapOr(raw, "xdp_sni_filter")
	if err != nil {
		return nil, err
	}
	app, err := getMapOr(raw, "app_control")
	if err != nil {
		return nil, err
	}
	on := func(m *config.Map, k string) bool { return config.Truthy(field(m, k)) }
	return []prerequisite{
		{on(adblocker, "enabled") && on(adblocker, "query_logging"),
			"DNS observation: Ad-Block resolver enabled with query logging"},
		{on(adblocker, "enabled") && on(adblocker, "serve_lan"),
			"DNS blocking: Ad-Block resolver announced to LAN clients (serve_lan)"},
		{on(adblocker, "force_dns"), "Clients cannot bypass the resolver with their own DNS server (force_dns)"},
		{on(xdp, "enabled") && on(app, "observe_sni"),
			"SNI observation: XDP filter enabled on the LAN-side interfaces with observe_sni"},
	}, nil
}

// sortNumber is a value 1.x negates for a sort key: a number (or bool).
func sortNumber(v config.Value) (float64, error) {
	if _, isStr := v.(string); !isStr {
		if f, ok := number(v); ok {
			return f, nil
		}
	}
	return 0, errInternal
}

func (s *Server) showApps(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "app_control")
	if err != nil {
		return nil, err
	}
	d := &appsData{ConfigError: configError(raw)}
	catalog, err := appid.Load()
	if err != nil {
		return nil, err
	}
	usage, err := readJSONMap(s.env.Paths.sensorState("appid_usage.json"))
	if err != nil {
		return nil, err
	}
	var generated config.Value
	apps := config.NewMap()
	if usage != nil {
		if m, ok := field(usage, "apps").(*config.Map); ok {
			apps, generated = m, field(usage, "generated")
		}
	}
	labels, err := s.clientLabels()
	if err != nil {
		return nil, err
	}
	blockedList, err := pyIter(field(section, "blocked_apps"))
	if err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	for _, b := range blockedList {
		if id, ok := b.(string); ok {
			blocked[id] = true
		}
	}
	stamp := func(v config.Value) string {
		text, _ := s.localStamp(v, "2006-01-02 15:04:05")
		return text
	}
	for _, app := range catalog.Apps {
		statsV, _ := apps.Get(app.ID)
		stats := config.NewMap()
		if config.Truthy(statsV) {
			m, ok := statsV.(*config.Map)
			if !ok {
				return nil, errInternal
			}
			stats = m
		}
		clientsV := field(stats, "clients")
		clientMap := config.NewMap()
		if config.Truthy(clientsV) {
			m, ok := clientsV.(*config.Map)
			if !ok {
				return nil, errInternal
			}
			clientMap = m
		}
		var clients []appClient
		for i, k := range clientMap.Keys() {
			row, ok := clientMap.Values()[i].(*config.Map)
			if !ok {
				return nil, errInternal
			}
			hits := pyGet(row, "hits_24h", pyInt(0))
			sources, err := pyStrList(pyGet(row, "sources", []config.Value{}))
			if err != nil {
				return nil, err
			}
			c := appClient{IP: pyStr(k), Hits: pyStr(hits), LastSeen: stamp(field(row, "last_seen")),
				Active: config.Truthy(field(row, "active")), Sources: strings.Join(sources, ", ")}
			if ip, ok := k.(string); ok {
				c.Label = labels[ip]
			}
			if c.hits, err = sortNumber(hits); err != nil {
				return nil, err
			}
			clients = append(clients, c)
		}
		sort.SliceStable(clients, func(i, j int) bool { return -clients[i].hits < -clients[j].hits })
		hits, active := pyGet(stats, "hits_24h", pyInt(0)), pyGet(stats, "active_clients", pyInt(0))
		r := appRow{ID: app.ID, Name: app.Name, Category: app.Category, Names: pyStr(pyInt(int64(len(app.Domains) + len(app.Exact)))),
			Hits: pyStr(hits), ActiveClients: pyStr(active), LastSeen: stamp(field(stats, "last_seen")),
			Clients: clients, Blocked: blocked[app.ID]}
		if r.hits, err = sortNumber(hits); err != nil {
			return nil, err
		}
		if r.active, err = sortNumber(active); err != nil {
			return nil, err
		}
		d.Rows = append(d.Rows, r)
	}
	sort.SliceStable(d.Rows, func(i, j int) bool {
		a, b := d.Rows[i], d.Rows[j]
		if a.active != b.active {
			return -a.active < -b.active
		}
		if a.hits != b.hits {
			return -a.hits < -b.hits
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.Name < b.Name
	})
	d.Enabled = config.Truthy(pyGet(section, "enabled", false))
	d.ObserveSNI = config.Truthy(pyGet(section, "observe_sni", false))
	d.BlockViaXDP = config.Truthy(pyGet(section, "block_via_xdp", false))
	if d.Prerequisites, err = appPrerequisites(raw); err != nil {
		return nil, err
	}
	d.DaemonActive = s.daemonActive("fr-appid.service")
	d.UsageGenerated = stamp(generated)
	d.Source, d.License, d.Generated = catalog.Source, catalog.License, catalog.Generated
	d.Ref = catalog.Ref
	if len(d.Ref) > 12 {
		d.Ref = d.Ref[:12]
	}
	return s.render(q, "apps", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveAppSettings(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled, observe, viaXDP bool
	if err = q.fields(func(p *formParams) {
		enabled, observe, viaXDP = p.boolOr("enabled", false), p.boolOr("observe_sni", false),
			p.boolOr("block_via_xdp", false)
	}); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "app_control")
	if err != nil {
		return nil, err
	}
	blocked, err := pyIter(field(previous, "blocked_apps"))
	if err != nil {
		return nil, err
	}
	raw.Set("app_control", cmdMap("enabled", enabled, "observe_sni", observe, "block_via_xdp", viaXDP,
		"blocked_apps", append([]config.Value{}, blocked...)))
	return s.saved(raw, "/apps", "Application settings saved -- click Apply on the dashboard to load them")
}

func (s *Server) saveBlockedApps(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var chosen []string
	if err = q.fields(func(p *formParams) { chosen = p.list("blocked_apps") }); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "app_control")
	if err != nil {
		return nil, err
	}
	section := copyMap(previous)
	catalog, err := appid.Load()
	if err != nil {
		return nil, err
	}
	// Keep the catalog's order so config.yaml diffs stay stable.
	set := map[string]bool{}
	for _, c := range chosen {
		set[c] = true
	}
	list := []config.Value{}
	known := map[string]bool{}
	for _, app := range catalog.Apps {
		known[app.ID] = true
		if set[app.ID] {
			list = append(list, app.ID)
		}
	}
	var rest []string
	for c := range set {
		if !known[c] {
			rest = append(rest, c)
		}
	}
	sort.Strings(rest)
	for _, c := range rest {
		list = append(list, c)
	}
	section.Set("blocked_apps", list)
	raw.Set("app_control", section)
	return s.saved(raw, "/apps", pyStr(pyInt(int64(len(list))))+" app(s) blocked -- click Apply on the dashboard to enforce")
}
