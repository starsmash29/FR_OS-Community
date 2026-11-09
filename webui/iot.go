package webui

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The IoT devices screen (1.x's routes/iot.py): the last scan's
// display-only inventory, who the kernel isolates now (through the
// apply-helper), a scan on demand (run by the apply-helper as the sensor
// account, never in this process), and trust / isolate / clear, which
// save the config and re-apply the isolation decision right away.

var iotActions = []string{"trust", "isolate", "clear"}

var iotMACRE = regexp.MustCompile(`\A(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\z`)

// iotNormalizeMAC is frfw.iot.oui.normalize_mac.
func iotNormalizeMAC(v config.Value) (string, bool) {
	text, ok := v.(string)
	if !ok {
		return "", false
	}
	mac := strings.ReplaceAll(config.PyLower(config.PyStrip(text)), "-", ":")
	return mac, iotMACRE.MatchString(mac)
}

// pyEq is Python's == for the scalar values these screens compare.
func pyEq(a, b config.Value) bool {
	switch x := a.(type) {
	case string:
		y, ok := b.(string)
		return ok && x == y
	case *big.Int:
		y, ok := b.(*big.Int)
		return ok && x.Cmp(y) == 0
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	}
	return false
}

func pyIn(v config.Value, list []config.Value) bool {
	for _, item := range list {
		if pyEq(v, item) {
			return true
		}
	}
	return false
}

type iotDevice struct {
	MAC, IP, Hostname, Vendor, Services, Category, Score, Reasons string
	LiveIsolated, Trusted, ManuallyIsolated                       bool
}

type iotZone struct {
	Name     string
	Selected bool
}

type iotData struct {
	ConfigError       string
	Enabled           bool
	Zones             []iotZone
	AutoIsolate       bool
	InternetOnly      bool
	Block             bool
	Devices           []iotDevice
	ScannedAt         string
	ScanMessages      string
	LiveIsolated      string
	HasLiveIsolated   bool
	IsolationError    string
	HasIsolationError bool
}

var iotCategoryOrder = map[string]int{"iot": 0, "unknown": 1, "general": 2}

func (s *Server) showIoT(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "iot")
	if err != nil {
		return nil, err
	}
	d := &iotData{ConfigError: configError(raw), Enabled: config.Truthy(pyGet(section, "enabled", false))}
	var live []config.Value
	if d.Enabled {
		status, err := s.helper.IoTIsolationStatus()
		var he *HelperError
		switch {
		case errors.As(err, &he):
			d.HasIsolationError, d.IsolationError = he.Msg != "", he.Msg
		case err != nil:
			return nil, err
		case config.Truthy(field(status, "ok")):
			if live, err = pyIter(field(status, "isolated")); err != nil {
				return nil, err
			}
		default:
			msg := field(status, "message")
			d.HasIsolationError, d.IsolationError = config.Truthy(msg), pyStr(msg)
		}
	}
	inv, err := s.inventory()
	if err != nil {
		return nil, err
	}
	if inv == nil {
		inv = config.NewMap()
	}
	devices, err := s.inventoryDevices()
	if err != nil {
		return nil, err
	}
	type keyed struct {
		order int
		ip    string
		m     *config.Map
	}
	var list []keyed
	for _, m := range devices {
		k := keyed{order: 3, m: m}
		if c, ok := field(m, "category").(string); ok {
			if o, known := iotCategoryOrder[c]; known {
				k.order = o
			}
		}
		ip := field(m, "ip")
		if config.Truthy(ip) {
			text, ok := ip.(string)
			if !ok {
				return nil, errInternal // comparing it with the others' strings raises
			}
			k.ip = text
		}
		list = append(list, k)
	}
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].order != list[j].order {
			return list[i].order < list[j].order
		}
		return list[i].ip < list[j].ip
	})
	trusted, err := pyIter(field(section, "trusted_macs"))
	if err != nil {
		return nil, err
	}
	isolated, err := pyIter(field(section, "isolated_macs"))
	if err != nil {
		return nil, err
	}
	for _, k := range list {
		m := k.m
		mac, macDefined := m.Get("mac")
		dev := iotDevice{MAC: jinjaText(m, "mac"), IP: jinjaOr(m, "ip", "-"), Vendor: jinjaOr(m, "vendor", "-"),
			Category: jinjaText(m, "category"), Score: jinjaText(m, "score"), Services: "-",
			LiveIsolated: pyIn(mac, live)}
		if v, ok := m.Get("hostname"); ok && config.Truthy(v) {
			dev.Hostname = pyStr(v)
		}
		if v, ok := m.Get("services"); ok && config.Truthy(v) {
			if dev.Services, err = jinjaJoin(v, ", "); err != nil {
				return nil, err
			}
		}
		if v, ok := m.Get("reasons"); ok {
			if dev.Reasons, err = jinjaJoin(v, "; "); err != nil {
				return nil, err
			}
		}
		if macDefined {
			dev.Trusted, dev.ManuallyIsolated = pyIn(mac, trusted), pyIn(mac, isolated)
		}
		d.Devices = append(d.Devices, dev)
	}
	selected, err := pyIter(field(section, "zones"))
	if err != nil {
		return nil, err
	}
	zones, err := sortedZoneKeys(raw)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		d.Zones = append(d.Zones, iotZone{z, pyIn(z, selected)})
	}
	d.AutoIsolate = config.Truthy(pyGet(section, "auto_isolate", false))
	mode := pyGet(section, "isolation_mode", "internet_only")
	d.InternetOnly, d.Block = strEq(mode, "internet_only"), strEq(mode, "block")
	if text, ok := s.localStamp(field(inv, "scanned_at"), "2006-01-02 15:04:05"); ok {
		d.ScannedAt = text
	}
	if msgs, ok := inv.Get("messages"); ok && config.Truthy(msgs) {
		if d.ScanMessages, err = jinjaJoin(msgs, "; "); err != nil {
			return nil, err
		}
	}
	if len(live) > 0 {
		d.HasLiveIsolated = true
		if d.LiveIsolated, err = jinjaJoin(live, ", "); err != nil {
			return nil, err
		}
	}
	return s.render(q, "iot", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveIoTSettings(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled, auto bool
	var zones []string
	var mode string
	if err = q.fields(func(p *formParams) {
		enabled, zones = p.boolOr("enabled", false), p.list("zones")
		auto, mode = p.boolOr("auto_isolate", false), p.strOr("isolation_mode", "internet_only")
	}); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "iot")
	if err != nil {
		return nil, err
	}
	trusted, err := pyIter(field(previous, "trusted_macs"))
	if err != nil {
		return nil, err
	}
	isolated, err := pyIter(field(previous, "isolated_macs"))
	if err != nil {
		return nil, err
	}
	raw.Set("iot", cmdMap("enabled", enabled, "zones", zones, "auto_isolate", auto, "isolation_mode", mode,
		"trusted_macs", append([]config.Value{}, trusted...), "isolated_macs", append([]config.Value{}, isolated...)))
	return s.saved(raw, "/iot", "IoT settings saved -- click Apply on the dashboard to load the isolation rules")
}

func (s *Server) scanIoT(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return errorRedirect("/iot", "Config does not pass validation: "+err.Error()), nil
	}
	if !cfg.Iot.Enabled {
		return errorRedirect("/iot", "IoT discovery is disabled -- enable it and save first"), nil
	}
	response, err := s.helper.IoTScan()
	var he *HelperError
	if errors.As(err, &he) {
		return errorRedirect("/iot", "Scan failed: "+he.Msg), nil
	} else if err != nil {
		return nil, err
	}
	if !config.Truthy(field(response, "ok")) {
		return errorRedirect("/iot", "Scan failed: "+pyStr(field(response, "message"))), nil
	}
	inv, err := s.inventory()
	if err != nil {
		return nil, err
	}
	var msgs config.Value
	if inv != nil {
		msgs = field(inv, "messages")
	}
	if !config.Truthy(msgs) {
		msgs = []config.Value{pyGet(response, "message", "")}
	}
	list, err := pyStrList(msgs)
	if err != nil {
		return nil, err
	}
	summary := strings.Join(list, "; ")
	for _, m := range list {
		if strings.HasPrefix(m, "error:") {
			return errorRedirect("/iot", summary), nil
		}
	}
	return successRedirect("/iot", summary), nil
}

// macsWithout is `[m for m in (v or []) if m.lower() != mac]`.
func macsWithout(v config.Value, mac string) ([]config.Value, error) {
	items, err := pyStrList(v)
	if err != nil {
		return nil, err
	}
	out := []config.Value{}
	for _, m := range items {
		if config.PyLower(m) != mac {
			out = append(out, m)
		}
	}
	return out, nil
}

// iotDecision is frfw.iot.scanner.resync_from_inventory's list:
// decide_isolation over the last scan's classifications.
func (s *Server) iotDecision(cfg *config.Config) ([]string, error) {
	devices, err := s.inventoryDevices()
	if err != nil {
		return nil, err
	}
	trusted := map[string]bool{}
	for _, m := range cfg.Iot.TrustedMacs {
		trusted[m] = true
	}
	isolated := map[string]bool{}
	for _, m := range cfg.Iot.IsolatedMacs {
		isolated[m] = true
	}
	for _, d := range devices {
		mac, ok := iotNormalizeMAC(pyGet(d, "mac", ""))
		if !ok {
			continue
		}
		if cfg.Iot.AutoIsolate && pyStr(field(d, "category")) == "iot" {
			isolated[mac] = true
		}
	}
	out := []string{}
	for m := range isolated {
		if !trusted[m] {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Server) iotDeviceAction(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var mac, action string
	if err = q.fields(func(p *formParams) { mac, action = p.str("mac"), p.str("action") }); err != nil {
		return nil, err
	}
	known := false
	for _, a := range iotActions {
		known = known || a == action
	}
	if !known {
		return errorRedirect("/iot", fmt.Sprintf("unknown action %s", config.Repr(action))), nil
	}
	mac = config.PyLower(pyStripped(mac))
	previous, err := getMapOr(raw, "iot")
	if err != nil {
		return nil, err
	}
	section := copyMap(previous)
	trusted, err := macsWithout(field(section, "trusted_macs"), mac)
	if err != nil {
		return nil, err
	}
	isolated, err := macsWithout(field(section, "isolated_macs"), mac)
	if err != nil {
		return nil, err
	}
	switch action {
	case "trust":
		trusted = append(trusted, mac)
	case "isolate":
		isolated = append(isolated, mac)
	}
	section.Set("trusted_macs", trusted)
	section.Set("isolated_macs", isolated)
	raw.Set("iot", section)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/iot", message), nil
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !cfg.Iot.Enabled {
		return successRedirect("/iot", fmt.Sprintf("%s: saved (%s)", mac, action)), nil
	}
	macs, err := s.iotDecision(cfg)
	if err != nil {
		return nil, err
	}
	response, err := s.helper.IoTSyncIsolation(macs)
	var he *HelperError
	if errors.As(err, &he) {
		return errorRedirect("/iot", fmt.Sprintf("%s: saved, but isolation not re-applied: %s", mac, he.Msg)), nil
	} else if err != nil {
		return nil, err
	}
	if !config.Truthy(field(response, "ok")) {
		return errorRedirect("/iot", fmt.Sprintf("%s: saved, but isolation not re-applied: %s", mac,
			pyStr(field(response, "message")))), nil
	}
	return successRedirect("/iot", fmt.Sprintf("%s: %s saved; %s device(s) now isolated", mac, action,
		pyStr(pyGet(response, "count", pyInt(0))))), nil
}
