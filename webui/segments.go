package webui

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The network segments screen (security-lessons K4, 1.x's frfw.segments
// and routes/segments.py): an IoT and a guest segment in one step, each
// a VLAN on the LAN port with its own subnet, DHCP and zone, and rules
// that let it reach the internet and nothing else. First-run setup
// brings the admin here; it stays reachable from the sidebar.

type segmentSpec struct {
	Name    string
	VLAN    int
	Address string
	Label   string
}

// segmentSpecs is frfw.segments.SEGMENTS, in its order.
var segmentSpecs = []segmentSpec{
	{"iot", 30, "192.168.30.1/24", "IoT devices"},
	{"guest", 40, "192.168.40.1/24", "Guests"},
}

var publicDNS = []string{"1.1.1.1", "9.9.9.9"}

// segmentError is frfw.segments.SegmentError: its message goes back to
// the screen.
type segmentError struct{ msg string }

func (e *segmentError) Error() string { return e.msg }

// lanDevice is segments.lan_device: the device of the "lan" interface.
func lanDevice(raw *config.Map) (string, error) {
	ifaces, err := getMapOr(raw, "interfaces")
	if err != nil {
		return "", err
	}
	lan, _ := ifaces.Get("lan")
	m, ok := lan.(*config.Map)
	if !ok || !config.Truthy(field(m, "device")) {
		return "", &segmentError{"No 'lan' interface to put the segments on"}
	}
	return pyStr(field(m, "device")), nil
}

// hasKey is Python's `name in container` for a raw config section.
func hasKey(v config.Value, name string) (bool, error) {
	switch x := v.(type) {
	case *config.Map:
		return x.Has(name), nil
	case []config.Value:
		for _, item := range x {
			if strEq(item, name) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, errInternal
}

func setdefault(m *config.Map, key string, def config.Value) config.Value {
	if v, ok := m.Get(key); ok {
		return v
	}
	m.Set(key, def)
	return def
}

// addSegments is segments.add_segments: the chosen segments are added
// to raw (cfg is raw parsed, before the change); the ones already there
// are left as they are. It returns the names added.
func addSegments(raw *config.Map, cfg *config.Config, names []string) ([]string, error) {
	parent, err := lanDevice(raw)
	if err != nil {
		return nil, err
	}
	zones, err := setdefaultMap(raw, "zones")
	if err != nil {
		return nil, err
	}
	interfaces, err := setdefaultMap(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	rulesV := setdefault(raw, "rules", []config.Value{})
	rules, ok := rulesV.([]config.Value)
	if !ok {
		return nil, errInternal
	}
	ruleNames := map[string]bool{}
	for _, r := range rules {
		if m, ok := r.(*config.Map); ok {
			if n, ok := field(m, "name").(string); ok {
				ruleNames[n] = true
			}
		}
	}
	var wan []string
	for z := range cfg.InternetFacingZones() {
		wan = append(wan, z)
	}
	sort.Strings(wan)
	var added []string
	for _, name := range names {
		var spec *segmentSpec
		for i := range segmentSpecs {
			if segmentSpecs[i].Name == name {
				spec = &segmentSpecs[i]
			}
		}
		if spec == nil {
			return nil, &segmentError{fmt.Sprintf("unknown segment %s", config.Repr(name))}
		}
		if zones.Has(name) || interfaces.Has(name) {
			continue
		}
		net := netip.MustParsePrefix(spec.Address).Masked()
		for _, other := range cfg.Interfaces.Values() {
			if other.Address == "" {
				continue
			}
			p, err := netip.ParsePrefix(other.Address)
			if err != nil || !p.Addr().Is4() {
				return nil, errInternal // IPv4Interface() raises
			}
			if p.Masked().Overlaps(net) {
				return nil, &segmentError{fmt.Sprintf("%s is already used by interface %s", net, config.Repr(other.Name))}
			}
		}
		management, err := setdefaultMap(raw, "management")
		if err != nil {
			return nil, err
		}
		if !config.Truthy(field(management, "zones")) && !config.Truthy(field(management, "allow_wan")) {
			// Pin management to today's zones: the new segment isn't one.
			var pinned []string
			for z := range cfg.ManagementZones() {
				pinned = append(pinned, z)
			}
			sort.Strings(pinned)
			management.Set("zones", stringList(pinned))
		}
		device := fmt.Sprintf("%s.%d", parent, spec.VLAN)
		zones.Set(name, cmdMap("description", spec.Label))
		interfaces.Set(name, cmdMap("device", device, "zone", name, "address", spec.Address,
			"vlan", cmdMap("parent", parent, "id", spec.VLAN)))
		dhcp, err := setdefaultMap(raw, "dhcp")
		if err != nil {
			return nil, err
		}
		// hosts[99] and hosts[198] of a /24: .100 and .199.
		base := net.Addr().As4()
		start, end := base, base
		start[3], end[3] = 100, 199
		dhcp.Set(name, cmdMap("range_start", netip.AddrFrom4(start).String(),
			"range_end", netip.AddrFrom4(end).String(), "dns_servers", stringList(publicDNS)))
		for _, out := range wan {
			rule := name + "-to-" + out
			if !ruleNames[rule] {
				rules = append(rules, cmdMap("name", rule, "action", "accept", "from_zone", name, "to_zone", out))
			}
		}
		raw.Set("rules", rules)
		if name == "iot" {
			iot, err := setdefaultMap(raw, "iot")
			if err != nil {
				return nil, err
			}
			iot.Set("enabled", true)
			current, err := pyIter(field(iot, "zones"))
			if err != nil {
				return nil, err
			}
			set := map[string]bool{"iot": true}
			for _, z := range current {
				s, ok := z.(string)
				if !ok {
					return nil, errInternal // sorted() of mixed types raises
				}
				set[s] = true
			}
			var list []string
			for z := range set {
				list = append(list, z)
			}
			sort.Strings(list)
			iot.Set("zones", stringList(list))
			setdefault(iot, "auto_isolate", true)
			setdefault(iot, "isolation_mode", "internet_only")
		}
		added = append(added, name)
	}
	return added, nil
}

func stringList(items []string) []config.Value {
	out := make([]config.Value, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

type segmentRow struct {
	Name, Label, Address, Device string
	VLAN                         int
	Present                      bool
}

type segmentsData struct {
	Segments []segmentRow
	Parent   string
	FirstRun bool
}

func (s *Server) showSegments(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	zones, err := getMapOr(raw, "zones")
	if err != nil {
		return nil, err
	}
	parent, err := lanDevice(raw)
	var segErr *segmentError
	if errors.As(err, &segErr) {
		parent = ""
	} else if err != nil {
		return nil, err
	}
	d := &segmentsData{Parent: parent, FirstRun: q.queryGet("first_run") == "1"}
	for _, spec := range segmentSpecs {
		row := segmentRow{Name: spec.Name, Label: spec.Label, Address: spec.Address, VLAN: spec.VLAN,
			Present: zones.Has(spec.Name)}
		if parent != "" {
			row.Device = fmt.Sprintf("%s.%d", parent, spec.VLAN)
		}
		d.Segments = append(d.Segments, row)
	}
	return s.render(q, "segments", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) addSegmentsForm(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var chosen []string
	if err = q.fields(func(p *formParams) { chosen = p.list("segment") }); err != nil {
		return nil, err
	}
	if len(chosen) == 0 {
		return successRedirect("/", "No segments added -- you can add them later on the Segments screen"), nil
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return errorRedirect("/segments", err.Error()), nil
	}
	added, err := addSegments(raw, cfg, chosen)
	var segErr *segmentError
	if errors.As(err, &segErr) {
		return errorRedirect("/segments", segErr.msg), nil
	} else if err != nil {
		return nil, err
	}
	if len(added) == 0 {
		return successRedirect("/segments", "Those segments are already there"), nil
	}
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/segments", message), nil
	}
	return successRedirect("/segments", "Added: "+strings.Join(added, ", ")+" -- click Apply on the dashboard to load them"), nil
}
