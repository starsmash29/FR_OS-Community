package webui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The interfaces screen (1.x's routes/interfaces.py): the configured
// interfaces, the ones the kernel has (frfw.netdetect, read from sysfs),
// and IPv6 from the provider (ROADMAP FND-1).

type detectedNIC struct {
	Name, Driver, MAC, Link string
}

// detectInterfaces is netdetect.list_interfaces(include_virtual=True):
// every entry of /sys/class/net, by name.
func (s *Server) detectInterfaces() ([]detectedNIC, error) {
	dir := s.env.Paths.at("/sys/class/net")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	sort.Strings(names)
	var out []detectedNIC
	for _, name := range names {
		nic := detectedNIC{Name: name, Driver: "?", MAC: "?", Link: "?"}
		read := func(file string) (string, bool, error) {
			text, ok, err := readOptional(filepath.Join(dir, name, file))
			return config.PyStrip(text), ok, err
		}
		if mac, ok, err := read("address"); err != nil {
			return nil, err
		} else if ok && mac != "" {
			nic.MAC = mac
		}
		// The driver is the name device/driver links to; a virtual
		// interface has none.
		if target, err := filepath.EvalSymlinks(filepath.Join(dir, name, "device", "driver")); err == nil {
			if driver := filepath.Base(target); driver != "" {
				nic.Driver = driver
			}
		}
		if carrier, ok, err := read("carrier"); err != nil {
			return nil, err
		} else if ok {
			nic.Link = "down"
			if carrier == "1" {
				nic.Link = "up"
			}
		}
		out = append(out, nic)
	}
	return out, nil
}

type ifaceView struct {
	Name, Device, Zone, Address string
	edit                        *config.Map
}

type ipv6Pair struct{ Term, Detail string }

type ipv6Pinhole struct {
	Name, Text string
}

type ipv6View struct {
	State, Summary string
	Shown          bool
	Addresses      []ipv6Pair // device, "address (source)"
	Routes         []ipv6Pair // device, gateway
	Prefixes       []string
	Lan            []ipv6Pair // "zone (device)", network
	Ula            []ipv6Pair // "zone (device)", address
	Pinholes       []ipv6Pinhole
}

type interfacesData struct {
	Interfaces  []ifaceView
	Edit        *ifaceView
	Detected    []detectedNIC
	IPv6Enabled bool
	IPv6        *ipv6View
}

// unpack is `for a, b, c in items`: each item must have exactly n parts.
func unpack(item config.Value, n int) ([]config.Value, error) {
	parts, err := pyIter(item)
	if err != nil || len(parts) != n {
		return nil, errInternal
	}
	return parts, nil
}

// ipv6StatusView is what the screen shows of the apply-helper's
// ipv6_status (reading it takes netlink, which the webUI lacks).
func ipv6StatusView(status *config.Map) (*ipv6View, error) {
	v := &ipv6View{State: jinjaText(status, "state"), Summary: jinjaText(status, "summary")}
	for _, key := range []string{"addresses", "prefixes", "default_routes", "lan", "ula", "pinholes"} {
		if x, ok := status.Get(key); ok && config.Truthy(x) {
			v.Shown = true
		}
	}
	list := func(key string, n int, each func([]config.Value)) error {
		items, err := pyIter(field(status, key))
		if err != nil {
			return err
		}
		for _, item := range items {
			parts := []config.Value{item}
			if n > 1 {
				if parts, err = unpack(item, n); err != nil {
					return err
				}
			}
			each(parts)
		}
		return nil
	}
	err := list("addresses", 3, func(p []config.Value) {
		v.Addresses = append(v.Addresses, ipv6Pair{pyStr(p[0]), pyStr(p[1]) + " (" + pyStr(p[2]) + ")"})
	})
	if err == nil {
		err = list("default_routes", 2, func(p []config.Value) {
			v.Routes = append(v.Routes, ipv6Pair{pyStr(p[0]), pyStr(p[1])})
		})
	}
	if err == nil {
		err = list("prefixes", 1, func(p []config.Value) { v.Prefixes = append(v.Prefixes, pyStr(p[0])) })
	}
	if err == nil {
		err = list("lan", 3, func(p []config.Value) {
			network := "no network yet"
			if config.Truthy(p[2]) {
				network = pyStr(p[2])
			}
			v.Lan = append(v.Lan, ipv6Pair{pyStr(p[0]) + " (" + pyStr(p[1]) + ")", network})
		})
	}
	if err == nil {
		err = list("ula", 3, func(p []config.Value) {
			v.Ula = append(v.Ula, ipv6Pair{pyStr(p[0]) + " (" + pyStr(p[1]) + ")", pyStr(p[2])})
		})
	}
	if err == nil {
		err = list("pinholes", 4, func(p []config.Value) {
			name, zone, what, targets := pyStr(p[0]), pyStr(p[1]), pyStr(p[2]), p[3]
			var text string
			switch {
			case targets == nil:
				text = what + ", off: zone " + zone + " has no IPv6"
			case config.Truthy(targets):
				items, ierr := pyIter(targets)
				if ierr != nil {
					err = ierr
					return
				}
				parts := make([]string, len(items))
				for i, t := range items {
					parts[i] = pyStr(t)
				}
				text = what + " to " + strings.Join(parts, ", ")
			default:
				text = what + " to no address in " + zone + " yet"
			}
			v.Pinholes = append(v.Pinholes, ipv6Pinhole{name, text})
		})
	}
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Server) listInterfaces(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	ifaces, err := getMapOr(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	d := &interfacesData{}
	type named struct {
		name string
		body *config.Map
	}
	var all []named
	for i, k := range ifaces.Keys() {
		name, ok := k.(string)
		body, isMap := ifaces.Values()[i].(*config.Map)
		if !ok || !isMap {
			return nil, errInternal // {"name": name, **body} needs a mapping; sorting needs one key type
		}
		all = append(all, named{name, body})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	editName, hasEdit := q.query.get("edit")
	for _, n := range all {
		// {"name": name, **body}: a "name" inside the body wins.
		entry := cmdMap("name", n.name)
		for i, k := range n.body.Keys() {
			entry.SetKey(k, n.body.Values()[i])
		}
		row := ifaceView{Name: jinjaText(entry, "name"), Device: jinjaText(entry, "device"),
			Zone: jinjaText(entry, "zone"), Address: jinjaOr(entry, "address", "-"), edit: entry}
		d.Interfaces = append(d.Interfaces, row)
		if hasEdit && d.Edit == nil && strEq(field(entry, "name"), editName) {
			e := ifaceView{Name: jinjaText(entry, "name"), Device: jinjaText(entry, "device"),
				Zone: jinjaText(entry, "zone"), Address: jinjaText(entry, "address")}
			d.Edit = &e
		}
	}
	if d.Detected, err = s.detectInterfaces(); err != nil {
		return nil, err
	}
	ipv6, err := getMapOr(raw, "ipv6")
	if err != nil {
		return nil, err
	}
	enabled, _ := ipv6.Get("enabled")
	d.IPv6Enabled = config.Truthy(enabled)
	status, err := s.helper.IPv6Status()
	if err != nil {
		return nil, err // a HelperError isn't the OSError 1.x catches
	}
	if ok, _ := status.Get("ok"); !config.Truthy(ok) {
		msg, _ := status.Get("message")
		if !config.Truthy(msg) {
			msg = "unknown"
		}
		status = cmdMap("state", "unknown", "summary", pyStr(msg))
	}
	if d.IPv6, err = ipv6StatusView(status); err != nil {
		return nil, err
	}
	return s.render(q, "interfaces", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveInterface(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var name, device, zone, address string
	if err = q.fields(func(p *formParams) {
		name, device, zone, address = p.str("name"), p.str("device"), p.str("zone"), p.strOr("address", "")
	}); err != nil {
		return nil, err
	}
	interfaces, err := setdefaultMap(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	zones, err := setdefaultMap(raw, "zones")
	if err != nil {
		return nil, err
	}
	entry := cmdMap("device", device, "zone", zone)
	if v := pyStripped(address); v != "" {
		entry.Set("address", v)
	}
	interfaces.Set(name, entry)
	if !zones.Has(zone) {
		zones.Set(zone, config.NewMap())
	}
	return s.saved(raw, "/interfaces", fmt.Sprintf("Interface %s saved", config.Repr(name)))
}

func (s *Server) deleteInterface(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	name := q.params["name"]
	interfaces, err := getMapOr(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	removed, _ := interfaces.Get(name)
	interfaces.Delete(name)
	if removed == nil {
		return errorRedirect("/interfaces", fmt.Sprintf("No such interface %s", config.Repr(name))), nil
	}
	// A zone left with no interfaces is always invalid: drop it too, so
	// deleting a zone's only interface just works; whatever still names
	// the zone fails the check below and nothing is saved.
	remaining := map[string]bool{}
	for _, v := range interfaces.Values() {
		m, ok := v.(*config.Map)
		if !ok || !m.Has("zone") {
			return nil, errInternal
		}
		if z, ok := field(m, "zone").(string); ok {
			remaining[z] = true
		}
	}
	gone, ok := removed.(*config.Map)
	if !ok || !gone.Has("zone") {
		return nil, errInternal
	}
	zones, err := getMapOr(raw, "zones")
	if err != nil {
		return nil, err
	}
	if z, ok := field(gone, "zone").(string); ok && !remaining[z] {
		zones.Delete(z)
	}
	return s.saved(raw, "/interfaces", fmt.Sprintf("Interface %s deleted", config.Repr(name)))
}

// saveIPv6 is the IPv6 switch (ROADMAP FND-1): only the switch, the rest
// of the ipv6 section (lan_zones) stays.
func (s *Server) saveIPv6(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	if err = q.fields(func(p *formParams) { enabled = p.boolOr("enabled", false) }); err != nil {
		return nil, err
	}
	old, err := getMapOr(raw, "ipv6")
	if err != nil {
		return nil, err
	}
	section := config.NewMap()
	for i, k := range old.Keys() {
		section.SetKey(k, old.Values()[i])
	}
	section.Set("enabled", enabled)
	raw.Set("ipv6", section)
	if !enabled && section.Len() == 1 {
		raw.Delete("ipv6")
	}
	state := "off"
	if enabled {
		state = "on"
	}
	return s.saved(raw, "/interfaces", "IPv6 "+state+" -- Apply on the dashboard to use it")
}
