package webui

import (
	"cmp"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// The router's attack surface (security-lessons I3, 1.x's frfw.surface):
// what listens, from the apply-helper's listening_sockets, and from
// which zone the input chain lets a new connection reach it -- worked
// out from the config in the input chain's order: the ad-block
// resolver's DNS accept, the management drop, the admin's rules to
// "self", then the chain's policy drop.

const (
	surfaceOpen       = "open"
	surfaceRestricted = "restricted"
	surfaceClosed     = "closed"
)

// The management ports (frfw.management).
const (
	sshPort   = 22
	webUIPort = 443
)

type listener struct {
	Proto, Address string
	Port           int
	Device         string // "" when not bound to one interface
	Process        string // "" when ss couldn't name it
	addr           netip.Addr
}

func (l listener) family() int {
	if l.addr.Is4() {
		return 4
	}
	return 6
}

type verdict struct {
	State, Why string
	// LinkLocalOnly: only from a link-local address, the zone's own
	// link, never the internet.
	LinkLocalOnly bool
}

type surfaceRow struct {
	Listener listener
	Zones    map[string]verdict
	Internet bool
	// Needed is what in the config needs the socket (K7), "" for nothing.
	Needed string
}

func (r *surfaceRow) reachable() bool {
	for _, v := range r.Zones {
		if v.State != surfaceClosed {
			return true
		}
	}
	return false
}

// unneeded: reachable from some zone, and nothing FR_OS runs needs it.
func (r *surfaceRow) unneeded() bool { return r.reachable() && r.Needed == "" }

// listenersOf reads the helper's reply as frfw.surface.Listener(**l)
// would; a listener 1.x's dataclass refuses fails the page.
func listenersOf(list config.Value) ([]listener, error) {
	items, ok := list.([]config.Value)
	if !ok {
		return nil, errInternal
	}
	var out []listener
	for _, item := range items {
		m, ok := item.(*config.Map)
		if !ok {
			return nil, errInternal
		}
		var l listener
		proto, _ := m.Get("proto")
		address, _ := m.Get("address")
		port, _ := m.Get("port")
		var okP, okA bool
		l.Proto, okP = proto.(string)
		l.Address, okA = address.(string)
		n, isInt := port.(*big.Int)
		if !okP || !okA || !isInt || !n.IsInt64() || n.Int64() < 0 || n.Int64() > 65535 {
			return nil, errInternal
		}
		l.Port = int(n.Int64())
		if d, _ := m.Get("device"); d != nil {
			s, ok := d.(string)
			if !ok {
				return nil, errInternal
			}
			l.Device = s
		}
		if pr, _ := m.Get("process"); pr != nil {
			s, ok := pr.(string)
			if !ok {
				return nil, errInternal
			}
			l.Process = s
		}
		a, err := netip.ParseAddr(l.Address)
		if err != nil {
			return nil, errInternal
		}
		l.addr = a
		out = append(out, l)
	}
	return out, nil
}

// neededBy is why this socket is expected on an FR_OS router with this
// config (security-lessons K7), or "": a service nothing here asked for.
func neededBy(c *config.Config, l listener) string {
	if l.addr.IsLoopback() {
		return "local only"
	}
	switch {
	case l.Proto == "tcp" && l.Port == webUIPort:
		return "the webUI"
	case l.Proto == "tcp" && l.Port == sshPort:
		return "SSH (runs only while someone has a key)"
	case l.Proto == "udp" && l.Port == 68:
		return "the WAN's DHCP client"
	case l.Proto == "udp" && l.Port == 546 && c.IPv6.Enabled:
		return "IPv6 on the WAN (ipv6)"
	case l.Port == 53 && c.Adblocker.Enabled:
		return "the DNS filter (adblocker)"
	case l.Proto == "udp" && l.Port == 67 && c.Dhcp.Zones.Len() > 0:
		return "the DHCP server (dhcp)"
	case l.Proto == "udp" && (l.Port == 5353 || l.Port == nft.IotMDNSReplyPort) && c.Iot.Enabled:
		return "the IoT scan (iot)"
	case l.Proto == "udp" && l.Port == c.Wireguard.ListenPort && c.Wireguard.Enabled:
		return "the WireGuard VPN (wireguard)"
	}
	return ""
}

func portMatches(spec string, port int) bool {
	lo, hi := portRange(spec)
	return lo <= port && port <= hi
}

func ruleMatches(r *config.Rule, zone, proto string, port, family int) bool {
	if r.FromZone != "" && r.FromZone != zone {
		return false
	}
	if r.Proto != config.ProtoAny && string(r.Proto) != proto {
		return false
	}
	if r.DstPort != "" && !portMatches(r.DstPort, port) {
		return false
	}
	return r.Families()[family]
}

func ruleConditions(r *config.Rule) []string {
	var out []string
	if len(r.SrcAddress) > 0 {
		out = append(out, "from "+strings.Join(r.SrcAddress, ", "))
	}
	if r.SrcMac != "" {
		out = append(out, "from device "+r.SrcMac)
	}
	if r.RequireZtna {
		out = append(out, "ZTNA-signed-in clients")
	}
	if len(r.DstAddress) > 0 {
		out = append(out, "to "+strings.Join(r.DstAddress, ", "))
	}
	if r.Schedule != nil {
		out = append(out, "on a schedule")
	}
	return out
}

func isolatedDNSDHCP(proto string, port int) bool {
	return (proto == "udp" && (port == 53 || port == 67)) || (proto == "tcp" && port == 53)
}

// inputVerdict is what the input chain does with a new connection from
// zone to proto/port on the router, step by step in the builder's order.
func inputVerdict(c *config.Config, zone, proto string, port, family int) verdict {
	v := chainVerdict(c, zone, proto, port, family)
	// The isolated-IoT accepts come first in the chain and aren't tied to
	// a zone: whatever else happens, those devices still get DNS and DHCP.
	if v.State == surfaceClosed && c.Iot.Enabled && isolatedDNSDHCP(proto, port) {
		return verdict{State: surfaceRestricted, Why: "only isolated IoT devices (DNS/DHCP)"}
	}
	return v
}

// ipv6Verdict is the input chain's answer for a socket bound to an IPv6
// address (not the wildcard, which takes IPv4 too): IPv6 goes through
// the builder's IPv6 input chain ahead of the admin's rules.
func ipv6Verdict(c *config.Config, zone, proto string, port int) verdict {
	if c.Iot.Enabled && isolatedDNSDHCP(proto, port) {
		return verdict{State: surfaceRestricted, Why: "only isolated IoT devices (DNS/DHCP)"}
	}
	if !c.IPv6.Enabled {
		return verdict{State: surfaceClosed, Why: "IPv6 is off (ipv6.enabled)"}
	}
	internet := c.InternetFacingZones()
	if proto == "udp" && port == 546 && internet[zone] {
		return verdict{surfaceRestricted, "only DHCPv6 replies from the provider's link-local address", true}
	}
	ipv6Zone := slices.ContainsFunc(c.LanDevices(), func(zd config.ZoneDevice) bool { return zd.Zone == zone })
	if port == 53 && (proto == "tcp" || proto == "udp") && ipv6Zone && slices.Contains(c.DNSResolverZones(), zone) {
		return verdict{State: surfaceOpen, Why: "the ad-block DNS resolver serves this zone over IPv6"}
	}
	if c.Wireguard.Enabled && proto == "udp" && port == c.Wireguard.ListenPort && internet[zone] {
		return verdict{State: surfaceOpen, Why: "the WireGuard VPN (answers known keys only)"}
	}
	if proto == "tcp" && (port == sshPort || port == webUIPort) && c.Management.IPv6 && ipv6Zone &&
		c.ManagementZones()[zone] {
		return chainVerdict(c, zone, proto, port, 6)
	}
	return verdict{State: surfaceClosed, Why: "over IPv6 the router answers only what the WAN needs, DNS on the LAN, and " +
		"the webUI and SSH with management.ipv6 (ROADMAP FND-1a/1c)"}
}

func chainVerdict(c *config.Config, zone, proto string, port, family int) verdict {
	if c.Iot.Enabled && slices.Contains(c.Iot.Zones, zone) && proto == "udp" && port == nft.IotMDNSReplyPort {
		return verdict{State: surfaceRestricted, Why: "only mDNS replies from port 5353 (IoT scan)"}
	}
	var cut, rest []*config.Rule
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.ToZone != config.SelfZone {
			continue
		}
		if r.Schedule != nil && r.Schedule.CutEstablished {
			cut = append(cut, r)
		} else {
			rest = append(rest, r)
		}
	}
	var restrictedBy []string
	restricted := func() verdict {
		return verdict{State: surfaceRestricted, Why: strings.Join(restrictedBy, "; ")}
	}
	decide := func(rules []*config.Rule) *verdict {
		for _, r := range rules {
			if !ruleMatches(r, zone, proto, port, family) {
				continue
			}
			if conditions := ruleConditions(r); len(conditions) > 0 {
				if r.Action == config.Accept {
					restrictedBy = append(restrictedBy,
						fmt.Sprintf("rule %s: %s", config.Repr(r.Name), strings.Join(conditions, ", ")))
				}
				continue // a conditional drop leaves the rest to the next rules
			}
			if r.Action == config.Accept {
				return &verdict{State: surfaceOpen, Why: "rule " + config.Repr(r.Name)}
			}
			if len(restrictedBy) > 0 {
				v := restricted()
				return &v
			}
			return &verdict{State: surfaceClosed, Why: fmt.Sprintf("rule %s (%s)", config.Repr(r.Name), r.Action)}
		}
		return nil
	}
	if v := decide(cut); v != nil {
		return *v
	}
	if slices.Contains(c.DNSResolverZones(), zone) && port == 53 {
		return verdict{State: surfaceOpen, Why: "the ad-block DNS resolver serves this zone"}
	}
	if proto == "tcp" && (port == sshPort || port == webUIPort) && c.Zones.Has(zone) && !c.ManagementZones()[zone] {
		if len(restrictedBy) > 0 {
			return restricted()
		}
		return verdict{State: surfaceClosed, Why: "management is off this zone (management.zones)"}
	}
	if v := decide(rest); v != nil {
		return *v
	}
	if len(restrictedBy) > 0 {
		return restricted()
	}
	return verdict{State: surfaceClosed, Why: "no rule allows it (policy drop)"}
}

// reachableZones are the zones whose traffic can reach the socket at
// all, before the firewall: by what it is bound to.
func reachableZones(l listener, c *config.Config, addresses map[string][]string) []string {
	if l.addr.IsLoopback() {
		return nil
	}
	byDevice := map[string]string{}
	for _, i := range c.Interfaces.Values() {
		byDevice[i.Device] = i.Zone
	}
	if l.Device != "" {
		if z := byDevice[l.Device]; z != "" {
			return []string{z}
		}
		return nil
	}
	zones := map[string]bool{}
	if l.addr.IsUnspecified() {
		for _, z := range byDevice {
			if c.Zones.Has(z) {
				zones[z] = true
			}
		}
	} else {
		for device, addrs := range addresses {
			if z, ok := byDevice[device]; ok && slices.Contains(addrs, l.Address) {
				zones[z] = true
			}
		}
		for _, i := range c.Interfaces.Values() { // a static address not up yet
			if i.Address != "" && netip.MustParsePrefix(i.Address).Addr().String() == l.Address {
				zones[i.Zone] = true
			}
		}
	}
	return slices.Sorted(func(yield func(string) bool) {
		for z := range zones {
			if !yield(z) {
				return
			}
		}
	})
}

// surfaceRows is frfw.surface.surface: one row per listener, the ones
// reachable from the internet first.
func surfaceRows(c *config.Config, listeners []listener, addresses map[string][]string) []*surfaceRow {
	internet := c.InternetFacingZones()
	var rows []*surfaceRow
	for _, l := range listeners {
		row := &surfaceRow{Listener: l, Zones: map[string]verdict{}}
		ipv6Only := l.family() == 6 && !l.addr.IsUnspecified()
		for _, zone := range reachableZones(l, c, addresses) {
			if ipv6Only {
				row.Zones[zone] = ipv6Verdict(c, zone, l.Proto, l.Port)
			} else {
				row.Zones[zone] = inputVerdict(c, zone, l.Proto, l.Port, l.family())
			}
		}
		for z, v := range row.Zones {
			if internet[z] && v.State != surfaceClosed && !v.LinkLocalOnly {
				row.Internet = true
			}
		}
		row.Needed = neededBy(c, l)
		rows = append(rows, row)
	}
	b := func(x bool) int {
		if x {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(rows, func(x, y *surfaceRow) int {
		return cmp.Or(
			cmp.Compare(b(!x.Internet), b(!y.Internet)),
			cmp.Compare(b(!x.reachable()), b(!y.reachable())),
			cmp.Compare(x.Listener.Port, y.Listener.Port),
			strings.Compare(x.Listener.Proto, y.Listener.Proto))
	})
	return rows
}

// addressesOf reads the helper's interface -> addresses map.
func addressesOf(v config.Value) (map[string][]string, error) {
	out := map[string][]string{}
	if !config.Truthy(v) {
		return out, nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, errInternal
	}
	for i, key := range m.Keys() {
		k, _ := key.(string)
		items, ok := m.Values()[i].([]config.Value)
		if !ok {
			return nil, errInternal
		}
		for _, a := range items {
			s, _ := a.(string)
			out[k] = append(out[k], s)
		}
	}
	return out, nil
}
