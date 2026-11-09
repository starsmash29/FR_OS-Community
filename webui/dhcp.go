package webui

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The DHCP screen (1.x's routes/dhcp.py): a pool per zone, and its
// reservations.

type dhcpReservation struct {
	MAC, Address, Hostname string
}

type dhcpZone struct {
	Zone, InterfaceAddress string
	HasPool                bool // `if z.pool`
	RangeStart, RangeEnd   string
	DNSServers             string
	LeaseTime              string
	Reservations           []dhcpReservation
}

type dhcpData struct{ Zones []dhcpZone }

// eligibleZones is _eligible_zones: zone -> its interface, for zones
// with exactly one interface, which has an address (a pool's subnet and
// gateway come from it).
func eligibleZones(raw *config.Map) (map[string]*config.Map, error) {
	ifaces, err := getMapOr(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	byZone := map[string][]*config.Map{}
	for _, v := range ifaces.Values() {
		m, ok := v.(*config.Map)
		if !ok {
			return nil, errInternal
		}
		zone, ok := field(m, "zone").(string)
		if !ok {
			return nil, errInternal // sorting the zones needs one key type
		}
		byZone[zone] = append(byZone[zone], m)
	}
	out := map[string]*config.Map{}
	for zone, list := range byZone {
		if len(list) == 1 && config.Truthy(field(list[0], "address")) {
			out[zone] = list[0]
		}
	}
	return out, nil
}

// jinjaJoin is `{{ v|join(', ') }}`: the items of a list (a mapping's
// keys, a string's characters), each as str().
func jinjaJoin(v config.Value, sep string) (string, error) {
	var items []config.Value
	switch x := v.(type) {
	case []config.Value:
		items = x
	case *config.Map:
		items = x.Keys()
	case string:
		for _, r := range x {
			items = append(items, string(r))
		}
	default:
		return "", errInternal
	}
	parts := make([]string, len(items))
	for i, item := range items {
		parts[i] = pyStr(item)
	}
	return strings.Join(parts, sep), nil
}

func (s *Server) showDHCP(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	eligible, err := eligibleZones(raw)
	if err != nil {
		return nil, err
	}
	dhcp, err := getMapOr(raw, "dhcp")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(eligible))
	for zone := range eligible {
		names = append(names, zone)
	}
	sort.Strings(names)
	d := &dhcpData{}
	for _, zone := range names {
		z := dhcpZone{Zone: zone, InterfaceAddress: pyStr(field(eligible[zone], "address"))}
		pool, _ := dhcp.Get(zone)
		if config.Truthy(pool) {
			z.HasPool = true
			z.RangeStart, z.RangeEnd = jinjaText(pool, "range_start"), jinjaText(pool, "range_end")
			if servers, ok := jinjaGet(pool, "dns_servers"); ok {
				if z.DNSServers, err = jinjaJoin(servers, ", "); err != nil {
					return nil, err
				}
			} else {
				z.DNSServers = "" // an undefined value joins to nothing
			}
			z.LeaseTime = jinjaText(pool, "lease_time")
			reservations, _ := jinjaGet(pool, "reservations")
			items, err := pyIter(reservations)
			if err != nil {
				return nil, err
			}
			for _, r := range items {
				z.Reservations = append(z.Reservations, dhcpReservation{MAC: jinjaText(r, "mac"),
					Address: jinjaText(r, "address"), Hostname: jinjaOr(r, "hostname", "-")})
			}
		} else {
			z.LeaseTime = "3600"
		}
		d.Zones = append(d.Zones, z)
	}
	return s.render(q, "dhcp", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveDHCPPool(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	zone := q.params["zone"]
	var rangeStart, rangeEnd, dnsServers string
	var leaseTime *big.Int
	if err = q.fields(func(p *formParams) {
		rangeStart, rangeEnd, dnsServers = p.str("range_start"), p.str("range_end"), p.str("dns_servers")
		leaseTime = p.intOr("lease_time", pyInt(3600))
	}); err != nil {
		return nil, err
	}
	dhcp, err := setdefaultMap(raw, "dhcp")
	if err != nil {
		return nil, err
	}
	existing, err := getMapOr(dhcp, zone)
	if err != nil {
		return nil, err
	}
	reservations, ok := existing.Get("reservations")
	if !ok {
		reservations = []config.Value{}
	}
	servers := []config.Value{}
	for _, part := range strings.Split(dnsServers, ",") {
		if v := pyStripped(part); v != "" {
			servers = append(servers, v)
		}
	}
	dhcp.Set(zone, cmdMap("range_start", rangeStart, "range_end", rangeEnd, "dns_servers", servers,
		"lease_time", leaseTime, "reservations", reservations))
	return s.saved(raw, "/dhcp", fmt.Sprintf("DHCP pool for %s saved", config.Repr(zone)))
}

func (s *Server) deleteDHCPPool(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	zone := q.params["zone"]
	dhcp, err := getMapOr(raw, "dhcp")
	if err != nil {
		return nil, err
	}
	dhcp.Delete(zone)
	return s.saved(raw, "/dhcp", fmt.Sprintf("DHCP pool for %s removed", config.Repr(zone)))
}

// dhcpPool is (raw.get("dhcp") or {}).get(zone): nil when there is none
// (or it is None).
func dhcpPool(raw *config.Map, zone string) (config.Value, error) {
	dhcp, err := getMapOr(raw, "dhcp")
	if err != nil {
		return nil, err
	}
	pool, _ := dhcp.Get(zone)
	return pool, nil
}

func (s *Server) addReservation(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	zone := q.params["zone"]
	var mac, address, hostname string
	if err = q.fields(func(p *formParams) {
		mac, address, hostname = p.str("mac"), p.str("address"), p.strOr("hostname", "")
	}); err != nil {
		return nil, err
	}
	v, err := dhcpPool(raw, zone)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return errorRedirect("/dhcp", fmt.Sprintf("No DHCP pool configured for zone %s yet", config.Repr(zone))), nil
	}
	pool, ok := v.(*config.Map)
	if !ok {
		return nil, errInternal
	}
	reservations, err := getList(pool, "reservations", false)
	if err != nil {
		return nil, err
	}
	kept := []*config.Map{}
	for _, r := range reservations {
		if !strEq(field(r, "mac"), mac) {
			kept = append(kept, r)
		}
	}
	entry := cmdMap("mac", mac, "address", address)
	if h := pyStripped(hostname); h != "" {
		entry.Set("hostname", h)
	}
	// reservations[:] = ...: the list stays where it is in the pool.
	pool.Set("reservations", values(append(kept, entry)))
	return s.saved(raw, "/dhcp", fmt.Sprintf("Reservation for %s saved", config.Repr(mac)))
}

func (s *Server) deleteReservation(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	zone, mac := q.params["zone"], q.params["mac"]
	v, err := dhcpPool(raw, zone)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return errorRedirect("/dhcp", fmt.Sprintf("No DHCP pool configured for zone %s", config.Repr(zone))), nil
	}
	pool, ok := v.(*config.Map)
	if !ok {
		return nil, errInternal
	}
	reservations, err := getList(pool, "reservations", true)
	if err != nil {
		return nil, err
	}
	kept := []*config.Map{}
	for _, r := range reservations {
		if !strEq(field(r, "mac"), mac) {
			kept = append(kept, r)
		}
	}
	pool.Set("reservations", values(kept))
	return s.saved(raw, "/dhcp", "Reservation deleted")
}
