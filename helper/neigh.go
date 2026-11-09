package helper

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// The router's neighbour table (`ip -j neigh`), read by root: which MAC
// a LAN host is at, so a jail, a quarantine or a ZTNA sign-in holds the
// device, not one address it picked itself (ROADMAP SEC-6, FND-1d, H3).
// Only ever an entry on a LAN device: through a gateway the table holds
// the gateway's MAC, and the provider's must never be held.

// neighTimeout is how long `ip neigh` may take (1.x's timeout=10).
const neighTimeout = 10 * time.Second

// usableNeighStates are the entries whose MAC is the host's
// (frfw.ids_quarantine; frfw.ztna also counts NOARP).
var usableNeighStates = map[string]bool{"REACHABLE": true, "STALE": true, "DELAY": true, "PROBE": true,
	"PERMANENT": true}

var ztnaNeighStates = map[string]bool{"REACHABLE": true, "STALE": true, "DELAY": true, "PROBE": true,
	"PERMANENT": true, "NOARP": true}

// validMACRE is frfw.validate's MAC: lower-case hex, six octets.
var validMACRE = regexp.MustCompile(`\A[0-9a-f]{2}(?::[0-9a-f]{2}){5}\z`)

// validMAC is frfw.validate.mac: a string, lower-cased, six octets.
func validMAC(v config.Value) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = config.PyLower(s)
	return s, validMACRE.MatchString(s)
}

// hashable is what Python asks of a value looked up in a set: a list or
// a dict is not one, and the lookup raises TypeError, which 1.x's request
// handler answers as an invalid request.
func hashable(v config.Value) error {
	switch v.(type) {
	case []config.Value, *config.Map:
		return invalidRequest(fmt.Sprintf("unhashable type: '%s'", pyTypeName(v)))
	}
	return nil
}

// inSet is `v in set` for a set of strings.
func inSet(v config.Value, set map[string]bool) (bool, error) {
	if err := hashable(v); err != nil {
		return false, err
	}
	s, ok := v.(string)
	return ok && set[s], nil
}

// stateSet is set(entry.get("state") or []): its strings (only a string
// can be one of the usable states).
func stateSet(v config.Value) (map[string]bool, error) {
	out := map[string]bool{}
	if !config.Truthy(v) {
		return out, nil
	}
	switch x := v.(type) {
	case string:
		for _, r := range x {
			out[string(r)] = true
		}
	case []config.Value:
		for _, e := range x {
			if err := hashable(e); err != nil {
				return nil, err
			}
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	case *config.Map:
		for _, k := range x.Keys() {
			if ks, ok := k.(string); ok {
				out[ks] = true
			}
		}
	default:
		return nil, invalidRequest(fmt.Sprintf("'%s' object is not iterable", pyTypeName(v)))
	}
	return out, nil
}

func anyIn(states, usable map[string]bool) bool {
	for s := range states {
		if usable[s] {
			return true
		}
	}
	return false
}

// neighEntries runs `ip -j <args>` and is its entries: nil when it can't
// be read (frfw.ids_quarantine's lookups find nothing then).
func (s *Server) neighEntries(args ...string) []config.Value {
	r, err := s.sys().Run(apply.Cmd{Argv: append([]string{"ip", "-j"}, args...), Timeout: neighTimeout})
	if err != nil || r.Code != 0 {
		return nil
	}
	return jsonList(r.Stdout)
}

// jsonList is json.loads(stdout or "[]") when it is a list; nil when it
// isn't one or isn't JSON.
func jsonList(stdout string) []config.Value {
	if stdout == "" {
		stdout = "[]"
	}
	v, err := config.ParseJSONLastWins([]byte(stdout))
	if err != nil {
		return nil
	}
	list, _ := v.([]config.Value)
	return list
}

// sameAddress is frfw's _same_address: dst is a string naming the same
// address as ip (ip -j writes an address in its own form).
func sameAddress(dst config.Value, ip string) bool {
	d, ok := dst.(string)
	if !ok {
		return false
	}
	a, err1 := config.ParsePyIP(d)
	b, err2 := config.ParsePyIP(ip)
	return err1 == nil && err2 == nil && a.Equal(b)
}

// lanNeighbourMAC is frfw.ids_quarantine.lan_neighbour_mac: the MAC the
// table holds for ip (a checked address, in its canonical text) on one of
// lanDevices, or "".
func (s *Server) lanNeighbourMAC(ip string, lanDevices map[string]bool) (string, error) {
	if len(lanDevices) == 0 {
		return "", nil
	}
	family := "-4"
	if containsColon(ip) {
		family = "-6"
	}
	for _, e := range s.neighEntries(family, "neigh", "show", "to", ip) {
		entry, ok := e.(*config.Map)
		if !ok {
			continue
		}
		if dst, _ := entry.Get("dst"); !sameAddress(dst, ip) {
			continue
		}
		dev, _ := entry.Get("dev")
		in, err := inSet(dev, lanDevices)
		if err != nil {
			return "", err
		}
		if !in {
			continue
		}
		state, _ := entry.Get("state")
		states, err := stateSet(state)
		if err != nil {
			return "", err
		}
		if !anyIn(states, usableNeighStates) {
			continue
		}
		lladdr, _ := entry.Get("lladdr")
		if mac, ok := validMAC(lladdr); ok {
			return mac, nil
		}
	}
	return "", nil
}

// lanNeighbours is frfw.ids_quarantine.lan_neighbours: address -> MAC
// for every usable entry of family ("-4" or "-6") on one of lanDevices,
// in one read of the table.
func (s *Server) lanNeighbours(lanDevices map[string]bool, family string) (map[string]string, error) {
	out := map[string]string{}
	if len(lanDevices) == 0 {
		return out, nil
	}
	for _, e := range s.neighEntries(family, "neigh", "show") {
		entry, ok := e.(*config.Map)
		if !ok {
			continue
		}
		dev, _ := entry.Get("dev")
		in, err := inSet(dev, lanDevices)
		if err != nil {
			return nil, err
		}
		if !in {
			continue
		}
		state, _ := entry.Get("state")
		states, err := stateSet(state)
		if err != nil {
			return nil, err
		}
		if !anyIn(states, usableNeighStates) {
			continue
		}
		dst, _ := entry.Get("dst")
		address, err := config.ParsePyIP(dst)
		if err != nil {
			continue
		}
		lladdr, _ := entry.Get("lladdr")
		mac, ok := validMAC(lladdr)
		if !ok {
			continue
		}
		out[address.String()] = mac
	}
	return out, nil
}

// lanIPv4Addresses are the IPv4 addresses the table holds for mac on the
// LAN, sorted as strings.
func (s *Server) lanIPv4Addresses(mac string, lanDevices map[string]bool) ([]string, error) {
	all, err := s.lanNeighbours(lanDevices, "-4")
	if err != nil {
		return nil, err
	}
	var out []string
	for ip, at := range all {
		if at == mac {
			out = append(out, ip)
		}
	}
	slices.Sort(out)
	return out, nil
}

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// --- the configured devices ---------------------------------------------------------

// lanDevices are the devices of the zones that don't face the internet,
// per the saved config: where a host's MAC may be looked up -- never the
// WAN's, where it would be the provider's gateway. An unreadable config
// gives none.
func (s *Server) lanDevices() map[string]bool {
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return map[string]bool{}
	}
	facing := c.InternetFacingZones()
	out := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		if !facing[i.Zone] {
			out[i.Device] = true
		}
	}
	return out
}

// routerAddresses are the router's own IPv4 addresses per the saved
// config, never quarantined. An unreadable config gives none: loopback
// and the other non-host addresses are still refused.
func (s *Server) routerAddresses() map[string]bool {
	out := map[string]bool{}
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return out
	}
	for _, i := range c.Interfaces.Values() {
		if i.Address != "" {
			out[hostOf(i.Address)] = true
		}
	}
	if c.Wireguard.Enabled && c.Wireguard.Address != "" {
		out[hostOf(c.Wireguard.Address)] = true
	}
	return out
}

// hostOf is str(IPv4Interface(text).ip) for a checked config's address.
func hostOf(text string) string {
	ip, _, _, err := config.IPv4InterfaceOf(text)
	if err != nil {
		return text
	}
	return ip.String()
}

var errNoNft = errors.New("'nft' binary not found; install the nftables package")
