package helper

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// ipv6_status (ROADMAP FND-1a, frfw.ipv6.status): what the provider gave
// the WAN, read from the kernel as root -- the webUI's sandbox has no
// netlink socket. Its global addresses, its default route, the
// unreachable routes dhcpcd installs for a delegated prefix, and the
// networks made of it on the LAN.

// status()'s verdicts.
const (
	ipv6Off         = "off"
	ipv6NoKernel    = "no-kernel-ipv6"
	ipv6Nothing     = "nothing"
	ipv6AddressOnly = "address-only"
	ipv6Prefix      = "prefix"
)

// ipv6Status is frfw.ipv6.Ipv6Status.
type ipv6Status struct {
	state         string
	devices       []string
	addresses     [][3]string // device, address/prefixlen, "SLAAC" or "DHCPv6"
	defaultRoutes [][2]string // device, gateway
	prefixes      []string
	serviceActive bool
	lan           [][3]string // zone, device, its network or ""
	raActive      bool
	excluded      []config.ZoneReason
	ulaPrefix     string
	ula           [][3]string // zone, device, the router's ULA address/64
	pinholes      []pinholeTarget
}

// pinholeTarget is a pinhole and the addresses it opens now; nil
// targets: its zone has no IPv6 now, so it is off.
type pinholeTarget struct {
	name, zone, what string
	targets          []string
}

// ipv6StateError is a failure 1.x words "could not read the IPv6 state":
// an OSError, ValueError, KeyError, TypeError or timeout.
func ipv6StateError(err error) error {
	var bad invalidRequest
	var key keyError
	switch {
	case errors.As(err, &bad):
		return errors.New("could not read the IPv6 state: " + string(bad))
	case errors.As(err, &key):
		return errors.New("could not read the IPv6 state: " + key.Error())
	}
	return err
}

func (s *Server) cmdIPv6Status() (any, error) {
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return commandError(err)
	}
	st, err := s.ipv6Status(c)
	if err != nil {
		var plain *plainError
		if errors.As(err, &plain) {
			return message(false, plain.msg), nil
		}
		if errors.Is(err, errNoReply) {
			return nil, err
		}
		return message(false, ipv6StateError(err).Error()), nil
	}
	return pyReply(st.asMap())
}

// plainError is an Ipv6Error: its text as it is.
type plainError struct{ msg string }

func (e *plainError) Error() string { return e.msg }

// ipJSON is `ip -j -6 ARGS`'s list: a failure is an Ipv6Error, a missing
// ip or a timeout the OSError and TimeoutExpired 1.x words as above.
func (s *Server) ipJSON(args ...string) ([]config.Value, error) {
	res, err := s.sys().Run(apply.Cmd{Argv: append([]string{"ip", "-j", "-6"}, args...), Timeout: 10 * time.Second})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return nil, invalidRequest(notFound("ip"))
	case errors.Is(err, apply.ErrTimeout):
		return nil, invalidRequest(err.Error())
	case err != nil:
		return nil, err
	}
	if res.Code != 0 {
		return nil, &plainError{fmt.Sprintf("ip -6 %s failed: %s", strings.Join(args, " "), config.PyStrip(res.Stderr))}
	}
	stdout := res.Stdout
	if stdout == "" {
		stdout = "[]"
	}
	v, err := config.ParseJSONLastWins([]byte(stdout))
	if err != nil {
		return nil, invalidRequest(err.Error())
	}
	return pyIter(v)
}

// pyDictGet is d.get(key) on what 1.x expects to be a dict (anything
// else is the AttributeError it lets through), nil when missing.
func pyDictGet(v config.Value, key string) (config.Value, bool, error) {
	m, ok := v.(*config.Map)
	if !ok {
		return nil, false, errNoReply
	}
	got, ok := m.Get(key)
	return got, ok, nil
}

func (s *Server) ipv6Status(c *config.Config) (*ipv6Status, error) {
	sys := s.sys()
	st := &ipv6Status{devices: c.WanDevices()}
	if !c.IPv6.Enabled {
		st.state = ipv6Off
		return st, nil
	}
	if !sys.KernelHasIPv6() {
		st.state = ipv6NoKernel
		return st, nil
	}
	lan := c.LanDevices()
	st.state = ipv6Nothing
	st.serviceActive = sys.ServiceActive(apply.IPv6Service)
	st.raActive = len(lan) > 0 && sys.ServiceActive(apply.IPv6RAService)
	st.excluded = c.IPv6ExcludedZones()
	ula := sys.ULAPrefix(c)
	if ula != nil && len(lan) > 0 {
		st.ulaPrefix = ula.String()
	}
	ulaAddrs := render.ULAAddresses(c, ula)
	stable := map[[2]string]bool{}
	for _, u := range ulaAddrs {
		stable[[2]string{u.Device, u.Address}] = true
	}
	present := map[[2]string]bool{}
	lanNetwork := config.NewMap() // device -> its /64, the first one seen
	isWan := func(v config.Value) bool { d, ok := v.(string); return ok && slices.Contains(st.devices, d) }
	isLan := func(v config.Value) bool {
		d, ok := v.(string)
		return ok && slices.ContainsFunc(lan, func(zd config.ZoneDevice) bool { return zd.Device == d })
	}

	links, err := s.ipJSON("addr", "show")
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		device, _, err := pyDictGet(link, "ifname")
		if err != nil {
			return nil, err
		}
		infos, ok, _ := pyDictGet(link, "addr_info")
		if !ok {
			infos = []config.Value{}
		}
		items, err := pyIter(infos)
		if err != nil {
			return nil, err
		}
		for _, info := range items {
			family, _, err := pyDictGet(info, "family")
			if err != nil {
				return nil, err
			}
			if family != "inet6" {
				continue
			}
			if scope, _, _ := pyDictGet(info, "scope"); scope != "global" {
				continue
			}
			local, err := pySubscript(info, "local")
			if err != nil {
				return nil, err
			}
			plen, err := pySubscript(info, "prefixlen")
			if err != nil {
				return nil, err
			}
			n, err := pyInt(plen)
			if err != nil {
				return nil, err
			}
			address, err := config.ParsePyIPv6Interface(config.Str(local) + "/" + n.String())
			if err != nil {
				return nil, invalidRequest(err.Error())
			}
			if address.InULA() {
				// FND-1c: the router's own stable addresses, not the provider's.
				if err := hashable(device); err != nil {
					return nil, err
				}
				if d, ok := device.(string); ok {
					present[[2]string{d, address.String()}] = true
				}
				continue
			}
			if isWan(device) {
				// dhcpcd adds a DHCPv6 (IA_NA) address as a /128, a SLAAC one
				// with its prefix's length.
				source := "SLAAC"
				if address.Prefix() == 128 {
					source = "DHCPv6"
				}
				st.addresses = append(st.addresses, [3]string{device.(string), address.String(), source})
			} else if isLan(device) && address.Prefix() == 64 {
				d := device.(string)
				if !lanNetwork.Has(d) {
					lanNetwork.Set(d, address.Network().String())
				}
			}
		}
	}
	for _, zd := range lan {
		network := ""
		if v, ok := lanNetwork.Get(zd.Device); ok {
			network = v.(string)
		}
		st.lan = append(st.lan, [3]string{zd.Zone, zd.Device, network})
	}
	for _, u := range ulaAddrs {
		k := [2]string{u.Device, u.Address}
		if present[k] && stable[k] {
			st.ula = append(st.ula, [3]string{u.Zone, u.Device, u.Address})
		}
	}
	if st.pinholes, err = pinholeTargets(c, st.lan); err != nil {
		return nil, err
	}

	routes, err := s.ipJSON("route", "show", "table", "main")
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		dst, _, err := pyDictGet(route, "dst")
		if err != nil {
			return nil, err
		}
		dev, _, _ := pyDictGet(route, "dev")
		gateway, _, _ := pyDictGet(route, "gateway")
		if dst == "default" && isWan(dev) && config.Truthy(gateway) {
			gw, err := config.ParsePyIPv6(gateway)
			if err != nil {
				return nil, invalidRequest(err.Error())
			}
			st.defaultRoutes = append(st.defaultRoutes, [2]string{dev.(string), gw.String()})
			continue
		}
		typ, _, _ := pyDictGet(route, "type")
		proto, _, _ := pyDictGet(route, "protocol")
		if typ == "unreachable" && proto == "dhcp" && config.Truthy(dst) {
			network, err := config.ParsePyIPv6Network(dst)
			if err != nil {
				return nil, invalidRequest(err.Error())
			}
			if network.Prefix() <= 64 && !(network.IsLinkLocal() || network.IsMulticast() || network.IsLoopback()) {
				st.prefixes = append(st.prefixes, network.String())
			}
		}
	}
	if len(st.prefixes) == 0 && lanNetwork.Len() > 0 {
		// A delegated /64 given whole to the first LAN device: dhcpcd
		// installs no unreachable route for it (dhcpcd.conf(5), ia_pd).
		seen := map[string]bool{}
		for _, v := range lanNetwork.Values() {
			if n := v.(string); !seen[n] {
				seen[n] = true
				st.prefixes = append(st.prefixes, n)
			}
		}
		slices.Sort(st.prefixes)
	}
	switch {
	case len(st.prefixes) > 0:
		st.state = ipv6Prefix
	case len(st.addresses) > 0:
		st.state = ipv6AddressOnly
	}
	return st, nil
}

// pinholeTargets is frfw.ipv6.pinhole_targets: per pinhole (FND-1c), an
// interface identifier in each network its zone has now, a full address
// as it is -- nil when the zone has no IPv6 now.
func pinholeTargets(c *config.Config, lan [][3]string) ([]pinholeTarget, error) {
	served := map[string]bool{}
	for _, zd := range c.LanDevices() {
		served[zd.Zone] = true
	}
	var out []pinholeTarget
	for i := range c.IPv6.Pinholes {
		p := &c.IPv6.Pinholes[i]
		var targets []string
		switch {
		case !served[p.Zone]:
		case p.IsSuffix():
			host, err := config.ParsePyIPv6(p.Host)
			if err != nil {
				return nil, invalidRequest(err.Error())
			}
			targets = []string{}
			for _, l := range lan {
				if l[0] != p.Zone || l[2] == "" {
					continue
				}
				network, err := config.ParsePyIPv6Network(l[2])
				if err != nil {
					return nil, invalidRequest(err.Error())
				}
				a, err := network.AddressPlus(host.Int())
				if err != nil {
					return nil, invalidRequest(err.Error())
				}
				targets = append(targets, a.String())
			}
		default:
			targets = []string{p.Host}
		}
		out = append(out, pinholeTarget{p.Name, p.Zone, string(p.Proto) + " " + p.Port(), targets})
	}
	return out, nil
}

// lanNetworks is how many /64 LAN networks a delegated prefix holds.
func lanNetworks(prefix string) *big.Int {
	n, err := config.ParseIPv6Network(prefix)
	if err != nil {
		return big.NewInt(0)
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(max(0, 64-n.Prefix())))
}

func (st *ipv6Status) summary() string {
	switch st.state {
	case ipv6Off:
		return "IPv6 is off."
	case ipv6NoKernel:
		return "This router's kernel runs without IPv6."
	}
	return st.providerSummary() + st.stableSummary()
}

// stableSummary (FND-1c): the LAN's own networks, whatever the provider
// gives.
func (st *ipv6Status) stableSummary() string {
	if len(st.ula) == 0 {
		return ""
	}
	return " The LAN's stable networks come from " + st.ulaPrefix + " (ULA, never routed to the internet): " +
		"the router answers there whatever the provider gives."
}

func (st *ipv6Status) providerSummary() string {
	switch st.state {
	case ipv6Nothing:
		return "Nothing from the provider (yet): no IPv6 address on the WAN. Either the network " +
			"upstream has no IPv6, or it hasn't answered yet; the router keeps using IPv4."
	case ipv6AddressOnly:
		return "The WAN has an IPv6 address, but no prefix was delegated: the router itself has IPv6, " +
			"the LAN can't get it from this upstream. Turn on prefix delegation (DHCPv6-PD) on the " +
			"router in front of this one, or ask the provider for it."
	}
	sizes := make([]string, len(st.prefixes))
	for i, p := range st.prefixes {
		sizes[i] = fmt.Sprintf("%s (%s LAN networks)", p, lanNetworks(p))
	}
	text := "A prefix was delegated: " + strings.Join(sizes, ", ") + "."
	var leftOut strings.Builder
	for _, e := range st.excluded {
		fmt.Fprintf(&leftOut, " Zone %s gets no IPv6: %s.", e.Zone, e.Why)
	}
	if len(st.lan) == 0 {
		return text + " No LAN zone gets IPv6, so only the router uses it." + leftOut.String()
	}
	var served, waiting []string
	for _, l := range st.lan {
		if l[2] != "" {
			served = append(served, fmt.Sprintf("%s (%s) %s", l[0], l[1], l[2]))
		} else {
			waiting = append(waiting, fmt.Sprintf("%s (%s)", l[0], l[1]))
		}
	}
	if len(served) > 0 {
		text += " The LAN has IPv6: " + strings.Join(served, ", ") + "."
	}
	if len(waiting) > 0 {
		room := new(big.Int)
		for _, p := range st.prefixes {
			room.Add(room, lanNetworks(p))
		}
		if room.Sign() != 0 && room.Cmp(big.NewInt(int64(len(st.lan)))) < 0 {
			text += fmt.Sprintf(" No network on %s: the prefix holds %s LAN network(s) and "+
				"%d are needed. Ask the provider for a larger prefix (a /56 or /60), "+
				"or leave zones out of ipv6.lan_zones.", strings.Join(waiting, ", "), room, len(st.lan))
		} else {
			text += " No network on " + strings.Join(waiting, ", ") + " yet."
		}
	}
	return text + leftOut.String()
}

// asMap is Ipv6Status.as_dict, after "ok".
func (st *ipv6Status) asMap() *config.Map {
	strs := func(list []string) []config.Value {
		out := []config.Value{}
		for _, s := range list {
			out = append(out, s)
		}
		return out
	}
	m := okMap()
	m.Set("state", st.state)
	m.Set("summary", st.summary())
	m.Set("devices", strs(st.devices))
	rows := func(n int, get func(i int) []string) []config.Value {
		out := []config.Value{}
		for i := range n {
			out = append(out, strs(get(i)))
		}
		return out
	}
	m.Set("addresses", rows(len(st.addresses), func(i int) []string { return st.addresses[i][:] }))
	m.Set("default_routes", rows(len(st.defaultRoutes), func(i int) []string { return st.defaultRoutes[i][:] }))
	m.Set("prefixes", strs(st.prefixes))
	m.Set("service_active", st.serviceActive)
	m.Set("lan", rows(len(st.lan), func(i int) []string { return st.lan[i][:] }))
	m.Set("ra_active", st.raActive)
	m.Set("excluded", rows(len(st.excluded), func(i int) []string {
		return []string{st.excluded[i].Zone, st.excluded[i].Why}
	}))
	m.Set("ula_prefix", st.ulaPrefix)
	m.Set("ula", rows(len(st.ula), func(i int) []string { return st.ula[i][:] }))
	pinholes := []config.Value{}
	for _, p := range st.pinholes {
		var targets config.Value
		if p.targets != nil {
			targets = strs(p.targets)
		}
		pinholes = append(pinholes, []config.Value{p.name, p.zone, p.what, targets})
	}
	m.Set("pinholes", pinholes)
	return m
}
