package helper

import (
	"cmp"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// listening_sockets (security-lessons I3, frfw.surface.collect): every
// listening socket and the interfaces' addresses, read as root so `ss`
// can name the processes it may. The webUI works out from the config
// which zone reaches each.

// listener is frfw.surface.Listener.
type listener struct {
	proto, address string
	port           *big.Int
	device         *string // bound to one interface (SO_BINDTODEVICE)
	process        *string
}

func (l listener) key() string {
	opt := func(p *string) string {
		if p == nil {
			return "\x00"
		}
		return "\x01" + *p
	}
	return l.proto + "\x00" + l.address + "\x00" + l.port.String() + "\x00" + opt(l.device) + opt(l.process)
}

// ssUsersRE is the first process `ss -p` names: users:(("sshd",...
var ssUsersRE = regexp.MustCompile(`users:\(\("([^"]+)"`)

// splitHostPort is frfw.surface._split_host_port: "[::]:22",
// "0.0.0.0%eth1:67", "*:68".
func splitHostPort(local string) (host string, device *string, port *big.Int, ok bool) {
	i := strings.LastIndex(local, ":")
	portText := local
	if i >= 0 {
		host, portText = local[:i], local[i+1:]
	}
	if h, d, found := strings.Cut(host, "%"); found {
		host, device = h, &d
	}
	host = strings.Trim(host, "[]")
	if host == "*" {
		host = "::"
	}
	port, ok = config.PyInt(portText)
	return host, device, port, ok
}

// parseSS is frfw.surface.parse_ss: the listening sockets of `ss
// -Hlntup` (tcp LISTEN, udp UNCONN), each once, by protocol, port,
// address and device.
func parseSS(text string) []listener {
	seen := map[string]bool{}
	var out []listener
	for _, line := range config.PySplitlines(text) {
		fields := config.PySplit(line)
		if len(fields) < 5 || (fields[0] != "tcp" && fields[0] != "udp") {
			continue
		}
		host, device, port, ok := splitHostPort(fields[4])
		if !ok {
			continue
		}
		if _, err := config.ParsePyIP(host); err != nil {
			continue
		}
		l := listener{proto: fields[0], address: host, port: port, device: device}
		if m := ssUsersRE.FindStringSubmatch(line); m != nil {
			l.process = &m[1]
		}
		if !seen[l.key()] {
			seen[l.key()] = true
			out = append(out, l)
		}
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	// 1.x sorts a set: sockets with the same key and different processes
	// come out in no fixed order there; here the unnamed one first.
	slices.SortStableFunc(out, func(a, b listener) int {
		return cmp.Or(strings.Compare(a.proto, b.proto), a.port.Cmp(b.port), strings.Compare(a.address, b.address),
			strings.Compare(str(a.device), str(b.device)), cmpOpt(a.process, b.process))
	})
	return out
}

func cmpOpt(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return strings.Compare(*a, *b)
}

// parseIPAddr is frfw.surface.parse_ip_addr: interface -> its addresses,
// from `ip -j addr show`, in its order.
func parseIPAddr(text string) (*config.Map, error) {
	if text == "" {
		text = "[]"
	}
	v, err := config.ParseJSONLastWins([]byte(text))
	if err != nil {
		return nil, invalidRequest(err.Error())
	}
	ifaces, err := pyIter(v)
	if err != nil {
		return nil, err
	}
	out := config.NewMap()
	for _, iface := range ifaces {
		name, err := pySubscript(iface, "ifname")
		if err != nil {
			return nil, err
		}
		infos, ok, _ := pyDictGet(iface, "addr_info")
		if !ok {
			infos = []config.Value{}
		}
		items, err := pyIter(infos)
		if err != nil {
			return nil, err
		}
		addrs := []config.Value{}
		for _, a := range items {
			has, err := pyContains(a, "local")
			if err != nil {
				return nil, err
			}
			if !has {
				continue
			}
			local, err := pySubscript(a, "local")
			if err != nil {
				return nil, err
			}
			addrs = append(addrs, local)
		}
		if !out.SetKey(name, addrs) {
			return nil, invalidRequest("unhashable type: '" + pyTypeName(name) + "'")
		}
	}
	return out, nil
}

// pyContains is `key in v`: a dict's keys, a list's items, a str's
// substrings; a TypeError for anything else.
func pyContains(v config.Value, key string) (bool, error) {
	switch x := v.(type) {
	case *config.Map:
		return x.Has(key), nil
	case []config.Value:
		for _, item := range x {
			if item == key {
				return true, nil
			}
		}
		return false, nil
	case string:
		return strings.Contains(x, key), nil
	}
	return false, invalidRequest("argument of type '" + pyTypeName(v) + "' is not iterable")
}

func (s *Server) cmdListeningSockets() (any, error) {
	run := s.sys().Run
	ss, err := run(apply.Cmd{Argv: []string{"ss", "-Hlntup"}, Timeout: 10 * time.Second})
	if err == nil {
		var ip apply.Result
		ip, err = run(apply.Cmd{Argv: []string{"ip", "-j", "addr", "show"}, Timeout: 10 * time.Second})
		if err == nil {
			return listeningReply(ss, ip)
		}
		if errors.Is(err, apply.ErrNotFound) {
			return message(false, "cannot list sockets: "+notFound("ip")), nil
		}
	} else if errors.Is(err, apply.ErrNotFound) {
		return message(false, "cannot list sockets: "+notFound("ss")), nil
	}
	if errors.Is(err, apply.ErrTimeout) {
		return message(false, "cannot list sockets: "+err.Error()), nil
	}
	return failed(err)
}

func listeningReply(ss, ip apply.Result) (any, error) {
	if ss.Code != 0 {
		text := config.PyStrip(ss.Stderr)
		if text == "" {
			text = "ss failed"
		}
		return message(false, text), nil
	}
	if ip.Code != 0 {
		text := config.PyStrip(ip.Stderr)
		if text == "" {
			text = "ip addr failed"
		}
		return message(false, text), nil
	}
	listeners := parseSS(ss.Stdout)
	addresses, err := parseIPAddr(ip.Stdout)
	if err != nil {
		return nil, err
	}
	opt := func(p *string) config.Value {
		if p == nil {
			return nil
		}
		return *p
	}
	list := []config.Value{}
	for _, l := range listeners {
		m := config.NewMap()
		m.Set("proto", l.proto)
		m.Set("address", l.address)
		m.Set("port", l.port)
		m.Set("device", opt(l.device))
		m.Set("process", opt(l.process))
		list = append(list, m)
	}
	m := okMap()
	m.Set("listeners", list)
	m.Set("addresses", addresses)
	return pyReply(m)
}
