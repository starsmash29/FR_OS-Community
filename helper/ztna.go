package helper

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
	"github.com/starsmash29/fr_os-community/render"
)

// The ZTNA gate's sign-in and status (frfw.ztna, ROADMAP SEC-6, FND-1d).
// A client is one device: on the router's own networks its address and
// the MAC the router's neighbour table holds for it, read by root right
// after its sign-in reached the router -- never anything the client says;
// through the WireGuard tunnel its tunnel address, which WireGuard binds
// to its key. A client behind another router or NAT is refused: the
// router can't tell it apart from the others there.

// errNotDirect is frfw.ztna.ClientNotDirect.
type errNotDirect struct{ msg string }

func (e *errNotDirect) Error() string { return e.msg }

// clientLink is the MAC and device the router reaches a client at.
type clientLink struct{ mac, device string }

// ztnaAddress is frfw.ztna._validated_address: ip in the text `ip`
// writes it in, or an error.
func ztnaAddress(ip string) (string, error) {
	family := "IPv4"
	var a config.PyAddr
	var err error
	if strings.Contains(ip, ":") {
		family = "IPv6"
		a, err = config.ParsePyIPv6(ip)
	} else {
		a, err = config.ParsePyIPv4(ip)
	}
	if err != nil || a.String() != ip || a.HasScope() {
		return "", fmt.Errorf("invalid %s address %s", family, config.Repr(ip))
	}
	return ip, nil
}

// ztnaNeighbours is `ip -j neigh show <args>`: a table that can't be
// read is an error the admin sees, not "no such client".
func (s *Server) ztnaNeighbours(args ...string) ([]config.Value, error) {
	argv := append([]string{"ip", "-j", "neigh", "show"}, args...)
	r, err := s.sys().Run(apply.Cmd{Argv: argv, Timeout: neighTimeout})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return nil, errors.New("could not read the neighbour table: [Errno 2] No such file or directory: 'ip'")
	case err != nil:
		return nil, errors.New("could not read the neighbour table: " + err.Error())
	case r.Code != 0:
		if stderr := config.PyStrip(r.Stderr); stderr != "" {
			return nil, errors.New(stderr)
		}
		return nil, fmt.Errorf("ip neigh exited with status %d", r.Code)
	}
	stdout := r.Stdout
	if stdout == "" {
		stdout = "[]"
	}
	v, err := config.ParseJSONLastWins([]byte(stdout))
	if err != nil {
		return nil, errors.New("could not parse ip neigh output: " + err.Error())
	}
	list, _ := v.([]config.Value)
	return list, nil
}

// clientLinkOf is the MAC and device the neighbour table holds for ip,
// or nil: not a neighbour, so not on a network the router is attached to.
func (s *Server) clientLinkOf(ip string) (*clientLink, error) {
	ip, err := ztnaAddress(ip)
	if err != nil {
		return nil, err
	}
	entries, err := s.ztnaNeighbours("to", ip)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		entry, ok := e.(*config.Map)
		if !ok {
			continue
		}
		if dst, _ := entry.Get("dst"); !sameAddress(dst, ip) {
			continue
		}
		state, _ := entry.Get("state")
		states, err := stateSet(state)
		if err != nil {
			return nil, err
		}
		l, _ := entry.Get("lladdr")
		d, _ := entry.Get("dev")
		lladdr, isStr := l.(string)
		dev, devStr := d.(string)
		if !anyIn(states, ztnaNeighStates) || !isStr || !devStr {
			continue
		}
		mac, ok := validMAC(lladdr)
		if !ok {
			continue
		}
		if _, err := apply.Ifname(dev); err != nil {
			continue
		}
		return &clientLink{mac, dev}, nil
	}
	return nil, nil
}

// deviceAddresses is every address the neighbour table holds for the
// device at link (its MAC, on that link), link-local ones left out: what
// one sign-in admits (FND-1d).
func (s *Server) deviceAddresses(link *clientLink) ([]string, error) {
	entries, err := s.ztnaNeighbours("dev", link.device)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		entry, ok := e.(*config.Map)
		if !ok {
			continue
		}
		state, _ := entry.Get("state")
		states, err := stateSet(state)
		if err != nil {
			return nil, err
		}
		if !anyIn(states, ztnaNeighStates) {
			continue
		}
		l, _ := entry.Get("lladdr")
		d, _ := entry.Get("dst")
		lladdr, ok := l.(string)
		if !ok || config.PyLower(lladdr) != link.mac {
			continue
		}
		dst, ok := d.(string)
		if !ok {
			continue
		}
		a, err := config.ParsePyIP(dst)
		if err != nil || a.IsLinkLocal() || a.IsMulticast() || a.IsUnspecified() {
			continue
		}
		if !contains(out, a.String()) {
			out = append(out, a.String())
		}
	}
	return out, nil
}

// tunnelTwin is, for a WireGuard client's tunnel address, its tunnel
// address of the other family (the same host number): "" when it has
// none (no ULA prefix yet); ok false when a isn't in the tunnel at all.
func (s *Server) tunnelTwin(a config.PyAddr, c *config.Config) (twin string, ok bool) {
	wg := &c.Wireguard
	if !wg.Enabled || wg.Address == "" {
		return "", false
	}
	_, net4, prefix4, err := config.IPv4InterfaceOf(wg.Address)
	if err != nil {
		return "", false
	}
	size4 := new(big.Int).Lsh(big.NewInt(1), uint(32-prefix4))
	var net6 *big.Int
	if ula := s.sys().ULAPrefix(c); ula != nil {
		n6 := render.TunnelNetwork6(*ula)
		a6, err := config.ParsePyIPv6(n6.Addr().String())
		if err == nil {
			net6 = a6.Int()
		}
	}
	host := new(big.Int).Sub(a.Int(), net4.Int())
	if a.Version() == 4 && host.Sign() >= 0 && host.Cmp(size4) < 0 {
		if net6 == nil {
			return "", true
		}
		t, err := config.PyAddrFromInt(6, new(big.Int).Add(net6, host))
		if err != nil {
			return "", true
		}
		return t.String(), true
	}
	if net6 != nil && a.Version() == 6 {
		host = new(big.Int).Sub(a.Int(), net6)
		if host.Sign() >= 0 && host.BitLen() <= 64 {
			if host.Sign() > 0 && host.Cmp(new(big.Int).Sub(size4, big.NewInt(1))) < 0 {
				t, err := config.PyAddrFromInt(4, new(big.Int).Add(net4.Int(), host))
				if err == nil {
					return t.String(), true
				}
			}
			return "", true
		}
	}
	return "", false
}

// ztnaClient is which client ip is and its other addresses: "" and its
// other tunnel address for a WireGuard client, else the MAC the router
// sees ip at and every address the table holds for that MAC on that
// link. A client not directly attached is errNotDirect.
func (s *Server) ztnaClient(ip string, c *config.Config) (string, []string, error) {
	a, err := config.ParsePyIP(ip)
	if err != nil {
		return "", nil, err
	}
	if twin, ok := s.tunnelTwin(a, c); ok {
		if twin == "" {
			return "", []string{}, nil
		}
		return "", []string{twin}, nil
	}
	link, err := s.clientLinkOf(ip)
	if err != nil {
		return "", nil, err
	}
	if link == nil {
		return "", nil, &errNotDirect{ip + " is not on a network the router is attached to -- it came through another " +
			"router or NAT, so the router can't tell its devices apart and won't sign them all in at once. From " +
			"outside, connect through the router's WireGuard VPN and sign in there."}
	}
	all, err := s.deviceAddresses(link)
	if err != nil {
		return "", nil, err
	}
	others := []string{}
	for _, x := range all {
		if x != a.String() {
			others = append(others, x)
		}
	}
	return link.mac, others, nil
}

// requestAddress is the request's "ip": a string, with no scope, that is
// an address.
func requestAddress(request *config.Map) (string, any) {
	ip, ok := requestString(request, "ip")
	if !ok {
		return "", message(false, "'ip' is required")
	}
	if strings.Contains(ip, "%") { // any text after a `%` parses as a scope
		return "", message(false, fmt.Sprintf("invalid IP address %s: no scope (%%) allowed", config.Repr(ip)))
	}
	if _, err := config.ParsePyIP(ip); err != nil {
		return "", message(false, fmt.Sprintf("invalid IP address %s: %s", config.Repr(ip), err))
	}
	return ip, nil
}

type authorizeReply struct {
	OK        bool     `json:"ok"`
	Message   string   `json:"message"`
	ExpiresIn int64    `json:"expires_in"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}

func (s *Server) cmdAuthorizeZtna(request *config.Map) (any, error) {
	ip, ok := requestString(request, "ip")
	if !ok {
		return message(false, "'ip' is required"), nil
	}
	username, ok := requestString(request, "username")
	if !ok {
		return message(false, "'username' is required"), nil
	}
	if _, refused := requestAddress(request); refused != nil {
		return refused, nil
	}
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return commandError(err)
	}
	if !c.Ztna.Enabled {
		return message(false, "ZTNA gate is disabled in the current config"), nil
	}
	known := false
	for _, u := range c.Ztna.Users {
		known = known || u.Username == username
	}
	if !known {
		// The webUI has authenticated the user before it sent this: a
		// check against a stale or forged request naming a user that no
		// longer exists, not a second authentication.
		return message(false, "no such ZTNA user "+config.Repr(username)), nil
	}
	mac, others, err := s.ztnaClient(ip, c)
	if err != nil {
		return failed(err)
	}
	ttl := c.Ztna.SessionTTLSeconds
	addresses, err := s.authorizeClient(ip, mac, ttl, username, others)
	if err != nil {
		return failed(err)
	}
	basis := "your WireGuard key"
	if mac != "" {
		basis = "this device (" + mac + ")"
	}
	return authorizeReply{OK: true,
		Message: fmt.Sprintf("%s authorized as %s for %ds, bound to %s", strings.Join(addresses, ", "),
			config.Repr(username), ttl, basis),
		ExpiresIn: ttl, MAC: mac, Addresses: addresses}, nil
}

// authorizeClient puts the client in the ZTNA sets for ttl seconds -- the
// sole enforcement; the state file is only for the status page. mac ""
// is a WireGuard client, by its tunnel addresses.
func (s *Server) authorizeClient(ip, mac string, ttl int64, username string, also []string) ([]string, error) {
	addresses := []string{}
	for _, a := range append([]string{ip}, also...) {
		a, err := ztnaAddress(a)
		if err != nil {
			return nil, err
		}
		if !contains(addresses, a) {
			addresses = append(addresses, a)
		}
	}
	if mac != "" {
		m, ok := validMAC(mac)
		if !ok {
			return nil, errors.New("invalid MAC address " + config.Repr(config.PyLower(mac)))
		}
		mac = m
	}
	seconds := big.NewInt(ttl)
	for _, a := range addresses {
		v6 := strings.Contains(a, ":")
		var err error
		switch {
		case mac != "" && v6:
			err = s.addTimed(nft.Ztna6Set, a+" . "+mac, seconds)
		case mac != "":
			err = s.addTimed(nft.ZtnaSet, a+" . "+mac, seconds)
		case v6:
			err = s.addTimed(nft.ZtnaTunnel6Set, a, seconds)
		default:
			err = s.addTimed(nft.ZtnaTunnelSet, a, seconds)
		}
		if err != nil {
			return nil, err
		}
		if err := s.recordAuthorization(a, mac, username); err != nil {
			return nil, err
		}
	}
	return addresses, nil
}

// ztnaStatePath is the helper's state file: Env's, or Sys's.
func (s *Server) ztnaStatePath() string {
	if s.Env.ZtnaStatePath != "" {
		return s.Env.ZtnaStatePath
	}
	return s.sys().Paths.ZtnaState
}

// loadZtnaState is the state file's JSON, an empty mapping when there is
// none or it can't be read.
func (s *Server) loadZtnaState() (config.Value, error) {
	path := s.ztnaStatePath()
	if !isFile(path) {
		return config.NewMap(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return config.NewMap(), nil
	}
	if !utf8.Valid(data) {
		return nil, invalidRequest("'utf-8' codec can't decode " + path)
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return config.NewMap(), nil
	}
	return v, nil
}

// recordAuthorization notes who signed in at ip (display only).
func (s *Server) recordAuthorization(ip, mac, username string) error {
	v, err := s.loadZtnaState()
	if err != nil {
		return err
	}
	state, ok := v.(*config.Map)
	if !ok {
		if _, isList := v.([]config.Value); isList {
			return invalidRequest("list indices must be integers or slices, not str")
		}
		return invalidRequest(fmt.Sprintf("'%s' object does not support item assignment", pyTypeName(v)))
	}
	entry := config.NewMap()
	entry.Set("username", username)
	entry.Set("mac", mac)
	entry.Set("authorized_at", apply.NowSeconds(s.sys().Now()))
	state.Set(ip, entry)
	text, err := config.PyJSON(state, -1, false)
	if err != nil {
		return err
	}
	path := s.ztnaStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	tmp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type ztnaStatusReply struct {
	OK         bool  `json:"ok"`
	Authorized bool  `json:"authorized"`
	Direct     *bool `json:"direct,omitempty"`
}

type ztnaFound struct {
	OK         bool         `json:"ok"`
	Authorized bool         `json:"authorized"`
	Username   config.Value `json:"username"`
	ExpiresIn  *big.Int     `json:"expires_in"`
	MAC        string       `json:"mac"`
}

func (s *Server) cmdZtnaStatus(request *config.Map) (any, error) {
	ip, refused := requestAddress(request)
	if refused != nil {
		return refused, nil
	}
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return commandError(err)
	}
	mac, _, err := s.ztnaClient(ip, c)
	var nd *errNotDirect
	if errors.As(err, &nd) {
		no := false
		return ztnaStatusReply{OK: true, Authorized: false, Direct: &no}, nil
	}
	if err != nil {
		return failed(err)
	}
	sessions, err := s.ztnaSessions()
	if err != nil {
		return failed(err)
	}
	for _, x := range sessions {
		if sameAddress(x.IP, ip) && x.MAC == config.PyLower(mac) {
			v, err := s.loadZtnaState()
			if err != nil {
				return nil, err
			}
			state, ok := v.(*config.Map)
			if !ok {
				// state.get on a list: AttributeError, which 1.x's
				// handler doesn't catch.
				return nil, errNoReply
			}
			var username config.Value
			if e, _ := state.Get(x.IP); e != nil {
				if em, ok := e.(*config.Map); ok {
					username, _ = em.Get("username")
				}
			}
			return ztnaFound{OK: true, Authorized: true, Username: username, ExpiresIn: x.ExpiresIn, MAC: x.MAC}, nil
		}
	}
	return ztnaStatusReply{OK: true, Authorized: false}, nil
}
