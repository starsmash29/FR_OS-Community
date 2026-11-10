package webui

import (
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The WireGuard VPN screen (1.x's routes/vpn.py, security-lessons
// G8/K5): the tunnel's settings, the router's public key and each
// device's last handshake (from the apply-helper: the key and `wg show`
// are root's), and the devices. A device either brings its own public
// key, or the router makes a key pair and shows the device's
// configuration once, as text and as a QR code; that private key is
// kept nowhere. A new device, and turning the VPN on, are alerts (G9).

const defaultVPNAddress = "10.99.0.1/24"

// fullTunnel is frfw.wireguard.FULL_TUNNEL: ::/0 too, or the device's
// IPv6 goes around the tunnel (H1).
const fullTunnel = "0.0.0.0/0, ::/0"

// vpnRules are added when the VPN is turned on, if missing: without
// them the tunnel comes up but leads nowhere.
var vpnRules = []struct {
	name, toZone string
	tcpPort      int
}{
	{"webui-from-vpn", "self", 443},
	{"ssh-from-vpn", "self", 22},
	{"vpn-to-lan", "lan", 0},
}

func (s *Server) ulaStatePath() string { return s.env.Paths.at("/etc/fr_os/ipv6_ula.json") }

// wireguardStatus is _status: the helper's reply when it is ok, else
// nothing (its HelperError is not caught, as in 1.x).
func (s *Server) wireguardStatus() (*config.Map, error) {
	reply, err := s.helper.WireGuardStatus()
	if err != nil {
		return nil, err
	}
	if !config.Truthy(field(reply, "ok")) {
		return config.NewMap(), nil
	}
	return reply, nil
}

// vpnPeers is _peers: the mappings of wireguard.peers.
func vpnPeers(raw *config.Map) ([]*config.Map, error) {
	section, err := getMapOr(raw, "wireguard")
	if err != nil {
		return nil, err
	}
	items, err := pyIter(orNil(field(section, "peers")))
	if err != nil {
		return nil, err
	}
	var out []*config.Map
	for _, item := range items {
		if m, ok := item.(*config.Map); ok {
			out = append(out, m)
		}
	}
	return out, nil
}

// tunnelIPv6 is _tunnel_ipv6: what the router does with the VPN
// clients' IPv6 (FND-1d), in words.
func tunnelIPv6(c *config.Config) string {
	wg := c.Wireguard
	switch {
	case !wg.Enabled:
		return ""
	case c.TunnelServed():
		return "Reaches the router and the LAN's stable (ULA) addresses; the rest is refused, never sent around the tunnel."
	case !c.IPv6.Enabled:
		return "Refused: IPv6 is off on this router. Devices use IPv4 through the tunnel, never IPv6 around it."
	}
	why := c.IPv6LanExclusions()[wg.Zone]
	return fmt.Sprintf("Refused: zone %s gets no IPv6 (%s). Devices use IPv4 through the tunnel.", wg.Zone, why)
}

type vpnPeer struct {
	Name, Address, Address6, KeyStart string
	DualStack                         bool
	Handshake, EndpointSeen           string
}

type vpnData struct {
	Enabled, Up                   bool
	Address, ListenPort, Endpoint string
	Peers                         []vpnPeer
	Reissue                       bool
	TunnelIPv6, RouterKey         string
}

func (s *Server) showVPN(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "wireguard")
	if err != nil {
		return nil, err
	}
	status, err := s.wireguardStatus()
	if err != nil {
		return nil, err
	}
	handshakes, err := getMapOr(status, "peers")
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		cfg = nil
	}
	var ula *netip.Prefix
	if cfg != nil && cfg.Wireguard.Address != "" {
		ula = apply.ULAPrefixAt(s.ulaStatePath(), cfg)
	}
	peers, err := vpnPeers(raw)
	if err != nil {
		return nil, err
	}
	d := &vpnData{}
	for _, peer := range peers {
		live := config.NewMap()
		switch key := field(peer, "public_key").(type) {
		case string:
			if v, ok := handshakes.Get(key); ok {
				m, isMap := v.(*config.Map)
				if !isMap {
					return nil, errInternal // live.get on anything else
				}
				live = m
			}
		case []config.Value, *config.Map:
			return nil, errInternal // unhashable
		}
		row := vpnPeer{Name: jinjaText(peer, "name"), Address: jinjaText(peer, "address"),
			DualStack: field(peer, "dual_stack") == true, EndpointSeen: pyStr(pyGet(live, "endpoint", ""))}
		key, ok := field(peer, "public_key").(string)
		if !ok {
			return nil, errInternal // p.public_key[:12] of None or a number
		}
		row.KeyStart = pySlice(key, 12)
		if ts := field(live, "latest_handshake"); config.Truthy(ts) {
			stamp, ok := s.localStamp(ts, "2006-01-02 15:04:05")
			if !ok {
				return nil, errInternal
			}
			row.Handshake = stamp
		}
		if ula != nil {
			if address, ok := field(peer, "address").(string); ok {
				if a6, err := render.PeerAddress6(&cfg.Wireguard, address, *ula); err == nil {
					row.Address6 = a6
				}
			}
		}
		if !row.DualStack {
			d.Reissue = true
		}
		d.Peers = append(d.Peers, row)
	}
	d.Enabled = config.Truthy(field(section, "enabled"))
	d.Address = defaultVPNAddress
	if v := field(section, "address"); config.Truthy(v) {
		d.Address = pyStr(v)
	}
	d.ListenPort = pyStr(pyGet(section, "listen_port", pyInt(51820)))
	d.Endpoint = pyStr(pyGet(section, "endpoint", ""))
	if cfg != nil {
		d.TunnelIPv6 = tunnelIPv6(cfg)
	}
	if v := field(status, "public_key"); config.Truthy(v) {
		d.RouterKey = pyStr(v)
	}
	d.Up = config.Truthy(pyGet(status, "up", false))
	return s.render(q, "vpn", flash(q, &page{Username: q.user.Username, Data: d}))
}

// pySlice is s[:n] by code point.
func pySlice(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func (s *Server) saveVPN(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	var address, endpoint string
	var port *big.Int
	if err = q.fields(func(p *formParams) {
		enabled, address = p.boolOr("enabled", false), p.strOr("address", defaultVPNAddress)
		port, endpoint = p.intOr("listen_port", pyInt(51820)), p.strOr("endpoint", "")
	}); err != nil {
		return nil, err
	}
	section, err := setdefaultMap(raw, "wireguard")
	if err != nil {
		return nil, err
	}
	wasEnabled := config.Truthy(field(section, "enabled"))
	section.Set("enabled", enabled)
	section.Set("address", pyStripped(address))
	section.Set("listen_port", port)
	section.Set("endpoint", pyStripped(endpoint))
	setdefault(section, "peers", []config.Value{})
	if enabled {
		zone, ok := setdefault(section, "zone", "vpn").(string)
		if !ok {
			return nil, errInternal
		}
		zones, err := setdefaultMap(raw, "zones")
		if err != nil {
			return nil, err
		}
		setdefault(zones, zone, config.NewMap())
		rules, ok := setdefault(raw, "rules", []config.Value{}).([]config.Value)
		if !ok {
			return nil, errInternal
		}
		names := map[string]bool{}
		for _, r := range rules {
			if m, ok := r.(*config.Map); ok {
				if n, ok := field(m, "name").(string); ok {
					names[n] = true
				}
			}
		}
		for _, rule := range vpnRules {
			if names[rule.name] || !(rule.toZone == "self" || zones.Has(rule.toZone)) {
				continue
			}
			m := cmdMap("name", rule.name, "action", "accept", "from_zone", zone, "to_zone", rule.toZone)
			if rule.tcpPort != 0 {
				m.Set("proto", "tcp")
				m.Set("dst_port", pyInt(int64(rule.tcpPort)))
			}
			rules = append(rules, m)
		}
		raw.Set("rules", rules)
	}
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/vpn", message), nil
	}
	if enabled && !wasEnabled {
		s.auditAlert(fmt.Sprintf("WireGuard VPN turned on by %s", config.Repr(q.user.Username)),
			entry("user", q.user.Username, "client", q.clientIP()))
	}
	state := "off"
	if enabled {
		state = "on"
	}
	return successRedirect("/vpn", fmt.Sprintf("VPN settings saved (%s) -- click Apply on the dashboard to load them", state)), nil
}

// wireguardKeypair is frfw.wireguard.generate_keypair: (private, public),
// base64 as `wg genkey`/`wg pubkey` print them.
func (s *Server) wireguardKeypair() (string, string, error) {
	private := s.env.bytes(32)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return "", "", err
	}
	enc := base64.StdEncoding
	return enc.EncodeToString(private), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

// nextFreeAddress is frfw.wireguard.next_free_address: the first host
// address of the tunnel no peer (and not the router) uses.
func nextFreeAddress(wg *config.WireguardConfig) (string, error) {
	tunnel, err := netip.ParsePrefix(wg.Address)
	if err != nil {
		return "", errInternal
	}
	used := map[netip.Addr]bool{tunnel.Addr(): true}
	for _, p := range wg.Peers {
		a, err := netip.ParsePrefix(p.Address)
		if err != nil {
			return "", errInternal
		}
		used[a.Addr()] = true
	}
	network := tunnel.Masked()
	for _, ip := range ipv4Hosts(network) {
		if !used[ip] {
			return ip.String() + "/32", nil
		}
	}
	return "", &segmentError{fmt.Sprintf("no free address left in %s", network)}
}

// ipv4Hosts is IPv4Network.hosts(): every address but the network and
// broadcast ones, all of a /31, the one of a /32.
func ipv4Hosts(network netip.Prefix) []netip.Addr {
	first := network.Addr()
	size := uint64(1) << (32 - network.Bits())
	var out []netip.Addr
	switch network.Bits() {
	case 32:
		return []netip.Addr{first}
	case 31:
		return []netip.Addr{first, first.Next()}
	}
	a := first.Next()
	for i := uint64(1); i < size-1; i++ {
		out = append(out, a)
		a = a.Next()
	}
	return out
}

// splitTunnelNetworks is frfw.wireguard.split_tunnel_networks: the
// tunnel, the networks of the zones that don't face the internet and,
// with the ULA prefix, the tunnel's IPv6 network and (while the router
// routes IPv6 for the tunnel) the LAN zones' stable networks.
func splitTunnelNetworks(c *config.Config, ula *netip.Prefix) []string {
	internet := c.InternetFacingZones()
	tunnel, _ := netip.ParsePrefix(c.Wireguard.Address)
	nets := []string{tunnel.Masked().String()}
	add := func(n string) {
		for _, have := range nets {
			if have == n {
				return
			}
		}
		nets = append(nets, n)
	}
	ifaces := c.Interfaces.Values()
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	for _, iface := range ifaces {
		if iface.Address != "" && !internet[iface.Zone] {
			if p, err := netip.ParsePrefix(iface.Address); err == nil {
				add(p.Masked().String())
			}
		}
	}
	if ula != nil {
		nets = append(nets, render.TunnelNetwork6(*ula).String())
		if c.TunnelServed() {
			for _, u := range render.ULAAddresses(c, ula) {
				if p, err := netip.ParsePrefix(u.Address); err == nil {
					add(p.Masked().String())
				}
			}
		}
	}
	return nets
}

// clientConfig is frfw.wireguard.client_config: a new device's
// configuration, for the WireGuard app (also as a QR code).
func clientConfig(c *config.Config, privateKey, address, routerKey string, full bool, ula *netip.Prefix) (string, error) {
	wg := &c.Wireguard
	endpoint := wg.Endpoint
	if endpoint == "" {
		endpoint = "YOUR-ROUTER-ADDRESS"
	}
	allowed := fullTunnel
	if !full {
		allowed = strings.Join(splitTunnelNetworks(c, ula), ", ")
	}
	addresses := address
	if ula != nil {
		a6, err := render.PeerAddress6(wg, address, *ula)
		if err != nil {
			return "", err
		}
		addresses += ", " + a6
	}
	return strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + privateKey,
		"Address = " + addresses,
		"",
		"[Peer]",
		"PublicKey = " + routerKey,
		fmt.Sprintf("Endpoint = %s:%d", endpoint, wg.ListenPort),
		"AllowedIPs = " + allowed,
		"PersistentKeepalive = 25",
		"",
	}, "\n"), nil
}

type vpnPeerData struct {
	Name, ConfigText string
	QR               any
}

func (s *Server) addVPNPeer(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var name, publicKey string
	var full bool
	if err = q.fields(func(p *formParams) {
		name, publicKey, full = p.str("name"), p.strOr("public_key", ""), p.boolOr("full_tunnel", false)
	}); err != nil {
		return nil, err
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		return errorRedirect("/vpn", err.Error()), nil
	}
	if cfg.Wireguard.Address == "" {
		return errorRedirect("/vpn", "Set the VPN's address and save the settings first"), nil
	}
	publicKey = pyStripped(publicKey)
	var privateKey, routerKey string
	if publicKey == "" {
		status, err := s.wireguardStatus()
		if err != nil {
			return nil, err
		}
		key := field(status, "public_key")
		if !config.Truthy(key) {
			return errorRedirect("/vpn", "Turn the VPN on and click Apply first: the router makes its key then"), nil
		}
		routerKey = pyStr(key)
		if privateKey, publicKey, err = s.wireguardKeypair(); err != nil {
			return nil, err
		}
	}
	address, err := nextFreeAddress(&cfg.Wireguard)
	if e, ok := err.(*segmentError); ok {
		return errorRedirect("/vpn", e.msg), nil
	} else if err != nil {
		return nil, err
	}
	// FND-1d: the device's IPv6 tunnel address, once an apply with the
	// VPN on made the ULA prefix. Only a configuration made here is known
	// to carry it (and ::/0 for a full tunnel).
	ula := apply.ULAPrefixAt(s.ulaStatePath(), cfg)
	name = pyStripped(name)
	peer := cmdMap("name", name, "public_key", publicKey, "address", address)
	if privateKey != "" && ula != nil {
		peer.Set("dual_stack", true)
	}
	section, ok := field(raw, "wireguard").(*config.Map)
	if !ok {
		return nil, errInternal
	}
	peersV := setdefault(section, "peers", []config.Value{})
	peers, ok := peersV.([]config.Value)
	if !ok {
		return nil, errInternal // .append on anything else
	}
	section.Set("peers", append(peers, peer))
	saved, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !saved {
		return errorRedirect("/vpn", message), nil
	}
	s.auditAlert(fmt.Sprintf("new VPN device %s added by %s", config.Repr(name), config.Repr(q.user.Username)),
		entry("user", q.user.Username, "client", q.clientIP()))
	if privateKey == "" {
		return successRedirect("/vpn", fmt.Sprintf("VPN device %s added -- click Apply to load it", config.Repr(name))), nil
	}
	after, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	text, err := clientConfig(after, privateKey, address, routerKey, full, ula)
	if err != nil {
		return nil, err
	}
	svg, err := qrSVGOf(text, 4, "#0C141F", "#FFFFFF")
	if err != nil {
		return nil, err
	}
	a, err := s.render(q, "vpn_peer", &page{Username: q.user.Username,
		Data: vpnPeerData{Name: name, ConfigText: text, QR: svg}})
	if err != nil {
		return nil, err
	}
	// The device's private key is on this page and nowhere else.
	a.header("cache-control", "no-store")
	return a, nil
}

func (s *Server) removeVPNPeer(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	name := q.params["peer_name"]
	section, err := setdefaultMap(raw, "wireguard")
	if err != nil {
		return nil, err
	}
	peers, err := vpnPeers(raw)
	if err != nil {
		return nil, err
	}
	remaining := []*config.Map{}
	for _, p := range peers {
		if !strEq(field(p, "name"), name) {
			remaining = append(remaining, p)
		}
	}
	if len(remaining) == len(peers) {
		return errorRedirect("/vpn", fmt.Sprintf("No such VPN device %s", config.Repr(name))), nil
	}
	section.Set("peers", values(remaining))
	return s.saved(raw, "/vpn", fmt.Sprintf("VPN device %s removed -- click Apply to cut it off", config.Repr(name)))
}
