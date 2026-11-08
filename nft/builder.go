// Package nft turns a checked config into an nftables ruleset in nft
// syntax: frfw.nft.builder in 1.x, held to its output byte for byte
// (AGENTS.md, "Differential tests").
//
// The script starts with `flush ruleset`, so loading it with `nft -f`
// replaces all nftables state: the config is the source of truth. Four
// sets hold runtime state by design (the brute-force jail, the IDS
// quarantine, signed-in ZTNA clients, isolated IoT devices). Their live
// members are read before a reload and passed in as RuntimeSets; they
// are written into the set declarations of the same script, so the flush
// and their return are one nft transaction and no banned or quarantined
// host is let through in between (1.x review FR-002).
package nft

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// Table is the one `inet` table that holds the filter and the NAT
// chains: `inet` takes `type nat` chains (nftables 0.9.7 and later), so
// the NAT rules use the same per-zone interface sets.
const Table = "fr_os"

// Set and chain names, as 1.x has them (frfw.nft.builder's constants say
// what each is for).
const (
	BruteforceJailSet    = "bruteforce_jail"
	BruteforceJail6Set   = "bruteforce_jail6"
	BruteforceJailMacSet = "bruteforce_jail_mac"
	IDSQuarantineSet     = "ids_quarantine"
	IDSQuarantineMacSet  = "ids_quarantine_mac"
	ZtnaSet              = "authenticated_ztna_users"
	ZtnaTunnelSet        = "authenticated_ztna_tunnel"
	Ztna6Set             = "authenticated_ztna_users6"
	ZtnaTunnel6Set       = "authenticated_ztna_tunnel6"
	IotIsolatedSet       = "iot_isolated"
	IPv6InputChain       = "ipv6_input"
)

// IotMDNSReplyPort is the local UDP port the IoT scanner sends its mDNS
// query from: a "legacy unicast" query (RFC 6762 6.7), answered straight
// back to it, so the input chain opens only this port, and only for
// replies from 5353.
const IotMDNSReplyPort = 53530

// WireguardIface is the VPN's interface (frfw.wireguard.IFACE).
const WireguardIface = "wg0"

// ManagementPorts are sshd's and the webUI's (frfw.management).
var ManagementPorts = []int{22, 443}

// DropLogPrefix starts the default-deny drop log lines (security-lessons
// K6); the firewall log reader finds them by it.
const DropLogPrefix = "fr_os/drop/"

// Timed is a member of a timed set carried over a reload: an address
// (or a network, or a MAC) and the seconds it has left.
type Timed struct {
	Member string
	Left   int64
}

// ZtnaSession is a signed-in ZTNA client: its address, its MAC ("" for a
// WireGuard client) and the seconds left.
type ZtnaSession struct {
	IP, MAC string
	Left    int64
}

// RuntimeSets are the members to carry into a new ruleset. ZTNA sessions
// and isolated devices only while their feature is on.
type RuntimeSets struct {
	BruteforceJail    []Timed
	BruteforceJail6   []Timed // an address, or a /64 from before FND-1d
	BruteforceJailMac []Timed
	IDSQuarantine     []Timed
	IDSQuarantineMac  []Timed
	Ztna              []ZtnaSession
	IotIsolated       []string
}

// Options are what Build takes besides the config.
type Options struct {
	// Clock only matters for rules with a schedule; nil is the current
	// one of the config's timezone (CurrentClock).
	Clock *Clock
	// Now decides which temporary rules have expired; zero is now.
	Now     time.Time
	Runtime *RuntimeSets
}

// errBuild carries a refusal out of the renderers.
type errBuild struct{ error }

func fail(format string, args ...any) { panic(errBuild{fmt.Errorf(format, args...)}) }

// Build renders c as one nft script, to be loaded with TZ=UTC: scheduled
// rules carry UTC hours. An error means a runtime member that isn't what
// its set holds (1.x raises there too).
func Build(c *config.Config, opts Options) (script string, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(errBuild)
			if !ok {
				panic(r)
			}
			err = e.error
		}
	}()
	b := &builder{c: c, now: opts.Now}
	if b.now.IsZero() {
		b.now = time.Now()
	}
	if opts.Runtime != nil {
		b.runtime = *opts.Runtime
	}
	b.clock = opts.Clock
	if b.clock == nil && slices.ContainsFunc(c.Rules, func(r config.Rule) bool { return r.Schedule != nil }) {
		clock, err := CurrentClock(c.Timezone, b.now)
		if err != nil {
			return "", err
		}
		b.clock = &clock
	}
	return b.build(), nil
}

type builder struct {
	c       *config.Config
	clock   *Clock
	now     time.Time
	runtime RuntimeSets
	lines   []string
}

func (b *builder) add(lines ...string) { b.lines = append(b.lines, lines...) }

// rules adds lines as rules of a chain: two tabs in.
func (b *builder) rules(lines ...string) {
	for _, l := range lines {
		b.lines = append(b.lines, "\t\t"+l)
	}
}

func (b *builder) build() string {
	c := b.c
	zoneDevices := b.zoneDevices()
	b.add("flush ruleset", "", "table inet "+Table+" {")

	zones := make([]string, 0, len(zoneDevices))
	for z := range zoneDevices {
		zones = append(zones, z)
	}
	slices.Sort(zones)
	for _, z := range zones {
		b.add(ifaceSet(z, zoneDevices[z])...)
	}

	b.add("")
	b.add(timedSet(BruteforceJailSet, "ipv4_addr", "timeout", ipv4Elements(b.runtime.BruteforceJail))...)
	b.add(b.bruteforceJail6Set()...)
	b.add(timedSet(BruteforceJailMacSet, "ether_addr", "timeout", macElements(b.runtime.BruteforceJailMac))...)

	b.add("")
	b.add(timedSet(IDSQuarantineSet, "ipv4_addr", "timeout", ipv4Elements(b.runtime.IDSQuarantine))...)
	b.add(timedSet(IDSQuarantineMacSet, "ether_addr", "timeout", macElements(b.runtime.IDSQuarantineMac))...)

	// Declared even while ZTNA is off, empty: a require_ztna rule then
	// matches nothing (fails closed) instead of naming a set that isn't
	// there, which made the whole ruleset fail to load.
	b.add("")
	var sessions []ZtnaSession
	if c.Ztna.Enabled {
		sessions = b.runtime.Ztna
	}
	b.add(b.ztnaSets(sessions)...)

	if c.Iot.Enabled {
		b.add("")
		b.add(iotIsolatedSet(b.runtime.IotIsolated)...)
	}

	cuts := func(r *config.Rule) bool { return r.Schedule != nil && r.Schedule.CutEstablished }
	// Security-lessons K2: a temporary rule past its expiry is left out.
	var inputCut, forwardCut, inputRules, forwardRules []*config.Rule
	for _, r := range b.activeRules() {
		switch toSelf := r.ToZone == config.SelfZone; {
		case toSelf && cuts(r):
			inputCut = append(inputCut, r)
		case cuts(r):
			forwardCut = append(forwardCut, r)
		case toSelf:
			inputRules = append(inputRules, r)
		default:
			forwardRules = append(forwardRules, r)
		}
	}

	b.add("", "\tchain input {", "\t\ttype filter hook input priority filter; policy drop;", "")
	// First of all, before even the loopback accept: a jailed or
	// quarantined source is dropped before any other rule can match it.
	b.rules(
		"ip saddr @"+BruteforceJailSet+" drop "+comment("bruteforce-jail"),
		"ip saddr @"+IDSQuarantineSet+" drop "+comment("ids-quarantine"),
		// FND-1c/1d: the same two over IPv6, the jail by MAC (or the
		// address), a quarantined host by its MAC.
		"ip6 saddr @"+BruteforceJail6Set+" tcp dport { "+managementPorts()+" } drop "+comment("bruteforce-jail6"),
		"ether saddr @"+BruteforceJailMacSet+" tcp dport { "+managementPorts()+" } drop "+comment("bruteforce-jail-mac"),
		idsQuarantineMacForwardRule(),
	)
	if c.Iot.Enabled {
		// Ahead of the established accept: an isolated device's open
		// sessions to the router end the moment it is isolated.
		b.rules(b.iotInputRules()...)
	}
	b.rules(`iifname "lo" accept`)
	// FND-1a/1b: what the WAN's and the LAN's IPv6 need, ahead of the
	// established accept (neighbour discovery and RAs aren't tracked).
	b.rules(b.ipv6WanInput()...)
	b.rules(b.ipv6LanInput()...)
	// Phase 17: scheduled drop/reject rules with cut_established go ahead
	// of the established accept, so a connection opened before the window
	// is cut when it starts.
	for _, r := range inputCut {
		b.rules(b.renderRule(r)...)
	}
	b.rules("ct state established,related accept", "ct state invalid drop")
	// Every IPv6 packet to the router, before any rule below: those were
	// written for IPv4 (the jail, the quarantine and ZTNA hold IPv4
	// addresses) and would match IPv6 too.
	b.rules(b.ipv6InputJump()...)
	dnsZones := b.dnsResolverZones()
	for _, z := range dnsZones {
		for _, proto := range []string{"udp", "tcp"} {
			b.rules("iifname @" + ifaceSetName(z) + " " + proto + " dport 53 accept " + comment("dns-resolver"))
		}
	}
	// Security-lessons F2/G4: the webUI and SSH only from the management
	// zones, ahead of every admin rule, so "allow 443 from wan" can't
	// open them to the internet; management.allow_wan is the one way.
	for _, z := range b.blockedZones() {
		if len(zoneDevices[z]) > 0 {
			b.rules("iifname @" + ifaceSetName(z) + " tcp dport { " + managementPorts() + " } drop " +
				comment("no-management-from-"+z))
		}
	}
	if c.Wireguard.Enabled {
		// From anywhere: WireGuard answers nothing to a packet that isn't
		// from a known key, so the port looks closed.
		b.rules(fmt.Sprintf("udp dport %d accept %s", c.Wireguard.ListenPort, comment("wireguard")))
	}
	if len(inputRules) > 0 {
		b.add("")
		for _, r := range inputRules {
			b.rules(b.renderRule(r)...)
		}
	}
	b.add(b.dropLog("input")...)
	b.add("\t}")

	if c.IPv6.Enabled {
		b.add("", "\tchain "+IPv6InputChain+" {")
		b.rules(b.ipv6InputChain()...)
		b.add("\t}")
	}

	b.add("", "\tchain forward {", "\t\ttype filter hook forward priority filter; policy drop;", "")
	// FND-1b: IPv6 only between the WAN and the LAN zones that have it,
	// from a LAN host's own network; with no such zone, not at all.
	b.rules(b.ipv6ForwardGuard()...)
	// FND-1c: unique local addresses never cross the border (RFC 4193).
	b.rules(b.ulaBorder()...)
	// A quarantined host is cut off from what it reaches through the
	// router too, ahead of the established accept.
	b.rules("ip saddr @"+IDSQuarantineSet+" drop "+comment("ids-quarantine-forward"), idsQuarantineMacForwardRule())
	if quic := b.sniFilterQUICReject(); quic != "" {
		b.rules(quic)
	}
	if c.Iot.Enabled {
		// Before every config rule: an admin rule can't reopen an
		// isolated device; iot.trusted_macs is the one exemption.
		b.rules(b.iotForwardRules()...)
	}
	for _, r := range forwardCut {
		b.rules(b.renderRule(r)...)
	}
	b.rules("ct state established,related accept", "ct state invalid drop")
	// FND-1b: nothing new from the internet to the LAN over IPv6; a
	// pinhole (FND-1c) is the one way in, so it goes just ahead.
	b.rules(b.ipv6Pinholes()...)
	b.rules(b.ipv6NoInbound()...)
	if c.Adblocker.Enabled && c.Adblocker.ForceDNS {
		// DNS over TLS and over QUIC would get around the resolver;
		// rejected, so a client trying it opportunistically falls back at
		// once.
		for _, z := range dnsZones {
			for _, proto := range []string{"tcp", "udp"} {
				b.rules("iifname @" + ifaceSetName(z) + " " + proto + " dport 853 reject " + comment("force-dns-block-dot"))
			}
		}
	}
	if len(forwardRules) > 0 {
		b.add("")
		for _, r := range forwardRules {
			b.rules(b.renderRule(r)...)
		}
	}
	b.add(b.dropLog("forward")...)
	b.add("\t}")

	b.add("", "\tchain output {", "\t\ttype filter hook output priority filter; policy accept;", "\t}")

	forceDNS := c.Adblocker.Enabled && c.Adblocker.ForceDNS
	if len(c.Nat.Masquerade) > 0 || len(c.Nat.PortForwards) > 0 || forceDNS {
		b.add("")
		var zones []string
		if forceDNS {
			zones = dnsZones
		}
		b.natChains(zones)
	}

	b.add("}", "")
	return strings.Join(b.lines, "\n")
}

// activeRules are the rules a ruleset built now holds: all but expired
// ones.
func (b *builder) activeRules() []*config.Rule {
	// expires > now: now.Unix() is its whole seconds, and an expiry is
	// whole seconds too.
	now := b.now.Unix()
	var out []*config.Rule
	for i := range b.c.Rules {
		if r := &b.c.Rules[i]; r.Expires == nil || *r.Expires > now {
			out = append(out, r)
		}
	}
	return out
}

func (b *builder) dropLog(chain string) []string {
	if !b.c.Logging.Drops {
		return nil
	}
	rate := b.c.Logging.DropsPerMinute
	return []string{"", fmt.Sprintf(`		limit rate %d/minute burst %d packets log prefix "%s%s: " %s`,
		rate, rate, DropLogPrefix, chain, comment("log-default-drop"))}
}

// icmpv6Errors are the ICMPv6 errors a host needs (RFC 4890 4.4.1).
const icmpv6Errors = "destination-unreachable, packet-too-big, time-exceeded, parameter-problem"

// ipv6WanInput is what the WAN's IPv6 needs (FND-1a), on its interfaces
// only: neighbour discovery and the provider's RA with hop limit 255 (no
// router forwarded it, RFC 4861), the upstream router's MLD queries,
// ICMPv6 errors, a rate-limited ping and DHCPv6 replies. A LAN must never
// configure the router.
func (b *builder) ipv6WanInput() []string {
	if !b.c.IPv6.Enabled {
		return nil
	}
	devices := b.wanDevices()
	if len(devices) == 0 {
		return nil
	}
	wan := "iifname " + devicesSet(devices)
	return []string{
		wan + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept " + comment("ipv6-nd"),
		wan + " ip6 saddr fe80::/10 icmpv6 type nd-router-advert ip6 hoplimit 255 accept " + comment("ipv6-ra"),
		wan + " ip6 saddr fe80::/10 icmpv6 type mld-listener-query ip6 hoplimit 1 accept " + comment("ipv6-mld"),
		wan + " icmpv6 type { " + icmpv6Errors + " } accept " + comment("ipv6-errors"),
		wan + " icmpv6 type echo-request limit rate 5/second burst 10 packets accept " + comment("ipv6-ping"),
		wan + " ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept " + comment("ipv6-dhcpv6-client"),
	}
}

// ipv6InputJump: IPv6 off, every IPv6 packet to the router is dropped
// (a VPN client's refused, FND-1d, so it tries IPv4 at once); on, it
// goes through the ipv6_input chain.
func (b *builder) ipv6InputJump() []string {
	if !b.c.IPv6.Enabled {
		return append(b.vpnIPv6Refused("ipv6-vpn-off"), "meta nfproto ipv6 drop "+comment("ipv6-off"))
	}
	return []string{"meta nfproto ipv6 jump " + IPv6InputChain}
}

// vpnIPv6Refused: a VPN client's IPv6, refused with "administratively
// prohibited" (FND-1d), so its apps fall back to IPv4 through the tunnel
// at once.
func (b *builder) vpnIPv6Refused(name string) []string {
	if !b.c.Wireguard.Enabled {
		return nil
	}
	return []string{`iifname "` + WireguardIface + `" meta nfproto ipv6 reject with icmpv6 type admin-prohibited ` + comment(name)}
}

// ipv6InputChain is what the router serves over IPv6 (FND-1c), then the
// drop of the rest: DNS from the resolver's LAN devices; with
// management.ipv6 the webUI and SSH from the management zones' LAN
// devices, to the router's ULA address on that device, `return`ed to
// meet the management drop and the admin's rules as IPv4 does;
// WireGuard from the WAN; a ping from the tunnel while the router routes
// its IPv6 (FND-1d).
func (b *builder) ipv6InputChain() []string {
	var lines []string
	served := map[string]bool{}
	for _, z := range b.dnsResolverZones() {
		served[z] = true
	}
	var dns []string
	for _, zd := range b.lanDevices() {
		if served[zd.zone] {
			dns = append(dns, zd.device)
		}
	}
	if len(dns) > 0 {
		lines = append(lines, "iifname "+devicesSet(dns)+" meta l4proto { tcp, udp } th dport 53 accept "+comment("ipv6-dns"))
	}
	if managed := b.ipv6ManagementDevices(); len(managed) > 0 {
		lines = append(lines, "iifname "+devicesSet(managed)+" ip6 daddr fc00::/7 fib daddr . iif type local "+
			"tcp dport { "+managementPorts()+" } return "+comment("ipv6-management"))
	}
	if wan := b.wanDevices(); b.c.Wireguard.Enabled && len(wan) > 0 {
		lines = append(lines, fmt.Sprintf("iifname %s udp dport %d accept %s", devicesSet(wan), b.c.Wireguard.ListenPort,
			comment("ipv6-wireguard")))
	}
	if b.tunnelServed() {
		lines = append(lines, `iifname "`+WireguardIface+`" icmpv6 type echo-request limit rate 5/second burst 10 packets `+
			"accept "+comment("ipv6-vpn-ping"))
	}
	lines = append(lines, b.vpnIPv6Refused("ipv6-vpn-not-served")...)
	return append(lines, b.ipv6InputDrop()...)
}

// ipv6ManagementDevices are the LAN devices management is reachable on
// over IPv6: those of the management zones, with management.ipv6 only.
func (b *builder) ipv6ManagementDevices() []string {
	if !b.c.Management.IPv6 {
		return nil
	}
	zones := b.c.ManagementZones()
	var out []string
	for _, zd := range b.lanDevices() {
		if zones[zd.zone] {
			out = append(out, zd.device)
		}
	}
	return out
}

// ipv6InputDrop: every other IPv6 packet to the router is dropped; a
// unicast one is logged (K6), multicast chatter is not, so it can't use
// up the log's rate.
func (b *builder) ipv6InputDrop() []string {
	lines := []string{"meta nfproto ipv6 meta pkttype != host drop " + comment("ipv6-not-for-the-router")}
	if b.c.Logging.Drops {
		rate := b.c.Logging.DropsPerMinute
		lines = append(lines, fmt.Sprintf(`meta nfproto ipv6 limit rate %d/minute burst %d packets log prefix "%sinput: " %s`,
			rate, rate, DropLogPrefix, comment("log-ipv6-drop")))
	}
	return append(lines, "meta nfproto ipv6 drop "+comment("ipv6-default-drop"))
}

// ipv6LanInput is what the LAN's IPv6 needs from the router (FND-1b), on
// the LAN zones' devices only: neighbour discovery and router
// solicitations with hop limit 255, and a rate-limited ping.
func (b *builder) ipv6LanInput() []string {
	devices := b.ipv6LanDevices()
	if len(devices) == 0 {
		return nil
	}
	lan := "iifname " + devicesSet(devices)
	return []string{
		lan + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } ip6 hoplimit 255 accept " +
			comment("ipv6-lan-nd"),
		lan + " icmpv6 type echo-request limit rate 5/second burst 10 packets accept " + comment("ipv6-lan-ping"),
	}
}

// ipv6ForwardGuard is first in the forward chain. With no LAN zone
// getting IPv6 nothing is routed over it. Else only between the WAN's
// and those zones' devices, and from a LAN host only from an address the
// router routes back to that device (BCP 38). The VPN tunnel (FND-1d)
// ahead of that: its clients' IPv6 reaches the LAN's ULA networks only,
// while the router routes IPv6 for the tunnel; the rest is refused at
// once, never let around the tunnel (H1).
func (b *builder) ipv6ForwardGuard() []string {
	lan := b.ipv6LanDevices()
	routesTunnel := len(lan) > 0 && b.c.Wireguard.Enabled && b.tunnelServed()
	var vpn []string
	if b.c.Wireguard.Enabled {
		if routesTunnel {
			tunnel := `"` + WireguardIface + `" meta nfproto ipv6`
			vpn = []string{
				"iifname " + tunnel + " ip6 daddr != fc00::/7 reject with icmpv6 type admin-prohibited " + comment("ipv6-vpn-ula-only"),
				"oifname " + tunnel + " ip6 saddr != fc00::/7 drop " + comment("ipv6-vpn-ula-only"),
			}
		} else {
			vpn = b.vpnIPv6Refused("ipv6-vpn-not-routed")
		}
	}
	if len(lan) == 0 {
		return append(vpn, "meta nfproto ipv6 drop "+comment("ipv6-no-routing"))
	}
	wan := b.wanDevices()
	routedList := slices.Clone(wan)
	for _, d := range lan {
		if !slices.Contains(wan, d) {
			routedList = append(routedList, d)
		}
	}
	if routesTunnel {
		routedList = append(routedList, WireguardIface)
	}
	routed := devicesSet(routedList)
	out := append(vpn,
		"meta nfproto ipv6 iifname != "+routed+" drop "+comment("ipv6-not-routed-here"),
		"meta nfproto ipv6 oifname != "+routed+" drop "+comment("ipv6-not-routed-here"),
		"meta nfproto ipv6 iifname "+devicesSet(lan)+" fib saddr . iif oif missing drop "+comment("ipv6-lan-spoofed"),
	)
	return append(out, lanSourceFromWan(wan, lan)...)
}

// lanSourceFromWan: from the internet, a source the router routes to a
// LAN device is spoofed (FND-1d), so a pinhole can't make a LAN host look
// like it opened connections it never did.
func lanSourceFromWan(wan, lan []string) []string {
	var inside []string
	for _, d := range lan {
		if !slices.Contains(wan, d) {
			inside = append(inside, d)
		}
	}
	if len(inside) == 0 {
		return nil
	}
	return []string{"meta nfproto ipv6 iifname " + devicesSet(wan) + " fib saddr oifname " + devicesSet(inside) + " drop " +
		comment("ipv6-lan-source-from-wan")}
}

// ipv6NoInbound: after the established accept, a new connection from
// the internet to the LAN over IPv6 is dropped, ahead of every admin
// rule, and logged like a default-deny drop.
func (b *builder) ipv6NoInbound() []string {
	if len(b.ipv6LanDevices()) == 0 {
		return nil
	}
	wan := "meta nfproto ipv6 iifname " + devicesSet(b.wanDevices())
	var lines []string
	if b.c.Logging.Drops {
		rate := b.c.Logging.DropsPerMinute
		lines = append(lines, fmt.Sprintf(`%s limit rate %d/minute burst %d packets log prefix "%sforward: " %s`,
			wan, rate, rate, DropLogPrefix, comment("log-ipv6-inbound")))
	}
	return append(lines, wan+" drop "+comment("ipv6-no-inbound"))
}

// ulaBorder: RFC 4193 4.3, unique local addresses are filtered at the
// border; from the internet dropped, to it refused so a LAN host gives up
// at once.
func (b *builder) ulaBorder() []string {
	if len(b.ipv6LanDevices()) == 0 {
		return nil
	}
	wan := devicesSet(b.wanDevices())
	return []string{
		"iifname " + wan + " ip6 saddr fc00::/7 drop " + comment("ipv6-ula-from-internet"),
		"iifname " + wan + " ip6 daddr fc00::/7 drop " + comment("ipv6-ula-from-internet"),
		"oifname " + wan + " ip6 saddr fc00::/7 reject with icmpv6 type admin-prohibited " + comment("ipv6-ula-to-internet"),
		"oifname " + wan + " ip6 daddr fc00::/7 reject with icmpv6 type admin-prohibited " + comment("ipv6-ula-to-internet"),
	}
}

// iidMask is the low 64 bits of an IPv6 address: the interface
// identifier a suffix pinhole matches in whatever prefix its zone has.
const iidMask = "::ffff:ffff:ffff:ffff"

// ipv6Pinholes (FND-1c): new connections from the internet to one LAN
// host's port, the only exceptions to the drop that follows. A zone
// without IPv6 now gets none.
func (b *builder) ipv6Pinholes() []string {
	served := map[string]bool{}
	for _, zd := range b.lanDevices() {
		served[zd.zone] = true
	}
	if len(served) == 0 || len(b.c.IPv6.Pinholes) == 0 {
		return nil
	}
	wan := devicesSet(b.wanDevices())
	var lines []string
	for i := range b.c.IPv6.Pinholes {
		p := &b.c.IPv6.Pinholes[i]
		if !served[p.Zone] {
			continue
		}
		exprs := []string{"meta nfproto ipv6 iifname " + wan + " oifname @" + ifaceSetName(p.Zone)}
		if p.Source != "" {
			exprs = append(exprs, "ip6 saddr "+p.Source)
		}
		if p.IsSuffix() {
			exprs = append(exprs, "ip6 daddr & "+iidMask+" == "+p.Host)
		} else {
			exprs = append(exprs, "ip6 daddr "+p.Host)
		}
		exprs = append(exprs, string(p.Proto)+" dport "+p.Port(), "counter accept "+comment("pinhole:"+p.Name))
		lines = append(lines, strings.Join(exprs, " "))
	}
	return lines
}

// zoneDevices are each zone's devices; the tunnel is an interface of its
// zone (security-lessons G8).
func (b *builder) zoneDevices() map[string][]string {
	zones := map[string][]string{}
	for _, z := range b.c.Zones.Keys {
		zones[z] = []string{}
	}
	for _, i := range b.c.Interfaces.Values() {
		zones[i.Zone] = append(zones[i.Zone], i.Device)
	}
	if b.c.Wireguard.Enabled {
		zones[b.c.Wireguard.Zone] = append(zones[b.c.Wireguard.Zone], WireguardIface)
	}
	return zones
}

func ifaceSetName(zone string) string { return zone + "_ifaces" }

func ifaceSet(zone string, devices []string) []string {
	out := []string{"\tset " + ifaceSetName(zone) + " {", "\t\ttype ifname"}
	// A zone kept for a tunnel that is off has no interface yet.
	if len(devices) > 0 {
		quoted := make([]string, len(devices))
		for i, d := range devices {
			quoted[i] = `"` + d + `"`
		}
		out = append(out, "\t\telements = { "+strings.Join(quoted, ", ")+" }")
	}
	return append(out, "\t}")
}

func devicesSet(devices []string) string {
	quoted := make([]string, len(devices))
	for i, d := range devices {
		quoted[i] = `"` + d + `"`
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func managementPorts() string {
	ports := make([]string, len(ManagementPorts))
	for i, p := range ManagementPorts {
		ports[i] = strconv.Itoa(p)
	}
	return strings.Join(ports, ", ")
}

// timedSet declares a set with per-element timeouts and no set-level
// default: each element carries its own.
func timedSet(name, kind, flags string, items []string) []string {
	out := []string{"\tset " + name + " {", "\t\ttype " + kind, "\t\tflags " + flags}
	if len(items) > 0 {
		out = append(out, "\t\telements = { "+strings.Join(items, ", ")+" }")
	}
	return append(out, "\t}")
}

// ipv4Elements are the live members of an IPv4 set, each address checked
// again (it comes from `nft -j` output).
func ipv4Elements(members []Timed) []string {
	var items []string
	for _, m := range members {
		if m.Left <= 0 {
			continue
		}
		ip, err := config.IPv4Address(m.Member)
		if err != nil {
			fail("%v", err)
		}
		items = append(items, fmt.Sprintf("%s timeout %ds", ip, m.Left))
	}
	return items
}

var macRE = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func macElements(members []Timed) []string {
	var items []string
	for _, m := range members {
		if macRE.MatchString(m.Member) && m.Left > 0 {
			items = append(items, fmt.Sprintf("%s timeout %ds", m.Member, m.Left))
		}
	}
	return items
}

// bruteforceJail6Set holds addresses, or a /64 from before FND-1d, each
// with its own timeout.
func (b *builder) bruteforceJail6Set() []string {
	type member struct {
		net  config.IPv6Network
		left int64
	}
	var live []member
	for _, m := range b.runtime.BruteforceJail6 {
		if m.Left <= 0 {
			continue
		}
		n, err := config.ParseIPv6Network(m.Member)
		if err != nil {
			fail("%v", err)
		}
		live = append(live, member{n, m.Left})
	}
	// An address inside a carried-over /64 would make nft refuse the
	// whole ruleset ("conflicting intervals"); the /64 holds it anyway.
	var items []string
	for _, m := range live {
		inside := slices.ContainsFunc(live, func(o member) bool { return !o.net.Equal(m.net) && m.net.SubnetOf(o.net) })
		if inside {
			continue
		}
		text := m.net.String()
		if m.net.Prefix() == 128 {
			text = m.net.Address()
		}
		items = append(items, fmt.Sprintf("%s timeout %ds", text, m.left))
	}
	return timedSet(BruteforceJail6Set, "ipv6_addr", "interval, timeout", items)
}

func idsQuarantineMacForwardRule() string {
	// IPv6 only: the IPv4 rule already holds the host by address.
	return "meta nfproto ipv6 ether saddr @" + IDSQuarantineMacSet + " drop " + comment("ids-quarantine-ipv6")
}

// ztnaSets: membership is runtime state only (a sign-in adds it); the
// only elements here are the sessions carried over a reload.
func (b *builder) ztnaSets(sessions []ZtnaSession) []string {
	items := map[string][]string{}
	for _, s := range sessions {
		if s.Left <= 0 {
			continue
		}
		ip, version, err := config.IPAddress(s.IP) // checked again: it comes from `nft -j` output
		if err != nil {
			continue
		}
		v6 := version == 6
		switch {
		case s.MAC != "":
			if !macRE.MatchString(s.MAC) {
				continue
			}
			name := ZtnaSet
			if v6 {
				name = Ztna6Set
			}
			items[name] = append(items[name], fmt.Sprintf("%s . %s timeout %ds", ip, s.MAC, s.Left))
		default:
			name := ZtnaTunnelSet
			if v6 {
				name = ZtnaTunnel6Set
			}
			items[name] = append(items[name], fmt.Sprintf("%s timeout %ds", ip, s.Left))
		}
	}
	var out []string
	for _, set := range [][2]string{
		{ZtnaSet, "ipv4_addr . ether_addr"}, {ZtnaTunnelSet, "ipv4_addr"},
		{Ztna6Set, "ipv6_addr . ether_addr"}, {ZtnaTunnel6Set, "ipv6_addr"},
	} {
		out = append(out, "\tset "+set[0]+" {", "\t\ttype "+set[1], "\t\tflags dynamic,timeout",
			fmt.Sprintf("\t\ttimeout %ds", b.c.Ztna.SessionTTLSeconds))
		if len(items[set[0]]) > 0 {
			out = append(out, "\t\telements = { "+strings.Join(items[set[0]], ", ")+" }")
		}
		out = append(out, "\t}")
	}
	return out
}

// ztnaMatches: what a require_ztna rule matches, one line each (ROADMAP
// SEC-6): a device on the router's networks by address and MAC, or a
// WireGuard client by its tunnel address on the tunnel only.
var ztnaMatches = []struct {
	family int
	match  string
}{
	{4, "ip saddr . ether saddr @" + ZtnaSet},
	{4, `iifname "` + WireguardIface + `" ip saddr @` + ZtnaTunnelSet},
	{6, "ip6 saddr . ether saddr @" + Ztna6Set},
	{6, `iifname "` + WireguardIface + `" ip6 saddr @` + ZtnaTunnel6Set},
}

// iotIsolatedSet: MACs, so a DHCP renewal can't let a device out; no
// timeout, membership is recomputed on every scan.
func iotIsolatedSet(members []string) []string {
	var macs []string
	for _, m := range members {
		if macRE.MatchString(m) {
			macs = append(macs, m)
		}
	}
	out := []string{"\tset " + IotIsolatedSet + " {", "\t\ttype ether_addr"}
	if len(macs) > 0 {
		out = append(out, "\t\telements = { "+strings.Join(macs, ", ")+" }")
	}
	return append(out, "\t}")
}

func (b *builder) iotInputRules() []string {
	var rules []string
	for _, z := range b.c.Iot.Zones {
		rules = append(rules, fmt.Sprintf("iifname @%s udp sport 5353 udp dport %d accept %s",
			ifaceSetName(z), IotMDNSReplyPort, comment("iot-mdns-replies")))
	}
	isolated := "ether saddr @" + IotIsolatedSet
	return append(rules,
		isolated+" udp dport { 53, 67 } accept "+comment("iot-isolated-dhcp-dns"),
		isolated+" tcp dport 53 accept "+comment("iot-isolated-dns-tcp"),
		isolated+" drop "+comment("iot-isolated-input"),
	)
}

func (b *builder) iotForwardRules() []string {
	isolated := "ether saddr @" + IotIsolatedSet
	var rules []string
	if b.c.Iot.IsolationMode == config.IotInternetOnly {
		var zones []string
		for _, m := range b.c.Nat.Masquerade {
			if !slices.Contains(zones, m.OutZone) {
				zones = append(zones, m.OutZone)
			}
		}
		slices.Sort(zones)
		for _, z := range zones {
			rules = append(rules, isolated+" oifname @"+ifaceSetName(z)+" accept "+comment("iot-isolated-internet"))
		}
	}
	return append(rules, isolated+" drop "+comment("iot-isolated-forward"))
}

// SNIFilteredDevices are the devices whose clients the XDP SNI filter
// covers: those of xdp_sni_filter.interfaces and the VLAN segments on
// them (ROADMAP SEC-16). Empty while the filter is off.
func SNIFilteredDevices(c *config.Config) []string {
	sni := c.XdpSniFilter
	if !sni.Enabled {
		return nil
	}
	ports := map[string]bool{}
	for _, name := range sni.Interfaces {
		if i, ok := c.Interfaces.Get(name); ok {
			ports[i.Device] = true
		}
	}
	all := map[string]bool{}
	for d := range ports {
		all[d] = true
	}
	for _, i := range c.Interfaces.Values() {
		if i.VlanParent != "" && ports[i.VlanParent] {
			all[i.Device] = true
		}
	}
	out := make([]string, 0, len(all))
	for d := range all {
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// sniFilterQUICReject (ROADMAP SEC-1, review R8): QUIC carries its
// ClientHello encrypted, so while the filter is on UDP/443 from its
// devices is rejected and a browser falls back to TCP, where the name is
// visible. Ahead of the established accept, the IoT rules and every
// config rule.
func (b *builder) sniFilterQUICReject() string {
	devices := SNIFilteredDevices(b.c)
	if len(devices) == 0 {
		return ""
	}
	return "iifname " + devicesSet(devices) + " udp dport 443 reject " + comment("sni-filter-no-quic")
}

// comment is an nft comment; a double quote would end it.
func comment(text string) string {
	return `comment "` + strings.ReplaceAll(text, `"`, "'") + `"`
}

// renderRule is one nft line per rule; for a scheduled rule one per time
// segment, all with the same comment. A require_ztna rule is rendered
// once per way a client can be signed in (nft has no "or" between set
// lookups of different types), a rule by address once per family it
// names (FND-1d: `ip saddr` and `ip6 saddr` can't share a line).
func (b *builder) renderRule(r *config.Rule) []string {
	addressed := len(r.SrcAddress) > 0 || len(r.DstAddress) > 0
	if !addressed && !r.RequireZtna {
		return b.ruleLines(r, 0, "")
	}
	families := r.Families()
	var lines []string
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		matches := []string{""}
		if r.RequireZtna {
			matches = nil
			for _, m := range ztnaMatches {
				if m.family == family {
					matches = append(matches, m.match)
				}
			}
		}
		for _, m := range matches {
			f := 0
			if addressed {
				f = family
			}
			lines = append(lines, b.ruleLines(r, f, m)...)
		}
	}
	return lines
}

func addressMatch(networks []string) string {
	if len(networks) == 1 {
		return networks[0]
	}
	return "{ " + strings.Join(networks, ", ") + " }"
}

// ruleLines renders a rule for one family (0 for no address match) and
// one ZTNA match ("" for none).
func (b *builder) ruleLines(r *config.Rule, family int, ztnaMatch string) []string {
	var exprs []string
	if r.Expires != nil {
		// Security-lessons K2: the kernel itself stops matching a
		// temporary rule at its expiry (Unix time, so no time zone).
		exprs = append(exprs, fmt.Sprintf("meta time < %d", *r.Expires))
	}
	if r.FromZone != "" {
		exprs = append(exprs, "iifname @"+ifaceSetName(r.FromZone))
	}
	if r.ToZone != "" && r.ToZone != config.SelfZone {
		exprs = append(exprs, "oifname @"+ifaceSetName(r.ToZone))
	}
	if ztnaMatch != "" {
		exprs = append(exprs, ztnaMatch)
	}
	switch {
	case r.DstPort != "":
		exprs = append(exprs, string(r.Proto)+" dport "+r.DstPort)
	case r.Proto == config.ProtoICMP:
		// ICMP of either family (FND-1b): "icmp from lan" means ping and
		// its errors over IPv6 too.
		exprs = append(exprs, "meta l4proto { icmp, ipv6-icmp }")
	case r.Proto != config.ProtoAny:
		// Not `ip protocol`, which matches IPv4 only (FND-1b).
		exprs = append(exprs, "meta l4proto "+string(r.Proto))
	}
	if r.SrcMac != "" {
		exprs = append(exprs, "ether saddr "+r.SrcMac)
	}
	if family != 0 {
		keyword := "ip"
		if family == 6 {
			keyword = "ip6"
		}
		if nets := r.SrcNetworks(family); len(nets) > 0 {
			exprs = append(exprs, keyword+" saddr "+addressMatch(nets))
		}
		if nets := r.DstNetworks(family); len(nets) > 0 {
			exprs = append(exprs, keyword+" daddr "+addressMatch(nets))
		}
	}
	if r.Log {
		exprs = append(exprs, `log prefix "fr_os/`+r.Name+`: "`)
	}
	// Per-rule hit counters for the rule check (security-lessons K2).
	exprs = append(exprs, "counter", string(r.Action), comment("rule:"+r.Name))
	if r.Schedule == nil {
		return []string{strings.Join(exprs, " ")}
	}
	if b.clock == nil {
		fail("rule %q has a schedule but no clock was given", r.Name)
	}
	s := r.Schedule
	var lines []string
	for _, seg := range Segments(s.Days, s.Start, s.End, *b.clock) {
		if m := seg.render(); m != "" {
			lines = append(lines, m+" "+strings.Join(exprs, " "))
		} else {
			lines = append(lines, strings.Join(exprs, " "))
		}
	}
	return lines
}

// dnsResolverZones are the zones the ad-block resolver serves
// (adblocker.serve_lan): the DHCP zones.
func (b *builder) dnsResolverZones() []string {
	if !(b.c.Adblocker.Enabled && b.c.Adblocker.ServeLan) {
		return nil
	}
	return slices.Sorted(slices.Values(b.c.Dhcp.Zones.Keys))
}

func (b *builder) natChains(forceDNSZones []string) {
	b.add("\tchain prerouting {", "\t\ttype nat hook prerouting priority dstnat; policy accept;")
	if len(forceDNSZones) > 0 {
		// Any plain-DNS query from these zones is answered by the
		// router's own resolver; over IPv6 too where the zone has it
		// (FND-1c).
		b.add("")
		ipv6Zones := map[string]bool{}
		for _, zd := range b.lanDevices() {
			ipv6Zones[zd.zone] = true
		}
		for _, z := range forceDNSZones {
			families := []string{"ipv4"}
			if ipv6Zones[z] {
				families = append(families, "ipv6")
			}
			for _, family := range families {
				for _, proto := range []string{"udp", "tcp"} {
					b.rules("meta nfproto " + family + " iifname @" + ifaceSetName(z) + " " + proto + " dport 53 " +
						"redirect to :53 " + comment("force-dns"))
				}
			}
		}
	}
	if len(b.c.Nat.PortForwards) > 0 {
		b.add("")
		for _, pf := range b.c.Nat.PortForwards {
			// `dnat ip to`: in an inet table dnat must name the family;
			// port forwards are IPv4 only.
			b.rules(fmt.Sprintf("iifname @%s %s dport %d dnat ip to %s:%d %s", ifaceSetName(pf.InZone), pf.Proto,
				pf.DstPort, pf.ToAddress, pf.ToPort, comment("nat:portfwd:"+pf.Name)))
		}
	}
	b.add("\t}", "", "\tchain postrouting {", "\t\ttype nat hook postrouting priority srcnat; policy accept;")
	if len(b.c.Nat.Masquerade) > 0 {
		b.add("")
		for _, m := range b.c.Nat.Masquerade {
			// IPv4 only: in an inet table a bare masquerade takes IPv6
			// too, and IPv6 is never translated (ROADMAP FND-1).
			b.rules("meta nfproto ipv4 oifname @" + ifaceSetName(m.OutZone) + " masquerade " +
				comment("nat:masquerade:"+m.OutZone))
		}
	}
	b.add("\t}")
}

type zoneDevice struct{ zone, device string }

// wanDevices are the internet-facing interfaces' devices, where IPv6
// comes from (frfw.ipv6.wan_devices).
func (b *builder) wanDevices() []string {
	facing := b.c.InternetFacingZones()
	var out []string
	for _, i := range b.c.Interfaces.Values() {
		if facing[i.Zone] && !slices.Contains(out, i.Device) {
			out = append(out, i.Device)
		}
	}
	return out
}

// lanDevices are (zone, device) for every device the delegated prefix is
// handed to (frfw.ipv6.lan_devices, FND-1b): zone by zone in lan-zone
// order, then in config order. Not the VPN tunnel. Empty while IPv6 is
// off.
func (b *builder) lanDevices() []zoneDevice {
	var out []zoneDevice
	for _, z := range b.c.IPv6LanZones() {
		for _, i := range b.c.Interfaces.Values() {
			if i.Zone == z && !slices.ContainsFunc(out, func(zd zoneDevice) bool { return zd.device == i.Device }) {
				out = append(out, zoneDevice{z, i.Device})
			}
		}
	}
	return out
}

func (b *builder) ipv6LanDevices() []string {
	var out []string
	for _, zd := range b.lanDevices() {
		out = append(out, zd.device)
	}
	return out
}

// tunnelServed: the router routes IPv6 for the VPN's clients (FND-1d):
// WireGuard and IPv6 on, and the tunnel's zone not kept off IPv6 by an
// IPv4-only protection.
func (b *builder) tunnelServed() bool {
	wg := b.c.Wireguard
	if !(wg.Enabled && b.c.IPv6.Enabled) {
		return false
	}
	_, excluded := b.c.IPv6LanExclusions()[wg.Zone]
	return !excluded
}

// blockedZones are the zones whose management traffic the input chain
// drops (frfw.management.blocked_zones).
func (b *builder) blockedZones() []string {
	allowed := b.c.ManagementZones()
	var out []string
	for _, z := range b.c.Zones.Keys {
		if !allowed[z] {
			out = append(out, z)
		}
	}
	slices.Sort(out)
	return out
}
