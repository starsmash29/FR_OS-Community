// Package config checks a raw config.yaml and builds the Config the rest
// of FR_OS works from. It is the one place a value from the config is
// validated before it reaches an argv, an nft script or a config file
// (AGENTS.md, "Untrusted input").
//
// FR_OS 1.x's frfw.config.loader is the specification: Parse accepts and
// refuses what parse_config does, in the same order of checks, so the
// first problem reported is the same one; the tests replay every config
// 1.x's own test suite fed it (testdata/reference/config.jsonl).
package config

import (
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/appid"
)

// Error is a config that can't be used, and why, in words for the admin.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

// fail stops the check with an Error. The checks are a long series of
// "refuse if"; unwinding to Parse keeps each as one line, as in 1.x,
// instead of an error return on every helper.
func fail(format string, args ...any) {
	panic(&Error{fmt.Sprintf(format, args...)})
}

// Parse checks a raw config (the YAML document as a Value) and returns
// the Config, or an *Error.
func Parse(raw Value) (cfg *Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(*Error)
			if !ok {
				panic(r)
			}
			cfg, err = nil, e
		}
	}()
	return parseConfig(raw), nil
}

// Local is the zone a rule's `expires` is read in when the config has
// no timezone: the router's own. Tests set it.
var Local = time.Local

var (
	nameRE        = regexp.MustCompile(`\A[a-z][a-z0-9_-]*\z`)
	namePattern   = `^[a-z][a-z0-9_-]*\Z`
	macRE         = regexp.MustCompile(`\A([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\z`)
	ztnaUserRE    = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\z`)
	wgPeerNameRE  = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.-]{0,31}\z`)
	ifnameRE      = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\z`)
	repoRE        = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9._-]{0,99}\z`)
	hhmmRE        = regexp.MustCompile(`\A(([01][0-9]|2[0-3]):([0-5][0-9])|24:00)\z`)
	ja4RE         = regexp.MustCompile(`\A[tqd][0-9ds][0-9d][di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}\z`)
	ja3RE         = regexp.MustCompile(`\A[0-9a-f]{32}\z`)
	siteRE        = regexp.MustCompile(`\A[a-z0-9][a-z0-9_.-]{0,62}\z`)
	tokenSHA256RE = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

const (
	supportedVersion = 1
	ztnaMinTTL       = 60
	ztnaMaxTTL       = 30 * 24 * 3600
	// maxSNILen must match the XDP program's MAX_SNI_LEN: a name this
	// long or longer never matches there (it fails open), so it is
	// refused here instead.
	maxSNILen          = 32
	maxQuarantine      = 7 * 24 * 3600
	confirmApplyMin    = 60
	confirmApplyMax    = 3600
	confirmApplyDef    = 300
	pinholeMaxPorts    = 1000
	localDNSMaxEntries = 1024
)

// hostLabel is one label of an RFC 1123 host name: 1-63 letters, digits
// and hyphens, not starting or ending with a hyphen.
func hostLabel(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// dottedHostname is 1.x's _HOSTNAME_RE: labels joined by dots. (1.x
// ends that pattern with `$`, which also lets one trailing newline
// through; see testdata/reference/decisions.md.)
func dottedHostname(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if !hostLabel(label) {
			return false
		}
	}
	return true
}

// Validators of frfw.validate, for values that become arguments
// (security-lessons F1). They return the message 1.x's ArgumentError has.

func typeName(v Value) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []Value:
		return "list"
	case *Map:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

func validateIfname(v Value) (string, string) {
	s, ok := v.(string)
	if !ok {
		return "", "interface name must be a string, got " + typeName(v)
	}
	if !ifnameRE.MatchString(s) || s == "." || s == ".." {
		return "", "invalid interface name " + strRepr(s)
	}
	return s, ""
}

func validateHostname(v Value) string {
	s, ok := v.(string)
	if !ok {
		return "hostname must be a string, got " + typeName(v)
	}
	if s == "" || len([]rune(s)) > 253 || !dottedHostname(s) {
		return "invalid hostname " + strRepr(s)
	}
	return ""
}

func validateGithubRepo(s string) string {
	if !repoRE.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Sprintf("invalid GitHub repository %s (expected OWNER/NAME)", strRepr(s))
	}
	return ""
}

// Python's `x in d` for a dict with string keys: only a string can be a
// key. (A list or a mapping there makes 1.x crash with a TypeError
// instead of a ConfigError; it is refused here all the same.)
func inZones(v Value, zones *Ordered[Zone]) bool {
	s, ok := v.(string)
	return ok && zones.Has(s)
}

func asMap(v Value) (*Map, bool) { m, ok := v.(*Map); return m, ok }

// items is Python's iteration over `raw.get(key, []) or []`: a list is
// its items; a non-empty mapping or string iterates its keys or
// characters, none of which is a mapping, so the caller refuses its
// first one; anything else can't be iterated (1.x crashes).
func items(v Value, what string) []Value {
	switch x := v.(type) {
	case []Value:
		return x
	case *Map:
		out := make([]Value, len(x.keys))
		for i, k := range x.keys {
			out[i] = k
		}
		return out
	case string:
		out := []Value{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out
	}
	fail("%s must be a list", what)
	return nil
}

func parseConfig(raw Value) *Config {
	top, ok := asMap(raw)
	if !ok {
		fail("Top-level config must be a mapping")
	}
	cfg := &Config{}

	version := top.get("version", nil)
	if !numEq(version, supportedVersion) {
		fail("Unsupported config version %s; expected %d", repr(version), supportedVersion)
	}
	cfg.Version = version

	hostname, ok := top.get("hostname", nil).(string)
	if !ok || hostname == "" {
		fail("'hostname' is required and must be a non-empty string")
	}
	if msg := validateHostname(hostname); msg != "" {
		fail("%s", msg) // it goes into the webUI certificate request
	}
	cfg.Hostname = hostname

	if tz, present := top.Get("timezone"); present && tz != nil {
		name, ok := tz.(string)
		if !ok || !validZoneName(name) {
			fail("'timezone' must be an IANA time zone name (e.g. Europe/Budapest), got %s", repr(tz))
		}
		cfg.Timezone = name
	}

	cfg.Zones = parseZones(top.get("zones", NewMap()))
	cfg.Interfaces = parseInterfaces(top.get("interfaces", NewMap()), &cfg.Zones, tunnelZones(top.get("wireguard", nil)))
	cfg.Rules = parseRules(top.get("rules", []Value{}), &cfg.Zones, cfg.Timezone)
	cfg.Nat = parseNat(top.getOr("nat", NewMap()), &cfg.Zones)
	cfg.Dhcp = parseDhcp(top.getOr("dhcp", NewMap()), &cfg.Zones, &cfg.Interfaces)
	cfg.AiIds = parseAiIds(top.getOr("ai_ids", NewMap()))
	cfg.Update = parseUpdate(top.getOr("update", NewMap()))
	cfg.XdpSniFilter = parseXdpSniFilter(top.getOr("xdp_sni_filter", NewMap()), &cfg.Interfaces)
	cfg.Ztna = parseZtna(top.getOr("ztna", NewMap()))
	cfg.Pqc = PqcConfig{Enabled: boolKey(mapOf(top.getOr("pqc", NewMap()), "'pqc' must be a mapping"), "enabled", false, "pqc.enabled must be a boolean")}
	cfg.Adblocker = parseAdblocker(top.getOr("adblocker", NewMap()), &cfg.Dhcp)
	cfg.Iot = parseIot(top.getOr("iot", NewMap()), &cfg.Zones, &cfg.Nat)
	cfg.AppControl = parseAppControl(top.getOr("app_control", NewMap()), &cfg.Adblocker, &cfg.XdpSniFilter)
	cfg.LocalDNS = parseLocalDNS(top.getOr("local_dns", NewMap()), &cfg.Adblocker, &cfg.AppControl)
	cfg.TlsFingerprint = parseTlsFingerprint(top.getOr("tls_fingerprint", NewMap()), &cfg.XdpSniFilter)
	cfg.Metrics = parseMetrics(top.getOr("metrics", NewMap()))
	cfg.Management = parseManagement(top.getOr("management", NewMap()), &cfg.Zones, &cfg.Nat)
	cfg.Wireguard = parseWireguard(top.getOr("wireguard", NewMap()), &cfg.Zones, &cfg.Nat, &cfg.Interfaces)
	checkManagementAddresses(cfg)
	cfg.Logging = parseLogging(top.getOr("logging", NewMap()))
	cfg.IPv6 = parseIPv6(top.getOr("ipv6", NewMap()), cfg)
	checkManagementIPv6(cfg)
	return cfg
}

func mapOf(v Value, msg string) *Map {
	m, ok := asMap(v)
	if !ok {
		fail("%s", msg)
	}
	return m
}

// boolKey is a key that must be true or false when present.
func boolKey(m *Map, key string, def bool, msg string) bool {
	b, ok := m.get(key, def).(bool)
	if !ok {
		fail("%s", msg)
	}
	return b
}

func requireName(name Value, what string) string {
	s, ok := name.(string)
	if !ok || !nameRE.MatchString(s) {
		fail("Invalid %s name %s: must match %s (lowercase letters, digits, '-'/'_', starting with a letter)",
			what, repr(name), namePattern)
	}
	return s
}

func parseZones(raw Value) Ordered[Zone] {
	m, ok := asMap(raw)
	if !ok {
		fail("'zones' must be a mapping of zone name -> settings")
	}
	var zones Ordered[Zone]
	for i, key := range m.Keys() {
		name := requireName(key, "zone")
		if name == SelfZone {
			fail("Zone name %s is reserved", strRepr(SelfZone))
		}
		body := m.vals[i]
		if !truthy(body) {
			body = NewMap()
		}
		b, ok := asMap(body)
		if !ok {
			fail("Zone %s settings must be a mapping", strRepr(name))
		}
		zones.set(name, Zone{Name: name, Description: b.get("description", "")})
	}
	return zones
}

func parseInterfaces(raw Value, zones *Ordered[Zone], tunnel map[string]bool) Ordered[Interface] {
	m, ok := asMap(raw)
	if !ok || m.Len() == 0 {
		fail("'interfaces' must be a non-empty mapping")
	}
	var out Ordered[Interface]
	seenDevices := map[string]string{}
	for i, key := range m.Keys() {
		name := requireName(key, "interface")
		body, ok := asMap(m.vals[i])
		if !ok {
			fail("Interface %s settings must be a mapping", strRepr(name))
		}
		device, ok := body.get("device", nil).(string)
		if !ok || device == "" {
			fail("Interface %s is missing a 'device'", strRepr(name))
		}
		if _, msg := validateIfname(device); msg != "" {
			fail("Interface %s: %s", strRepr(name), msg) // F1: an `ip`/`nft` argument
		}
		if other, dup := seenDevices[device]; dup {
			fail("Device %s is assigned to both %s and %s", strRepr(device), strRepr(other), strRepr(name))
		}
		seenDevices[device] = name

		zone := body.get("zone", nil)
		if !inZones(zone, zones) {
			fail("Interface %s references undefined zone %s; declare it under 'zones' first", strRepr(name), repr(zone))
		}
		iface := Interface{Name: name, Device: device, Zone: zone.(string), Description: body.get("description", "")}
		if address := body.get("address", nil); address != nil {
			iface.Address = validateInterfaceAddress(address, fmt.Sprintf("Interface %s address", strRepr(name)))
		}
		if vlan := body.get("vlan", nil); vlan != nil {
			vm, ok := asMap(vlan)
			if !ok {
				fail("Interface %s: vlan must be a mapping with parent and id", strRepr(name))
			}
			parent, msg := validateIfname(vm.get("parent", nil))
			if msg != "" {
				fail("Interface %s vlan.parent: %s", strRepr(name), msg)
			}
			id := vm.get("id", nil)
			if _, ok := strictInt(id); !ok || !intIn(id, 1, 4094) {
				fail("Interface %s: vlan.id must be 1-4094", strRepr(name))
			}
			if parent == device {
				fail("Interface %s: a VLAN can't be its own parent", strRepr(name))
			}
			iface.VlanParent, iface.VlanID = parent, int(intOf(id).Int64())
		}
		out.set(name, iface)
	}
	used := map[string]bool{}
	for _, i := range out.Values() {
		used[i.Zone] = true
	}
	for z := range tunnel {
		used[z] = true
	}
	for _, z := range zones.Keys {
		if !used[z] {
			fail("Zone %s is declared but not used by any interface", strRepr(z))
		}
	}
	return out
}

// validZoneRef is a zone reference that may be absent (nil), the router
// ("self") or a declared zone.
func validZoneRef(v Value, zones *Ordered[Zone]) bool {
	return v == nil || v == Value(SelfZone) || inZones(v, zones)
}

func zoneName(v Value) string {
	if v == nil {
		return ""
	}
	return v.(string)
}

func enumOf(v Value, values []string) (string, bool) {
	s, ok := v.(string)
	return s, ok && slices.Contains(values, s)
}

func reprList(values []string) string { return repr(values) }

func parseRules(raw Value, zones *Ordered[Zone], tz string) []Rule {
	list, ok := raw.([]Value)
	if !ok {
		fail("'rules' must be a list")
	}
	rules := []Rule{}
	seen := map[string]bool{}
	for i, item := range list {
		body, ok := asMap(item)
		if !ok {
			fail("rules[%d] must be a mapping", i)
		}
		name := requireName(body.get("name", nil), "rule")
		if seen[name] {
			fail("Duplicate rule name %s", strRepr(name))
		}
		seen[name] = true
		r := Rule{Name: name}

		action, ok := enumOf(body.get("action", nil), actions)
		if !ok {
			fail("Rule %s: invalid action %s; expected one of %s", strRepr(name), repr(body.get("action", nil)), reprList(actions))
		}
		r.Action = Action(action)

		from := body.get("from_zone", nil)
		if !validZoneRef(from, zones) || from == Value(SelfZone) {
			fail("Rule %s: invalid from_zone %s", strRepr(name), repr(from))
		}
		to := body.get("to_zone", nil)
		if !validZoneRef(to, zones) {
			fail("Rule %s: invalid to_zone %s", strRepr(name), repr(to))
		}
		r.FromZone, r.ToZone = zoneName(from), zoneName(to)

		protoRaw := body.get("proto", string(ProtoAny))
		proto, ok := enumOf(protoRaw, protocols)
		if !ok {
			fail("Rule %s: invalid proto %s; expected one of %s", strRepr(name), repr(protoRaw), reprList(protocols))
		}
		r.Proto = Protocol(proto)

		if port := body.get("dst_port", nil); port != nil {
			if r.Proto != ProtoTCP && r.Proto != ProtoUDP {
				fail("Rule %s: dst_port requires proto tcp or udp, got %s", strRepr(name), strRepr(proto))
			}
			r.DstPort = validatePortSpec(port, fmt.Sprintf("Rule %s dst_port", strRepr(name)))
		}

		r.SrcAddress, r.srcNets = parseNetworks(body.get("src_address", nil), fmt.Sprintf("Rule %s src_address", strRepr(name)))
		r.DstAddress, r.dstNets = parseNetworks(body.get("dst_address", nil), fmt.Sprintf("Rule %s dst_address", strRepr(name)))
		if len(r.srcNets) > 0 && len(r.dstNets) > 0 {
			common := false
			for _, s := range r.srcNets {
				for _, d := range r.dstNets {
					common = common || s.version == d.version
				}
			}
			if !common {
				fail("Rule %s: src_address and dst_address have no address family in common, so the rule could never match", strRepr(name))
			}
		}

		r.Log = truthy(body.get("log", false))
		r.RequireZtna = truthy(body.get("require_ztna", false))

		if mac := body.get("src_mac", nil); mac != nil {
			s, ok := mac.(string)
			if !ok || !macRE.MatchString(s) {
				fail("Rule %s: invalid src_mac %s", strRepr(name), repr(mac))
			}
			r.SrcMac = strings.ToLower(s)
		}
		if sched := body.get("schedule", nil); sched != nil {
			r.Schedule = parseSchedule(sched, fmt.Sprintf("Rule %s schedule", strRepr(name)), r.Action)
		}
		if exp := body.get("expires", nil); exp != nil {
			t := parseExpiry(exp, tz, fmt.Sprintf("Rule %s expires", strRepr(name)))
			r.Expires = &t
		}
		rules = append(rules, r)
	}
	return rules
}

// parseExpiry is a rule's expiry (security-lessons K2) as Unix time: an
// ISO 8601 date and time, or YAML's own timestamp; without an offset it
// is read in tz (else the router's zone, Local).
func parseExpiry(v Value, tz string, what string) int64 {
	var m isoMoment
	switch x := v.(type) {
	case Datetime: // YAML's own timestamp
		m = x.moment()
	case string:
		var err error
		if m, err = fromISOFormat(pyStrip(x)); err != nil {
			fail("%s: expected a date and time like 2026-10-01T18:00, got %s", what, repr(v))
		}
	default:
		fail("%s: expected a date and time like 2026-10-01T18:00, got %s", what, repr(v))
	}
	loc := Local
	if tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	return m.unix(loc)
}

// Expiry is a rule's expiry as Unix time, as the config check reads it
// (the webUI reads a new rule's expiry with it): what names the field in
// the *Error.
func Expiry(v Value, tz, what string) (t int64, err error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(*Error)
			if !ok {
				panic(r)
			}
			err = e
		}
	}()
	return parseExpiry(v, tz, what), nil
}

// portRange is 1.x's _PORT_RANGE_RE, `^(\d{1,5})-(\d{1,5})\Z`; Python's
// `\d` is any Unicode decimal digit, and int() reads them all.
func portRange(s string) (int, int, bool) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false
	}
	read := func(t string) (int, bool) {
		if n := len([]rune(t)); n < 1 || n > 5 {
			return 0, false
		}
		return pyDecimal(t)
	}
	lo, ok1 := read(a)
	hi, ok2 := read(b)
	return lo, hi, ok1 && ok2
}

func validatePortSpec(v Value, what string) string {
	if isInt(v) {
		if !intIn(v, 1, 65535) {
			fail("%s: port %s out of range 1-65535", what, pyStr(v))
		}
		return pyStr(v) // str(True) is "True": 1.x keeps it so
	}
	if s, ok := v.(string); ok {
		if lo, hi, ok := portRange(s); ok {
			if !(lo >= 1 && lo <= 65535 && hi >= 1 && hi <= 65535 && lo <= hi) {
				fail("%s: invalid port range %s", what, strRepr(s))
			}
			return fmt.Sprintf("%d-%d", lo, hi)
		}
	}
	fail("%s: expected an integer port or 'start-end' range string, got %s", what, repr(v))
	return ""
}

// portBounds is a port spec's first and last port. A spec 1.x stored
// as "True" makes 1.x crash here; it is refused instead.
func portBounds(spec, what string) (int, int) {
	lo, hi, found := strings.Cut(spec, "-")
	low, err1 := strconv.Atoi(lo)
	high := low
	var err2 error
	if found {
		high, err2 = strconv.Atoi(hi)
	}
	if err1 != nil || err2 != nil {
		fail("%s: port %s is not a number", what, strRepr(spec))
	}
	return low, high
}

// parseNetworks is a rule's address field (ROADMAP FND-1d): one network
// or a list, of either family, normalized and without repeats in the
// order given.
func parseNetworks(v Value, what string) ([]string, []ipNet) {
	if v == nil {
		return nil, nil
	}
	list, ok := v.([]Value)
	if !ok {
		list = []Value{v}
	}
	if len(list) == 0 {
		fail("%s: an empty list matches nothing; leave the key out instead", what)
	}
	var out []string
	var nets []ipNet
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			fail("%s: expected an address/network string, got %s", what, repr(item))
		}
		n, err := parseIPNetwork(pyStrip(s))
		if err != nil {
			fail("%s: invalid IPv4 or IPv6 address/network %s: %s", what, strRepr(s), err)
		}
		if n.version == 6 && n.v6.addr.hasScope {
			fail("%s: invalid IPv4 or IPv6 address/network %s: no scope (%%) allowed", what, strRepr(s))
		}
		if text := n.String(); !slices.Contains(out, text) {
			out = append(out, text)
			nets = append(nets, n)
		}
	}
	return out, nets
}

func validateAddress(v Value, what string) uint32 {
	s, ok := v.(string)
	if !ok {
		fail("%s: expected a string, got %s", what, repr(v))
	}
	ip, err := parseIPv4Address(s)
	if err != nil {
		fail("%s: invalid IPv4 address %s: %s", what, strRepr(s), err)
	}
	return ip
}

// validateInterfaceAddress: a host address with its prefix length, as
// IPv4Interface keeps it ("the router's own address").
func validateInterfaceAddress(v Value, what string) string {
	s, ok := v.(string)
	if !ok {
		fail("%s: expected a string, got %s", what, repr(v))
	}
	i, err := parseIPv4Interface(s)
	if err != nil {
		fail("%s: expected an IPv4 address with prefix length (e.g. '10.0.0.1/24'), got %s: %s", what, strRepr(s), err)
	}
	return i.String()
}

func mustInterface(s string) ipv4Interface {
	i, err := parseIPv4Interface(s)
	if err != nil {
		panic(err) // only for addresses this package already normalized
	}
	return i
}

func parseNat(raw Value, zones *Ordered[Zone]) NatConfig {
	m := mapOf(raw, "'nat' must be a mapping")
	nat := NatConfig{Masquerade: []Masquerade{}, PortForwards: []PortForward{}}
	for i, item := range items(m.getOr("masquerade", []Value{}), "nat.masquerade") {
		body, ok := asMap(item)
		if !ok {
			fail("nat.masquerade[%d] must be a mapping", i)
		}
		out := body.get("out_zone", nil)
		if !validZoneRef(out, zones) || out == nil || out == Value(SelfZone) {
			fail("nat.masquerade[%d]: invalid out_zone %s", i, repr(out))
		}
		nat.Masquerade = append(nat.Masquerade, Masquerade{OutZone: out.(string)})
	}
	seen := map[string]bool{}
	for i, item := range items(m.getOr("port_forwards", []Value{}), "nat.port_forwards") {
		body, ok := asMap(item)
		if !ok {
			fail("nat.port_forwards[%d] must be a mapping", i)
		}
		name := requireName(body.get("name", nil), "port_forward")
		if seen[name] {
			fail("Duplicate port_forward name %s", strRepr(name))
		}
		seen[name] = true
		in := body.get("in_zone", nil)
		if !validZoneRef(in, zones) || in == nil || in == Value(SelfZone) {
			fail("nat.port_forwards[%s]: invalid in_zone %s", strRepr(name), repr(in))
		}
		proto, ok := enumOf(body.get("proto", nil), protocols)
		if !ok {
			fail("nat.port_forwards[%s]: invalid proto %s", strRepr(name), repr(body.get("proto", nil)))
		}
		if proto != string(ProtoTCP) && proto != string(ProtoUDP) {
			fail("nat.port_forwards[%s]: proto must be tcp or udp, got %s", strRepr(name), strRepr(proto))
		}
		dst := body.get("dst_port", nil)
		if !isInt(dst) || !intIn(dst, 1, 65535) {
			fail("nat.port_forwards[%s]: dst_port must be an integer 1-65535", strRepr(name))
		}
		to := body.get("to_address", nil)
		validateAddress(to, fmt.Sprintf("nat.port_forwards[%s] to_address", strRepr(name)))
		toPort := body.get("to_port", dst)
		if !isInt(toPort) || !intIn(toPort, 1, 65535) {
			fail("nat.port_forwards[%s]: to_port must be an integer 1-65535", strRepr(name))
		}
		nat.PortForwards = append(nat.PortForwards, PortForward{
			Name: name, InZone: in.(string), Proto: Protocol(proto),
			DstPort: int(intOf(dst).Int64()), ToAddress: to.(string), ToPort: int(intOf(toPort).Int64()),
		})
	}
	return nat
}

func parseDhcp(raw Value, zones *Ordered[Zone], interfaces *Ordered[Interface]) DhcpConfig {
	m := mapOf(raw, "'dhcp' must be a mapping of zone name -> pool settings")
	byZone := map[string][]Interface{}
	for _, i := range interfaces.Values() {
		byZone[i.Zone] = append(byZone[i.Zone], i)
	}
	var dhcp DhcpConfig
	for i, key := range m.Keys() {
		if !inZones(key, zones) {
			fail("dhcp: undefined zone %s", repr(key))
		}
		zone := key.(string)
		body, ok := asMap(m.vals[i])
		if !ok {
			fail("dhcp[%s] must be a mapping", strRepr(zone))
		}
		ifaces := byZone[zone]
		if len(ifaces) != 1 {
			fail("dhcp[%s]: DHCP requires exactly one interface in this zone, found %d", strRepr(zone), len(ifaces))
		}
		iface := ifaces[0]
		if iface.Address == "" {
			fail("dhcp[%s]: interface %s needs a static 'address' before it can serve DHCP on this zone",
				strRepr(zone), strRepr(iface.Name))
		}
		ii := mustInterface(iface.Address)
		network, gateway := ii.network(), ii.ip
		what := fmt.Sprintf("dhcp[%s]", strRepr(zone))
		start := validatePoolAddress(body.get("range_start", nil), network, gateway, what+" range_start")
		end := validatePoolAddress(body.get("range_end", nil), network, gateway, what+" range_end")
		if start > end {
			fail("%s: range_start must not be after range_end", what)
		}
		dnsList, ok := body.get("dns_servers", nil).([]Value)
		if !ok || len(dnsList) == 0 {
			fail("%s: 'dns_servers' must be a non-empty list of IPv4 addresses", what)
		}
		var dns []string
		for _, d := range dnsList {
			dns = append(dns, v4String(validateAddress(d, what+" dns_servers")))
		}
		lease := body.get("lease_time", big.NewInt(3600))
		if !isInt(lease) || intOf(lease).Sign() <= 0 {
			fail("%s: 'lease_time' must be a positive integer (seconds)", what)
		}
		if !intOf(lease).IsInt64() {
			fail("%s: 'lease_time' is too large", what) // decisions.md: 64-bit integers
		}
		dhcp.Zones.set(zone, DhcpPool{
			Zone: zone, RangeStart: v4String(start), RangeEnd: v4String(end), DNSServers: dns,
			LeaseTime:    intOf(lease).Int64(),
			Reservations: parseDhcpReservations(body.get("reservations", []Value{}), network, gateway, what),
		})
	}
	return dhcp
}

func validatePoolAddress(v Value, network ipv4Net, gateway uint32, what string) uint32 {
	s, ok := v.(string)
	if !ok {
		fail("%s: expected a string, got %s", what, repr(v))
	}
	ip, err := parseIPv4Address(s)
	if err != nil {
		fail("%s: invalid IPv4 address %s: %s", what, strRepr(s), err)
	}
	if !network.contains(ip) {
		fail("%s: %s is not inside subnet %s", what, v4String(ip), network)
	}
	if ip == gateway {
		fail("%s: %s is the gateway address, cannot be in the pool", what, v4String(ip))
	}
	return ip
}

func parseDhcpReservations(raw Value, network ipv4Net, gateway uint32, what string) []DhcpReservation {
	list, ok := raw.([]Value)
	if !ok {
		fail("%s: 'reservations' must be a list", what)
	}
	out := []DhcpReservation{}
	seenMacs, seenAddrs := map[string]bool{}, map[uint32]bool{}
	for i, item := range list {
		body, ok := asMap(item)
		if !ok {
			fail("%s reservations[%d] must be a mapping", what, i)
		}
		macRaw := body.get("mac", nil)
		mac, ok := macRaw.(string)
		if !ok || !macRE.MatchString(mac) {
			fail("%s reservations[%d]: invalid MAC address %s (expected aa:bb:cc:dd:ee:ff)", what, i, repr(macRaw))
		}
		mac = strings.ToLower(mac)
		if seenMacs[mac] {
			fail("%s reservations[%d]: duplicate MAC address %s", what, i, strRepr(mac))
		}
		seenMacs[mac] = true
		ip := validatePoolAddress(body.get("address", nil), network, gateway, fmt.Sprintf("%s reservations[%d] address", what, i))
		if seenAddrs[ip] {
			fail("%s reservations[%d]: duplicate address %s", what, i, v4String(ip))
		}
		seenAddrs[ip] = true
		host, ok := body.get("hostname", "").(string)
		if !ok {
			fail("%s reservations[%d]: 'hostname' must be a string", what, i)
		}
		out = append(out, DhcpReservation{MacAddress: mac, Address: v4String(ip), Hostname: host})
	}
	return out
}

func parseMacList(raw Value, what string, dedupe bool) []string {
	list, ok := raw.([]Value)
	if !ok {
		fail("%s must be a list", what)
	}
	out := []string{}
	for i, item := range list {
		mac, ok := item.(string)
		if !ok || !macRE.MatchString(mac) {
			fail("%s[%d]: invalid MAC address %s", what, i, repr(item))
		}
		mac = strings.ToLower(mac)
		if !dedupe || !slices.Contains(out, mac) {
			out = append(out, mac)
		}
	}
	return out
}

// positive64 is an integer (not a bool) that must be > 0, as int64.
func strictIntIn(v Value, lo, hi int64) (int64, bool) {
	n, ok := strictInt(v)
	if !ok || !intIn(n, lo, hi) {
		return 0, false
	}
	return n.Int64(), true
}

func parseAiIds(raw Value) AiIdsConfig {
	m := mapOf(raw, "'ai_ids' must be a mapping")
	c := AiIdsConfig{Enabled: boolKey(m, "enabled", false, "ai_ids.enabled must be a boolean")}
	if _, ok := m.get("excluded_macs", []Value{}).([]Value); !ok {
		fail("ai_ids.excluded_macs must be a list")
	}
	c.ExcludedMacs = parseMacList(m.get("excluded_macs", []Value{}), "ai_ids.excluded_macs", false)
	q := m.get("quarantine_duration_seconds", big.NewInt(2*3600))
	if n, ok := strictInt(q); !ok || n.Sign() <= 0 {
		fail("ai_ids.quarantine_duration_seconds must be a positive integer")
	}
	d, ok := strictIntIn(q, 1, maxQuarantine)
	if !ok {
		// The apply-helper refuses longer ones.
		fail("ai_ids.quarantine_duration_seconds may be at most %d (7 days)", maxQuarantine)
	}
	c.QuarantineDurationSeconds = d
	return c
}

func parseUpdate(raw Value) UpdateConfig {
	m := mapOf(raw, "'update' must be a mapping")
	repo, ok := m.get("repo", "").(string)
	if !ok {
		fail("update.repo must be a string")
	}
	if repo != "" {
		if msg := validateGithubRepo(repo); msg != "" {
			fail("update.repo: %s", msg)
		}
	}
	return UpdateConfig{
		Repo:                repo,
		AutoInstallSecurity: boolKey(m, "auto_install_security", false, "update.auto_install_security must be true or false"),
		KernelUpdates:       boolKey(m, "kernel_updates", true, "update.kernel_updates must be true or false"),
	}
}

// internetFacing are the zones that face the internet: every
// nat.masquerade out_zone, and a zone called "wan" even without NAT.
func internetFacing(zones *Ordered[Zone], nat *NatConfig) map[string]bool {
	out := map[string]bool{}
	for _, m := range nat.Masquerade {
		out[m.OutZone] = true
	}
	if zones.Has("wan") {
		out["wan"] = true
	}
	return out
}

// InternetFacingZones is internetFacing for the checked config.
func (c *Config) InternetFacingZones() map[string]bool { return internetFacing(&c.Zones, &c.Nat) }

func withInterface(interfaces *Ordered[Interface]) map[string]bool {
	out := map[string]bool{}
	for _, i := range interfaces.Values() {
		out[i.Zone] = true
	}
	return out
}

// IPv6LanZones are the zones the delegated prefix goes to (ROADMAP
// FND-1b), in order: ipv6.lan_zones, or every zone with an interface that
// doesn't face the internet, in config order, but those IPv6 would get
// around a protection of (IPv6LanExclusions). Empty while IPv6 is off.
func (c *Config) IPv6LanZones() []string {
	if !c.IPv6.Enabled {
		return nil
	}
	if c.IPv6.LanZones != nil {
		return slices.Clone(c.IPv6.LanZones)
	}
	facing := c.InternetFacingZones()
	with := withInterface(&c.Interfaces)
	excluded := ipv6LanExclusions(&c.Zones, &c.Nat, c.Rules)
	var out []string
	for _, z := range c.Zones.Keys {
		if _, ex := excluded[z]; !facing[z] && with[z] && !ex {
			out = append(out, z)
		}
	}
	return out
}

// ipv6LanExclusions: zone -> why it can't have IPv6 (ROADMAP FND-1b).
// A forward drop/reject rule by IPv4 address only, touching the zone
// (naming it, or no zone at all), would be got around over IPv6; one
// whose traffic comes from the internet is no gap.
func ipv6LanExclusions(zones *Ordered[Zone], nat *NatConfig, rules []Rule) map[string]string {
	facing := internetFacing(zones, nat)
	out := map[string]string{}
	for i := range rules {
		r := &rules[i]
		if r.Action == Accept || r.ToZone == SelfZone || !r.IPv4AddressesOnly() {
			continue
		}
		if r.FromZone != "" && facing[r.FromZone] {
			continue
		}
		reason := fmt.Sprintf("rule %s blocks by IPv4 address only, which IPv6 would get around "+
			"(block a LAN host by MAC, src_mac: it picks its IPv6 addresses itself; "+
			"or name the IPv6 networks in the rule too)", strRepr(r.Name))
		for _, z := range zones.Keys {
			if facing[z] {
				continue
			}
			if r.FromZone == "" || r.FromZone == z || r.ToZone == "" || r.ToZone == z {
				if _, set := out[z]; !set {
					out[z] = reason
				}
			}
		}
	}
	return out
}

func parseIPv6(raw Value, cfg *Config) Ipv6Config {
	m := mapOf(raw, "'ipv6' must be a mapping")
	if unknown := unknownKeys(m, "enabled", "lan_zones", "ula_prefix", "pinholes"); unknown != nil {
		fail("ipv6: unknown key(s) %s", repr(unknown))
	}
	c := Ipv6Config{Enabled: boolKey(m, "enabled", false, "ipv6.enabled must be true or false")}
	facing := cfg.InternetFacingZones()
	if lz := m.get("lan_zones", nil); lz != nil {
		list, ok := lz.([]Value)
		names := []string{}
		for _, z := range list {
			s, isStr := z.(string)
			ok = ok && isStr
			names = append(names, s)
		}
		if !ok {
			fail("ipv6.lan_zones must be a list of zone names")
		}
		if len(dedupe(names)) != len(names) {
			fail("ipv6.lan_zones names a zone more than once")
		}
		with := withInterface(&cfg.Interfaces)
		excluded := map[string]string{}
		if c.Enabled {
			excluded = ipv6LanExclusions(&cfg.Zones, &cfg.Nat, cfg.Rules)
		}
		for _, z := range names {
			switch {
			case !cfg.Zones.Has(z):
				fail("ipv6.lan_zones: unknown zone %s", strRepr(z))
			case facing[z]:
				fail("ipv6.lan_zones: %s faces the internet; the prefix comes from there", strRepr(z))
			case !with[z]:
				fail("ipv6.lan_zones: zone %s has no interface to give a prefix to", strRepr(z))
			}
			if why, ex := excluded[z]; ex {
				fail("ipv6.lan_zones: zone %s can't have IPv6: %s", strRepr(z), why)
			}
		}
		c.LanZones = names
	}
	if c.Enabled {
		ok := false
		for _, i := range cfg.Interfaces.Values() {
			ok = ok || facing[i.Zone]
		}
		if !ok {
			fail("ipv6.enabled needs an internet-facing interface (a zone nat.masquerade points at, " +
				"or a zone named wan): IPv6 is taken from the provider there")
		}
	}
	c.UlaPrefix = parseUlaPrefix(m.get("ula_prefix", nil))
	c.Pinholes = parsePinholes(m.get("pinholes", []Value{}), c.Enabled, &cfg.Zones, facing, cfg.Rules)
	return c
}

// unknownKeys is `sorted(set(m) - known)`, nil when there are none.
func unknownKeys(m *Map, known ...string) []Value {
	var out []Value
	for _, k := range m.Keys() {
		if s, ok := k.(string); !ok || !slices.Contains(known, s) {
			out = append(out, k)
		}
	}
	pySort(out)
	return out
}

func dedupe(values []string) []string {
	var out []string
	for _, v := range values {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

var (
	ulaLocal      = mustV6Net("fd00::/8") // RFC 4193: a ULA /48 is in here
	ulaAll        = mustV6Net("fc00::/7")
	globalUnicast = mustV6Net("2000::/3")
	linkLocal     = mustV6Net("fe80::/10")
	multicast     = mustV6Net("ff00::/8")
	zeroULA       = mustV6Net("fd00::/48")
)

func parseUlaPrefix(raw Value) string {
	if raw == nil {
		return ""
	}
	var n ipv6Net
	ok := false
	if s, isStr := raw.(string); isStr {
		var err error
		n, err = parseIPv6Network(s, true)
		ok = err == nil && !n.addr.hasScope
	}
	if !ok || n.prefix != 48 || !n.subnetOf(ulaLocal) {
		fail("ipv6.ula_prefix must be a ULA /48 in fd00::/8 (RFC 4193), e.g. fd12:3456:789a::/48, got %s", repr(raw))
	}
	if n.equal(zeroULA) {
		// RFC 4193 3.2: the global ID is random, so two networks joined
		// later don't collide; all zeros is the one everyone would pick.
		fail("ipv6.ula_prefix: fd00::/48 is not a random global ID (RFC 4193 3.2); " +
			"leave ula_prefix out and the router picks one")
	}
	return n.String()
}

// pinholeHost is a host a pinhole may point at: an interface identifier
// (the low 64 bits, "::...") or a full global unicast address, never one
// that means more than one host or the router itself.
func pinholeHost(raw Value, what string) string {
	var a ipv6Addr
	ok := false
	if s, isStr := raw.(string); isStr {
		var err error
		a, err = parseIPv6Address(s)
		ok = err == nil && !a.hasScope
	}
	if !ok {
		fail("%s: host must be an IPv6 address or an interface identifier such as ::5054:ff:fe12:3456, got %s", what, repr(raw))
	}
	iid := a.ip.lo
	switch {
	case iid == 0:
		fail("%s: host %s is the subnet-router anycast address (all hosts' router), not a host", what, repr(raw))
	case iid == 1:
		fail("%s: host %s is the router's own address on the LAN (::1), not a host", what, repr(raw))
	case iid >= 0xfdff_ffff_ffff_ff80: // RFC 5453 reserved anycast
		fail("%s: host %s is a reserved anycast identifier (RFC 5453), not a host", what, repr(raw))
	}
	if a.ip.hi != 0 && !(globalUnicast.contains(a.ip) && !ulaAll.contains(a.ip)) {
		fail("%s: host %s must be a global unicast address (2000::/3), or an interface identifier (::…) to follow the provider's prefix", what, repr(raw))
	}
	return a.String()
}

func parsePinholes(raw Value, enabled bool, zones *Ordered[Zone], facing map[string]bool, rules []Rule) []Ipv6Pinhole {
	if raw == nil {
		return []Ipv6Pinhole{}
	}
	list, ok := raw.([]Value)
	if !ok {
		fail("ipv6.pinholes must be a list")
	}
	out := []Ipv6Pinhole{}
	for index, item := range list {
		body, ok := asMap(item)
		if !ok {
			fail("ipv6.pinholes[%d] must be a mapping", index)
		}
		name := requireName(body.get("name", nil), fmt.Sprintf("ipv6.pinholes[%d]", index))
		what := fmt.Sprintf("ipv6.pinholes[%s]", strRepr(name))
		if unknown := unknownKeys(body, "name", "zone", "host", "proto", "port", "from"); unknown != nil {
			fail("%s: unknown key(s) %s", what, repr(unknown))
		}
		for _, p := range out {
			if p.Name == name {
				fail("ipv6.pinholes: %s is named twice", strRepr(name))
			}
		}
		zone, ok := body.get("zone", nil).(string)
		if !ok {
			fail("%s: zone is required", what)
		}
		if enabled && (!zones.Has(zone) || facing[zone]) {
			fail("%s: zone %s is not a LAN zone of this config", what, strRepr(zone))
		}
		host := pinholeHost(body.get("host", nil), what)
		protoRaw := body.get("proto", nil)
		if protoRaw != Value("tcp") && protoRaw != Value("udp") {
			fail("%s: proto must be tcp or udp, got %s", what, repr(protoRaw))
		}
		if body.get("port", nil) == nil {
			fail("%s: port is required", what)
		}
		from, to := portBounds(validatePortSpec(body.get("port", nil), what+" port"), what)
		if to-from+1 > pinholeMaxPorts {
			fail("%s: %d ports is more than one pinhole may open (%d)", what, to-from+1, pinholeMaxPorts)
		}
		p := Ipv6Pinhole{Name: name, Zone: zone, Host: host, Proto: Protocol(protoRaw.(string)), PortFrom: from, PortTo: to}
		if src := body.get("from", nil); src != nil {
			var n ipv6Net
			ok := false
			if s, isStr := src.(string); isStr {
				var err error
				n, err = parseIPv6Network(s, false)
				ok = err == nil && !n.addr.hasScope
			}
			if !ok {
				fail("%s: from must be an IPv6 network such as 2001:db8:42::/48, got %s", what, repr(src))
			}
			isLinkLocal := linkLocal.contains(n.addr.ip) && linkLocal.contains(n.broadcast())
			isMulticast := multicast.contains(n.addr.ip) && multicast.contains(n.broadcast())
			if n.overlaps(ulaAll) || isLinkLocal || isMulticast {
				fail("%s: from %s can't come from the internet", what, repr(src))
			}
			p.Source = n.String()
		}
		if blocker := ruleDroppingPinhole(&p, facing, rules, what); blocker != "" {
			fail("%s: rule %s drops this traffic, and a pinhole goes ahead of the rules "+
				"(a drop rule would not hold). Remove the rule, or narrow the pinhole", what, strRepr(blocker))
		}
		out = append(out, p)
	}
	return out
}

// ruleDroppingPinhole is a forward drop/reject rule that would match a
// pinhole's traffic: from the internet, to its zone, its protocol and a
// port of it. Pinholes are rendered ahead of every rule, so such a rule
// would silently stop holding.
func ruleDroppingPinhole(p *Ipv6Pinhole, facing map[string]bool, rules []Rule, what string) string {
	for i := range rules {
		r := &rules[i]
		if r.Action == Accept || r.ToZone == SelfZone || !r.Families()[6] {
			continue
		}
		if r.FromZone != "" && !facing[r.FromZone] {
			continue
		}
		if r.ToZone != "" && r.ToZone != p.Zone {
			continue
		}
		if r.Proto != ProtoAny && r.Proto != p.Proto {
			continue
		}
		if r.DstPort != "" {
			lo, hi := portBounds(r.DstPort, what)
			if hi < p.PortFrom || lo > p.PortTo {
				continue
			}
		}
		return r.Name
	}
	return ""
}

// managedZones are the zones management is reachable from
// (frfw.management.management_zones).
func managedZones(c *Config) map[string]bool {
	out := map[string]bool{}
	switch {
	case len(c.Management.Zones) > 0:
		for _, z := range c.Management.Zones {
			out[z] = true
		}
	case c.Management.AllowWan:
		for _, z := range c.Zones.Keys {
			out[z] = true
		}
	default:
		facing := c.InternetFacingZones()
		for _, z := range c.Zones.Keys {
			if !facing[z] {
				out[z] = true
			}
		}
	}
	return out
}

// checkManagementIPv6 (ROADMAP FND-1c): management over IPv6 goes
// through the same input rules as over IPv4, and a drop/reject rule by
// IPv4 address can't hold there; with such a rule on the management
// ports from a zone managed over IPv6, management.ipv6 is refused.
func checkManagementIPv6(c *Config) {
	if !c.Management.IPv6 || !c.IPv6.Enabled {
		return
	}
	managed := managedZones(c)
	overIPv6 := map[string]bool{}
	for _, z := range c.IPv6LanZones() {
		if managed[z] {
			overIPv6[z] = true
		}
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Action == Accept || r.ToZone != SelfZone || !r.IPv4AddressesOnly() {
			continue
		}
		if r.FromZone != "" && !overIPv6[r.FromZone] {
			continue
		}
		if r.Proto != ProtoAny && r.Proto != ProtoTCP {
			continue
		}
		if r.DstPort != "" {
			lo, hi := portBounds(r.DstPort, "management.ipv6")
			if !(lo <= 22 && 22 <= hi) && !(lo <= 443 && 443 <= hi) {
				continue
			}
		}
		fail("management.ipv6: rule %s keeps hosts off the webUI or SSH by IPv4 address only, which "+
			"IPv6 would get around. Block them by MAC (src_mac) instead, or leave management.ipv6 off", strRepr(r.Name))
	}
}

func parseManagement(raw Value, zones *Ordered[Zone], nat *NatConfig) ManagementConfig {
	m := mapOf(raw, "'management' must be a mapping")
	c := ManagementConfig{AllowWan: boolKey(m, "allow_wan", false, "management.allow_wan must be a boolean")}
	zl, ok := m.getOr("zones", []Value{}).([]Value)
	if !ok {
		fail("management.zones must be a list of zone names")
	}
	internet := internetFacing(zones, nat)
	c.Zones = []string{}
	for _, z := range zl {
		if !inZones(z, zones) {
			fail("management.zones: undefined zone %s", repr(z))
		}
		s := z.(string)
		if internet[s] && !c.AllowWan {
			fail("management.zones: %s faces the internet; managing the router from there "+
				"needs management.allow_wan: true (not recommended -- use a VPN instead)", strRepr(s))
		}
		if !slices.Contains(c.Zones, s) {
			c.Zones = append(c.Zones, s)
		}
	}
	confirm := m.get("confirm_apply_seconds", big.NewInt(confirmApplyDef))
	n, isInt := strictInt(confirm)
	if !isInt || !(n.Sign() == 0 || intIn(n, confirmApplyMin, confirmApplyMax)) {
		fail("management.confirm_apply_seconds must be 0 (off) or %d-%d seconds", confirmApplyMin, confirmApplyMax)
	}
	c.ConfirmApplySeconds = n.Int64()
	al, ok := m.getOr("addresses", []Value{}).([]Value)
	if !ok {
		fail("management.addresses must be a list of IPv4 addresses")
	}
	c.Addresses = []string{}
	for _, a := range al {
		ip, err := parseIPv4Address(a)
		if s, isStr := a.(string); err != nil || !isStr || v4String(ip) != s {
			fail("management.addresses: %s is not an IPv4 address", repr(a))
		}
		if s := a.(string); !slices.Contains(c.Addresses, s) {
			c.Addresses = append(c.Addresses, s)
		}
	}
	c.IPv6 = boolKey(m, "ipv6", false, "management.ipv6 must be true or false")
	return c
}

// checkManagementAddresses (ROADMAP SEC-27): every address the webUI
// and SSH listen on must be on the router, a management zone's interface
// or the VPN's tunnel; a change that would take one away is refused.
func checkManagementAddresses(c *Config) {
	if len(c.Management.Addresses) == 0 {
		return
	}
	allowed := managedZones(c)
	available := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		if i.Address != "" && allowed[i.Zone] {
			available[v4String(mustInterface(i.Address).ip)] = true
		}
	}
	if wg := c.Wireguard; wg.Enabled && wg.Address != "" && allowed[wg.Zone] {
		available[v4String(mustInterface(wg.Address).ip)] = true
	}
	for _, a := range c.Management.Addresses {
		if !available[a] {
			fail("%s is where the webUI and SSH listen (management.addresses), and this change takes it "+
				"off the router. Move them first: System -> webUI address", a)
		}
	}
}

// ValidWireguardKey: 32 bytes in standard base64, 44 characters. With
// Python's b64decode(validate=True) that is 43 alphabet characters and
// one "=".
func ValidWireguardKey(v Value) bool {
	s, ok := v.(string)
	if !ok || len(s) != 44 || s[43] != '=' {
		return false
	}
	for i := 0; i < 43; i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

func parseLogging(raw Value) LoggingConfig {
	m := mapOf(raw, "'logging' must be a mapping")
	c := LoggingConfig{Drops: boolKey(m, "drops", true, "logging.drops must be true or false")}
	rate, ok := strictIntIn(m.get("drops_per_minute", big.NewInt(10)), 1, 10000)
	if !ok {
		fail("logging.drops_per_minute must be 1-10000")
	}
	c.DropsPerMinute = int(rate)
	return c
}

// tunnelZones: the zone of a configured WireGuard tunnel counts as used,
// like an interface's (wg0 isn't under 'interfaces').
func tunnelZones(raw Value) map[string]bool {
	if m, ok := asMap(raw); ok && (truthy(m.get("enabled", nil)) || truthy(m.get("address", nil))) {
		if z, ok := m.get("zone", "vpn").(string); ok {
			return map[string]bool{z: true}
		}
	}
	return nil
}

func parseWireguard(raw Value, zones *Ordered[Zone], nat *NatConfig, interfaces *Ordered[Interface]) WireguardConfig {
	m := mapOf(raw, "'wireguard' must be a mapping")
	if m.Has("private_key") {
		// config.yaml is readable by the webUI; the key stays root's.
		fail("wireguard.private_key must not be in config.yaml; the router keeps its key itself")
	}
	c := WireguardConfig{Enabled: boolKey(m, "enabled", false, "wireguard.enabled must be a boolean"), Peers: []WireguardPeer{}}
	port, ok := strictIntIn(m.get("listen_port", big.NewInt(51820)), 1, 65535)
	if !ok {
		fail("wireguard.listen_port must be a port number (1-65535)")
	}
	c.ListenPort = int(port)

	address := m.getOr("address", "")
	var network *ipv4Net
	var own uint32
	if truthy(address) {
		iface, err := parseIPv4Interface(address)
		if err != nil {
			fail("wireguard.address: %s is not an IPv4 address with a prefix", repr(address))
		}
		n := iface.network()
		if !strings.Contains(pyStr(address), "/") || n.prefix > 30 {
			fail("wireguard.address needs the tunnel's prefix, /30 or wider (e.g. 10.99.0.1/24)")
		}
		if iface.ip == n.addr || iface.ip == n.broadcast() {
			fail("wireguard.address: %s is not a host address", pyStr(address))
		}
		for _, other := range interfaces.Values() {
			if other.Address != "" && mustInterface(other.Address).network().overlaps(n) {
				fail("wireguard.address: the tunnel %s overlaps interface %s (%s)", n, strRepr(other.Name), other.Address)
			}
		}
		network, own, c.Address = &n, iface.ip, iface.String()
	}

	zone := m.get("zone", "vpn")
	if c.Enabled || zone != Value("vpn") {
		if !inZones(zone, zones) {
			fail("wireguard.zone: undefined zone %s (add it under 'zones')", repr(zone))
		}
		if internetFacing(zones, nat)[zone.(string)] {
			fail("wireguard.zone: %s faces the internet; the tunnel needs a zone of its own", repr(zone))
		}
	}
	c.Zone, _ = zone.(string)

	if endpoint := m.getOr("endpoint", ""); truthy(endpoint) {
		if msg := validateHostname(endpoint); msg != "" {
			fail("wireguard.endpoint: %s", msg)
		}
		c.Endpoint = endpoint.(string)
	}

	peers, ok := m.getOr("peers", []Value{}).([]Value)
	if !ok {
		fail("wireguard.peers must be a list")
	}
	names, keys, addrs := map[string]bool{}, map[string]bool{}, map[uint32]bool{}
	for i, item := range peers {
		body, ok := asMap(item)
		if !ok {
			fail("wireguard.peers[%d] must be a mapping", i)
		}
		nameRaw := body.get("name", nil)
		name, ok := nameRaw.(string)
		if !ok || !wgPeerNameRE.MatchString(name) {
			fail("wireguard.peers[%d]: invalid name %s", i, repr(nameRaw))
		}
		if names[name] {
			fail("wireguard.peers[%d]: duplicate name %s", i, strRepr(name))
		}
		key := body.get("public_key", nil)
		if !ValidWireguardKey(key) {
			fail("wireguard.peers[%d] (%s): public_key is not a WireGuard key", i, name)
		}
		if keys[key.(string)] {
			fail("wireguard.peers[%d] (%s): the same public_key is used twice", i, name)
		}
		if network == nil {
			fail("wireguard.peers need wireguard.address (the tunnel subnet)")
		}
		peerAddr := body.get("address", nil)
		pi, err := parseIPv4Interface(peerAddr)
		if err != nil {
			fail("wireguard.peers[%d] (%s): invalid address %s", i, name, repr(peerAddr))
		}
		if pi.prefix != 32 {
			fail("wireguard.peers[%d] (%s): the address must be a single host (/32)", i, name)
		}
		ip := pi.ip
		if !network.contains(ip) || ip == network.addr || ip == network.broadcast() || ip == own {
			fail("wireguard.peers[%d] (%s): %s is not a free host address in %s", i, name, v4String(ip), network)
		}
		if addrs[ip] {
			fail("wireguard.peers[%d] (%s): address %s is used twice", i, name, v4String(ip))
		}
		dual, ok := body.get("dual_stack", false).(bool)
		if !ok {
			fail("wireguard.peers[%d] (%s): dual_stack must be true or false", i, name)
		}
		names[name], keys[key.(string)], addrs[ip] = true, true, true
		c.Peers = append(c.Peers, WireguardPeer{Name: name, PublicKey: key.(string), Address: v4String(ip) + "/32", DualStack: dual})
	}
	if c.Enabled && network == nil {
		fail("wireguard.enabled is true but wireguard.address (the tunnel subnet) is not set")
	}
	return c
}

func parseXdpSniFilter(raw Value, interfaces *Ordered[Interface]) XdpSniFilterConfig {
	m := mapOf(raw, "'xdp_sni_filter' must be a mapping")
	c := XdpSniFilterConfig{Enabled: boolKey(m, "enabled", false, "xdp_sni_filter.enabled must be a boolean"), Interfaces: []string{}, Blocklist: []string{}}
	il, ok := m.get("interfaces", []Value{}).([]Value)
	if !ok {
		fail("xdp_sni_filter.interfaces must be a list")
	}
	for i, n := range il {
		s, ok := n.(string)
		if !ok || !interfaces.Has(s) {
			fail("xdp_sni_filter.interfaces[%d]: %s is not a defined interface", i, repr(n))
		}
		c.Interfaces = append(c.Interfaces, s)
	}
	if c.Enabled && len(c.Interfaces) == 0 {
		fail("xdp_sni_filter.enabled is true but interfaces is empty")
	}
	bl, ok := m.get("blocklist", []Value{}).([]Value)
	if !ok {
		fail("xdp_sni_filter.blocklist must be a list")
	}
	for i, h := range bl {
		// A trailing dot only marks the name fully qualified (RFC 1035
		// 3.1), so "example.com." is the entry "example.com".
		s, ok := h.(string)
		if !ok || !dottedHostname(strings.TrimRight(s, ".")) {
			fail("xdp_sni_filter.blocklist[%d]: invalid hostname %s", i, repr(h))
		}
		if n := len([]rune(s)); n >= maxSNILen {
			fail("xdp_sni_filter.blocklist[%d]: hostname %s is %d bytes, must be under %d "+
				"(the kernel filter's MAX_SNI_LEN) or it is NOT blocked", i, strRepr(s), n, maxSNILen)
		}
		// The form the kernel program builds its key from: ASCII
		// letters in lower case, no trailing dot.
		c.Blocklist = append(c.Blocklist, strings.TrimRight(asciiLower(s), "."))
	}
	return c
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c | 0x20
		}
	}
	return string(b)
}

// httpURL is 1.x's loose `^https?://\S+\Z`: it only catches an
// obviously wrong value; a bad URL fails cleanly when it is fetched.
func httpURL(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(s, "http://"); !ok {
			return false
		}
	}
	return rest != "" && !strings.ContainsFunc(rest, pyIsSpace)
}

func parseURLList(raw Value, what string) []string {
	list, ok := raw.([]Value)
	if !ok {
		fail("%s must be a list", what)
	}
	out := []string{}
	for i, u := range list {
		s, ok := u.(string)
		if !ok || !httpURL(s) {
			fail("%s[%d]: invalid URL %s", what, i, repr(u))
		}
		out = append(out, s)
	}
	return out
}

func parseAdblocker(raw Value, dhcp *DhcpConfig) AdblockerConfig {
	m := mapOf(raw, "'adblocker' must be a mapping")
	c := AdblockerConfig{Enabled: boolKey(m, "enabled", false, "adblocker.enabled must be a boolean")}
	c.SourceURLs = parseURLList(m.get("source_urls", []Value{}), "adblocker.source_urls")
	cats := mapOf(m.getOr("categories", NewMap()), "adblocker.categories must be a mapping of category name -> list of URLs")
	for i, key := range cats.Keys() {
		name := requireName(key, "adblocker category")
		if name == "ads" {
			fail("adblocker.categories: 'ads' is reserved for the base list (adblocker.source_urls)")
		}
		urls := parseURLList(cats.vals[i], "adblocker.categories."+name)
		if len(urls) == 0 {
			fail("adblocker.categories.%s has no URLs", name)
		}
		c.Categories.set(name, urls)
	}
	if c.Enabled && len(c.SourceURLs) == 0 && c.Categories.Len() == 0 {
		fail("adblocker.enabled is true but source_urls and categories are both empty")
	}
	limit := m.get("xdp_critical_limit", big.NewInt(0))
	n, ok := strictInt(limit)
	if !ok {
		fail("adblocker.xdp_critical_limit must be an integer")
	}
	if n.Sign() < 0 {
		fail("adblocker.xdp_critical_limit must be >= 0")
	}
	if !n.IsInt64() {
		fail("adblocker.xdp_critical_limit is too large") // decisions.md: 64-bit integers
	}
	c.XdpCriticalLimit = n.Int64()

	al, ok := m.getOr("allowlist", []Value{}).([]Value)
	if !ok {
		fail("adblocker.allowlist must be a list of domain names")
	}
	c.Allowlist = []string{}
	for i, d := range al {
		s, ok := d.(string)
		if !ok || !strings.Contains(s, ".") || !dottedHostname(strings.TrimRight(s, ".")) {
			fail("adblocker.allowlist[%d]: invalid domain name %s", i, repr(d))
		}
		if s = strings.TrimRight(strings.ToLower(s), "."); !slices.Contains(c.Allowlist, s) {
			c.Allowlist = append(c.Allowlist, s)
		}
	}
	c.ServeLan = boolKey(m, "serve_lan", false, "adblocker.serve_lan must be a boolean")
	c.ForceDNS = boolKey(m, "force_dns", false, "adblocker.force_dns must be a boolean")
	c.QueryLogging = boolKey(m, "query_logging", false, "adblocker.query_logging must be a boolean")
	if c.ForceDNS && !c.ServeLan {
		fail("adblocker.force_dns requires adblocker.serve_lan")
	}
	if c.ServeLan && dhcp.Zones.Len() == 0 {
		fail("adblocker.serve_lan needs at least one DHCP pool -- the resolver is announced " +
			"to, and listens on, the DHCP zones")
	}
	return c
}

func parseIot(raw Value, zones *Ordered[Zone], nat *NatConfig) IotConfig {
	m := mapOf(raw, "'iot' must be a mapping")
	c := IotConfig{Enabled: boolKey(m, "enabled", false, "iot.enabled must be a boolean"), Zones: []string{}}
	zl, ok := m.get("zones", []Value{}).([]Value)
	if !ok {
		fail("iot.zones must be a list of zone names")
	}
	internet := map[string]bool{}
	for _, mq := range nat.Masquerade {
		internet[mq.OutZone] = true
	}
	for _, z := range zl {
		if !inZones(z, zones) {
			fail("iot.zones: undefined zone %s", repr(z))
		}
		s := z.(string)
		if internet[s] {
			fail("iot.zones: %s is an internet-facing (nat.masquerade) zone; "+
				"list the LAN-side zone(s) your devices live in instead", strRepr(s))
		}
		if !slices.Contains(c.Zones, s) {
			c.Zones = append(c.Zones, s)
		}
	}
	if c.Enabled && len(c.Zones) == 0 {
		fail("iot.enabled is true but iot.zones is empty")
	}
	c.AutoIsolate = boolKey(m, "auto_isolate", false, "iot.auto_isolate must be a boolean")
	modeRaw := m.get("isolation_mode", string(IotInternetOnly))
	mode, ok := enumOf(modeRaw, iotModes)
	if !ok {
		fail("iot.isolation_mode: invalid value %s; expected one of %s", repr(modeRaw), reprList(iotModes))
	}
	c.IsolationMode = IotIsolationMode(mode)
	if c.Enabled && c.IsolationMode == IotInternetOnly && len(internet) == 0 {
		fail("iot.isolation_mode 'internet_only' needs at least one nat.masquerade " +
			"entry to know which zone is the internet; add one or use 'block'")
	}
	c.TrustedMacs = parseMacList(m.get("trusted_macs", []Value{}), "iot.trusted_macs", true)
	c.IsolatedMacs = parseMacList(m.get("isolated_macs", []Value{}), "iot.isolated_macs", true)
	var overlap []string
	for _, t := range c.TrustedMacs {
		if slices.Contains(c.IsolatedMacs, t) {
			overlap = append(overlap, t)
		}
	}
	if overlap != nil {
		sort.Strings(overlap)
		fail("iot: MAC(s) listed as both trusted and isolated: %s", repr(overlap))
	}
	return c
}

func parseZtna(raw Value) ZtnaConfig {
	m := mapOf(raw, "'ztna' must be a mapping")
	c := ZtnaConfig{Enabled: boolKey(m, "enabled", false, "ztna.enabled must be a boolean"), Users: []ZtnaUser{}}
	ttl, ok := strictIntIn(m.get("session_ttl_seconds", big.NewInt(8*3600)), ztnaMinTTL, ztnaMaxTTL)
	if !ok {
		fail("ztna.session_ttl_seconds must be an integer between %d and %d (seconds)", ztnaMinTTL, ztnaMaxTTL)
	}
	c.SessionTTLSeconds = ttl
	users, ok := m.get("users", []Value{}).([]Value)
	if !ok {
		fail("ztna.users must be a list")
	}
	seen := map[string]bool{}
	for i, item := range users {
		body, ok := asMap(item)
		if !ok {
			fail("ztna.users[%d] must be a mapping", i)
		}
		uRaw := body.get("username", nil)
		u, ok := uRaw.(string)
		if !ok || !ztnaUserRE.MatchString(u) {
			fail("ztna.users[%d]: invalid username %s", i, repr(uRaw))
		}
		if seen[u] {
			fail("ztna.users[%d]: duplicate username %s", i, strRepr(u))
		}
		seen[u] = true
		// Always already hashed by the webUI; verifying its format is the
		// login's job, which fails closed on anything malformed.
		h, ok := body.get("password_hash", nil).(string)
		if !ok || h == "" {
			fail("ztna.users[%d]: missing or invalid password_hash", i)
		}
		c.Users = append(c.Users, ZtnaUser{Username: u, PasswordHash: h})
	}
	if c.Enabled && len(c.Users) == 0 {
		fail("ztna.enabled is true but no users are configured")
	}
	return c
}

func parseAppControl(raw Value, adblocker *AdblockerConfig, xdp *XdpSniFilterConfig) AppControlConfig {
	m := mapOf(raw, "'app_control' must be a mapping")
	c := AppControlConfig{
		Enabled:     boolKey(m, "enabled", false, "app_control.enabled must be a boolean"),
		BlockViaXdp: boolKey(m, "block_via_xdp", false, "app_control.block_via_xdp must be a boolean"),
		ObserveSni:  boolKey(m, "observe_sni", false, "app_control.observe_sni must be a boolean"),
		BlockedApps: []string{},
	}
	bl, ok := m.get("blocked_apps", []Value{}).([]Value)
	if !ok {
		fail("app_control.blocked_apps must be a list of app ids")
	}
	catalog := mustCatalog()
	for i, item := range bl {
		id, ok := item.(string)
		if !ok || !catalog.Known(id) {
			fail("app_control.blocked_apps[%d]: unknown app %s", i, repr(item))
		}
		if slices.Contains(c.BlockedApps, id) {
			fail("app_control.blocked_apps: %s is listed twice", strRepr(id))
		}
		c.BlockedApps = append(c.BlockedApps, id)
	}
	// Cross-section requirements only matter while the feature is on.
	if c.Enabled {
		if len(c.BlockedApps) > 0 && !(adblocker.Enabled && adblocker.ServeLan) {
			fail("app_control.blocked_apps needs adblocker.enabled and adblocker.serve_lan: " +
				"apps are blocked by the router's DNS resolver")
		}
		if c.BlockViaXdp && !xdp.Enabled {
			fail("app_control.block_via_xdp requires xdp_sni_filter.enabled")
		}
		if c.ObserveSni && !xdp.Enabled {
			fail("app_control.observe_sni requires xdp_sni_filter.enabled")
		}
	}
	return c
}

func mustCatalog() *appid.Catalog {
	c, err := appid.Load()
	if err != nil {
		panic(err) // the embedded catalog is checked by appid's tests
	}
	return c
}

// privateTopLevel: single-label local domains nobody delegates
// publicly; everything under local_dns.domain that isn't a host is
// NXDOMAIN, so "com" there would cut the network off.
var privateTopLevel = []string{"corp", "home", "internal", "intranet", "lan", "localdomain", "private"}

// localDNSName: lower case, no trailing dot, a valid host name (it goes
// into the resolver's config, F1); dotted: at least two labels.
func localDNSName(v Value, what string, dotted bool) string {
	s, ok := v.(string)
	if !ok {
		fail("%s: expected a domain name, got %s", what, repr(v))
	}
	name := strings.TrimRight(pyLower(pyStrip(s)), ".")
	if msg := validateHostname(name); msg != "" {
		fail("%s: %s", what, msg)
	}
	if dotted && !strings.Contains(name, ".") {
		fail("%s: %s needs at least two labels (e.g. nas.lan)", what, strRepr(name))
	}
	return name
}

func parseLocalDNS(raw Value, adblocker *AdblockerConfig, apps *AppControlConfig) LocalDnsConfig {
	m := mapOf(raw, "'local_dns' must be a mapping")
	if unknown := unknownKeys(m, "domain", "hosts", "overrides"); unknown != nil {
		fail("local_dns: unknown key(s) %s", repr(unknown))
	}
	var c LocalDnsConfig
	if d := m.get("domain", nil); truthy(d) {
		c.Domain = localDNSName(d, "local_dns.domain", false)
		if !strings.Contains(c.Domain, ".") && !slices.Contains(privateTopLevel, c.Domain) {
			fail("local_dns.domain: %s could be a public top-level domain; use one of %s or a domain of your own (e.g. home.arpa)",
				strRepr(c.Domain), strings.Join(privateTopLevel, ", "))
		}
	}
	for _, key := range []string{"hosts", "overrides"} {
		table := mapOf(m.getOr(key, NewMap()), fmt.Sprintf("local_dns.%s must be a mapping of name -> IPv4 address", key))
		var out Ordered[string]
		for i, raw := range table.Keys() {
			name := localDNSName(raw, "local_dns."+key, true)
			ip := validateAddress(table.vals[i], fmt.Sprintf("local_dns.%s.%s", key, name))
			if out.Has(name) {
				fail("local_dns.%s: %s is listed twice", key, strRepr(name))
			}
			out.set(name, v4String(ip))
		}
		if key == "hosts" {
			c.Hosts = out
		} else {
			c.Overrides = out
		}
	}
	var both []string
	for _, h := range c.Hosts.Keys {
		if c.Overrides.Has(h) {
			both = append(both, h)
		}
	}
	if both != nil {
		sort.Strings(both)
		fail("local_dns: %s is both a host and an override", strRepr(both[0]))
	}
	if c.Hosts.Len()+c.Overrides.Len() > localDNSMaxEntries {
		fail("local_dns: at most %d hosts and overrides", localDNSMaxEntries)
	}
	if (c.Hosts.Len() > 0 || c.Overrides.Len() > 0 || c.Domain != "") && !(adblocker.Enabled && adblocker.ServeLan) {
		fail("local_dns needs adblocker.enabled and adblocker.serve_lan: local names are " +
			"answered by the router's DNS resolver")
	}
	// A blocked app's names are NXDOMAIN in the same resolver: one name
	// can't be both.
	if apps.Enabled && len(apps.BlockedApps) > 0 {
		blocked := mustCatalog().BlockingNames(apps.BlockedApps)
		names := append(slices.Clone(c.Hosts.Keys), c.Overrides.Keys...)
		if c.Domain != "" {
			names = append(names, c.Domain)
		}
		for _, n := range names {
			for _, b := range blocked {
				if n == b || strings.HasSuffix(n, "."+b) || strings.HasSuffix(b, "."+n) {
					fail("local_dns: %s overlaps the blocked app name %s", strRepr(n), strRepr(b))
				}
			}
		}
	}
	return c
}

var dayGroups = map[string][]int{"daily": {0, 1, 2, 3, 4, 5, 6}, "weekdays": {0, 1, 2, 3, 4}, "weekend": {5, 6}}
var dayKeys = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

func parseHHMM(v Value, what string) int {
	s, ok := v.(string)
	if !ok || !hhmmRE.MatchString(s) {
		fail("%s must be a \"HH:MM\" time (00:00-24:00), got %s", what, repr(v))
	}
	h, _ := strconv.Atoi(s[:2])
	mm, _ := strconv.Atoi(s[3:])
	return h*60 + mm
}

func parseSchedule(raw Value, what string, action Action) *RuleSchedule {
	m, ok := asMap(raw)
	if !ok {
		fail("%s must be a mapping", what)
	}
	daysRaw := m.get("days", []Value{"daily"})
	if s, ok := daysRaw.(string); ok {
		daysRaw = []Value{s}
	}
	list, ok := daysRaw.([]Value)
	if !ok || len(list) == 0 {
		fail("%s.days must be a non-empty list (mon..sun, weekdays, weekend, daily)", what)
	}
	set := map[int]bool{}
	for _, d := range list {
		key, isStr := d.(string)
		if isStr {
			key = pyLower(key)
		}
		if g, ok := dayGroups[key]; isStr && ok {
			for _, x := range g {
				set[x] = true
			}
		} else if i := slices.Index(dayKeys, key); isStr && i >= 0 {
			set[i] = true
		} else {
			fail("%s.days: unknown day %s (mon..sun, weekdays, weekend, daily)", what, repr(d))
		}
	}
	s := &RuleSchedule{}
	for d := range 7 {
		if set[d] {
			s.Days = append(s.Days, d)
		}
	}
	s.Start = parseHHMM(m.get("start", nil), what+".start")
	s.End = parseHHMM(m.get("end", nil), what+".end")
	if s.Start == 24*60 {
		fail("%s.start cannot be 24:00", what)
	}
	if s.Start == s.End {
		fail("%s: start and end are both %s; use 00:00-24:00 for a whole day", what, pyStr(m.get("start", nil)))
	}
	cut, ok := m.get("cut_established", false).(bool)
	if !ok {
		fail("%s.cut_established must be a boolean", what)
	}
	if cut && action == Accept {
		fail("%s.cut_established only applies to drop/reject rules", what)
	}
	s.CutEstablished = cut
	return s
}

func parseTlsFingerprint(raw Value, xdp *XdpSniFilterConfig) TlsFingerprintConfig {
	m := mapOf(raw, "'tls_fingerprint' must be a mapping")
	c := TlsFingerprintConfig{
		Enabled:           boolKey(m, "enabled", false, "tls_fingerprint.enabled must be a boolean"),
		QuarantineOnMatch: boolKey(m, "quarantine_on_match", false, "tls_fingerprint.quarantine_on_match must be a boolean"),
		Blocklist:         []TlsFingerprintEntry{},
	}
	bl, ok := m.get("blocklist", []Value{}).([]Value)
	if !ok {
		fail("tls_fingerprint.blocklist must be a list")
	}
	seen := map[string]bool{}
	for i, item := range bl {
		if s, ok := item.(string); ok {
			e := NewMap()
			e.Set("fingerprint", s)
			item = e
		}
		body, ok := asMap(item)
		if !ok {
			fail("tls_fingerprint.blocklist[%d] must be a mapping or a string", i)
		}
		fp, ok := body.get("fingerprint", nil).(string)
		if !ok {
			fail("tls_fingerprint.blocklist[%d].fingerprint is required", i)
		}
		fp = pyLower(pyStrip(fp))
		if !ja4RE.MatchString(fp) && !ja3RE.MatchString(fp) {
			fail("tls_fingerprint.blocklist[%d]: %s is neither a JA4 fingerprint "+
				"(e.g. t13d1516h2_8daaf6152771_e5627efa2ab1) nor a 32-hex-digit JA3 hash", i, strRepr(fp))
		}
		if seen[fp] {
			fail("tls_fingerprint.blocklist: %s is listed twice", strRepr(fp))
		}
		seen[fp] = true
		label, ok := body.get("label", "").(string)
		if !ok || len([]rune(label)) > 80 {
			fail("tls_fingerprint.blocklist[%d].label must be a string of at most 80 characters", i)
		}
		c.Blocklist = append(c.Blocklist, TlsFingerprintEntry{Fingerprint: fp, Label: label})
	}
	if c.Enabled && !xdp.Enabled {
		fail("tls_fingerprint.enabled requires xdp_sni_filter.enabled: the XDP program " +
			"on the LAN-side interfaces is what hands over the ClientHellos")
	}
	return c
}

func parseMetrics(raw Value) MetricsConfig {
	m := mapOf(raw, "'metrics' must be a mapping")
	var c MetricsConfig
	if site := m.get("site", nil); site != nil {
		s, ok := site.(string)
		if !ok || !siteRE.MatchString(s) {
			fail("metrics.site must be lowercase letters, digits, '.', '_', '-' (max 63), e.g. budapest-office")
		}
		c.Site = &s
	}
	if token := m.get("token_sha256", nil); token != nil {
		s, ok := token.(string)
		if !ok || !tokenSHA256RE.MatchString(s) {
			fail("metrics.token_sha256 must be a 64-character lowercase SHA-256 hex digest")
		}
		c.TokenSHA256 = &s
	}
	return c
}
