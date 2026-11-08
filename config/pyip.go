package config

import (
	"fmt"
	"math/big"
	"math/bits"
	"strconv"
	"strings"
)

// Addresses and networks as Python's ipaddress module reads and writes
// them. 1.x validates every address with it, so what it accepts (a
// netmask after the slash, an IPv4 tail on an IPv6 address, a scope after
// a "%", a whole number for an IPv4 interface) and how it prints the
// result (the normalized form goes into the nft script) are the
// specification here. The error texts are ipaddress's too: 1.x puts them
// in its messages.

type ipError struct{ msg string }

func (e *ipError) Error() string { return e.msg }

func ipErr(format string, args ...any) error { return &ipError{fmt.Sprintf(format, args...)} }

// u128 is an IPv6 address as a number.
type u128 struct{ hi, lo uint64 }

func (a u128) and(b u128) u128 { return u128{a.hi & b.hi, a.lo & b.lo} }
func (a u128) or(b u128) u128  { return u128{a.hi | b.hi, a.lo | b.lo} }
func (a u128) not() u128       { return u128{^a.hi, ^a.lo} }
func (a u128) cmp(b u128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

// mask128 is the netmask of a prefix length.
func mask128(prefix int) u128 {
	switch {
	case prefix <= 0:
		return u128{}
	case prefix < 64:
		return u128{^uint64(0) << (64 - prefix), 0}
	case prefix == 64:
		return u128{^uint64(0), 0}
	case prefix < 128:
		return u128{^uint64(0), ^uint64(0) << (128 - prefix)}
	}
	return u128{^uint64(0), ^uint64(0)}
}

func mask32(prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	return ^uint32(0) << (32 - prefix)
}

// IPv4 -----------------------------------------------------------------

func parseOctet(s string) (uint32, error) {
	if s == "" {
		return 0, ipErr("Empty octet not permitted")
	}
	if !isASCIIDigits(s) {
		return 0, ipErr("Only decimal digits permitted in %s", strRepr(s))
	}
	if len(s) > 3 {
		return 0, ipErr("At most 3 characters permitted in %s", strRepr(s))
	}
	if s != "0" && s[0] == '0' {
		return 0, ipErr("Leading zeros are not permitted in %s", strRepr(s))
	}
	n, _ := strconv.Atoi(s)
	if n > 255 {
		return 0, ipErr("Octet %d (> 255) not permitted", n)
	}
	return uint32(n), nil
}

// v4FromString is IPv4Address._ip_int_from_string.
func v4FromString(s string) (uint32, error) {
	if s == "" {
		return 0, ipErr("Address cannot be empty")
	}
	octets := strings.Split(s, ".")
	if len(octets) != 4 {
		return 0, ipErr("Expected 4 octets in %s", strRepr(s))
	}
	var ip uint32
	for _, o := range octets {
		n, err := parseOctet(o)
		if err != nil {
			return 0, ipErr("%s in %s", err, strRepr(s))
		}
		ip = ip<<8 | n
	}
	return ip, nil
}

func v4String(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, ip>>16&0xff, ip>>8&0xff, ip&0xff)
}

// v4FromInt is IPv4Address(int).
func v4FromInt(n *big.Int) (uint32, error) {
	if n.Sign() < 0 {
		return 0, ipErr("%s (< 0) is not permitted as an IPv4 address", n)
	}
	if n.BitLen() > 32 {
		return 0, ipErr("%s (>= 2**32) is not permitted as an IPv4 address", n)
	}
	return uint32(n.Uint64()), nil
}

// parseIPv4Address is IPv4Address(value) for a value from a config: a
// string, or a whole number (a bool is one too).
func parseIPv4Address(v Value) (uint32, error) {
	if isInt(v) {
		return v4FromInt(intOf(v))
	}
	s := pyStr(v)
	if strings.Contains(s, "/") {
		return 0, ipErr("Unexpected '/' in %s", repr(v))
	}
	return v4FromString(s)
}

// prefixFromPrefixString is _prefix_from_prefix_string.
func prefixFromPrefixString(s string, max int) (int, error) {
	if !isASCIIDigits(s) {
		return 0, ipErr("%s is not a valid netmask", strRepr(s))
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > max {
		return 0, ipErr("%s is not a valid netmask", strRepr(s))
	}
	return n, nil
}

// v4PrefixFromMask is the prefix of a netmask, or false if the bits are
// mixed.
func v4PrefixFromMask(m uint32) (int, bool) {
	ones := bits.LeadingZeros32(^m)
	return ones, mask32(ones) == m
}

// v4MakeNetmask is IPv4's _make_netmask for the text after the slash: a
// prefix length, a netmask or a hostmask.
func v4MakeNetmask(s string) (int, error) {
	if p, err := prefixFromPrefixString(s, 32); err == nil {
		return p, nil
	}
	m, err := v4FromString(s)
	if err != nil {
		return 0, ipErr("%s is not a valid netmask", strRepr(s))
	}
	if p, ok := v4PrefixFromMask(m); ok {
		return p, nil
	}
	if p, ok := v4PrefixFromMask(^m); ok {
		return p, nil
	}
	return 0, ipErr("%s is not a valid netmask", strRepr(s))
}

// splitAddrPrefix is _split_addr_prefix for a non-integer value: the
// text, split at its one slash.
func splitAddrPrefix(v Value) (addr string, mask string, hasMask bool, err error) {
	parts := strings.Split(pyStr(v), "/")
	if len(parts) > 2 {
		return "", "", false, ipErr("Only one '/' permitted in %s", repr(v))
	}
	if len(parts) == 2 {
		return parts[0], parts[1], true, nil
	}
	return parts[0], "", false, nil
}

// ipv4Interface is an IPv4Interface: the address keeps its host bits.
type ipv4Interface struct {
	ip     uint32
	prefix int
}

func (i ipv4Interface) String() string   { return fmt.Sprintf("%s/%d", v4String(i.ip), i.prefix) }
func (i ipv4Interface) network() ipv4Net { return ipv4Net{i.ip & mask32(i.prefix), i.prefix} }

// parseIPv4Interface is IPv4Interface(value).
func parseIPv4Interface(v Value) (ipv4Interface, error) {
	if isInt(v) {
		ip, err := v4FromInt(intOf(v))
		return ipv4Interface{ip, 32}, err
	}
	addr, mask, hasMask, err := splitAddrPrefix(v)
	if err != nil {
		return ipv4Interface{}, err
	}
	ip, err := v4FromString(addr)
	if err != nil {
		return ipv4Interface{}, err
	}
	prefix := 32
	if hasMask {
		if prefix, err = v4MakeNetmask(mask); err != nil {
			return ipv4Interface{}, err
		}
	}
	return ipv4Interface{ip, prefix}, nil
}

type ipv4Net struct {
	addr   uint32
	prefix int
}

func (n ipv4Net) String() string          { return fmt.Sprintf("%s/%d", v4String(n.addr), n.prefix) }
func (n ipv4Net) broadcast() uint32       { return n.addr | ^mask32(n.prefix) }
func (n ipv4Net) contains(ip uint32) bool { return ip&mask32(n.prefix) == n.addr }
func (n ipv4Net) overlaps(o ipv4Net) bool {
	return o.contains(n.addr) || o.contains(n.broadcast()) || n.contains(o.addr) || n.contains(o.broadcast())
}

// parseIPv4Network is IPv4Network(text, strict).
func parseIPv4Network(s string, strict bool) (ipv4Net, error) {
	addr, mask, hasMask, err := splitAddrPrefix(s)
	if err != nil {
		return ipv4Net{}, err
	}
	ip, err := v4FromString(addr)
	if err != nil {
		return ipv4Net{}, err
	}
	prefix := 32
	if hasMask {
		if prefix, err = v4MakeNetmask(mask); err != nil {
			return ipv4Net{}, err
		}
	}
	n := ipv4Net{ip & mask32(prefix), prefix}
	if strict && n.addr != ip {
		return ipv4Net{}, fmt.Errorf("%s/%d has host bits set", v4String(ip), prefix)
	}
	return n, nil
}

// IPv6 -----------------------------------------------------------------

// ipv6Addr is an IPv6Address; scope is set when the text had a "%".
type ipv6Addr struct {
	ip       u128
	scope    string
	hasScope bool
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func parseHextet(s string) (uint64, error) {
	if !isHex(s) {
		return 0, ipErr("Only hex digits permitted in %s", strRepr(s))
	}
	if len(s) > 4 {
		return 0, ipErr("At most 4 characters permitted in %s", strRepr(s))
	}
	if s == "" {
		// int('', 16) fails; ipaddress passes on its message.
		return 0, ipErr("invalid literal for int() with base 16: ''")
	}
	n, _ := strconv.ParseUint(s, 16, 16)
	return n, nil
}

// v6FromString is IPv6Address._ip_int_from_string.
func v6FromString(s string) (u128, error) {
	if s == "" {
		return u128{}, ipErr("Address cannot be empty")
	}
	if n := len([]rune(s)); n > 45 {
		short := s
		if n > 100 {
			r := []rune(s)
			short = fmt.Sprintf("%s(%d chars elided)%s", string(r[:45]), n-90, string(r[n-45:]))
		}
		return u128{}, ipErr("At most 45 characters expected in %s", strRepr(short))
	}
	const hextets, maxParts = 8, 9
	parts := strings.SplitN(s, ":", maxParts+1)
	if len(parts) < 3 {
		return u128{}, ipErr("At least 3 parts expected in %s", strRepr(s))
	}
	if strings.Contains(parts[len(parts)-1], ".") {
		v4, err := v4FromString(parts[len(parts)-1])
		if err != nil {
			return u128{}, ipErr("%s in %s", err, strRepr(s))
		}
		parts = append(parts[:len(parts)-1], fmt.Sprintf("%x", v4>>16), fmt.Sprintf("%x", v4&0xffff))
	}
	if len(parts) > maxParts {
		return u128{}, ipErr("At most %d colons permitted in %s", maxParts-1, strRepr(s))
	}
	skip := -1
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			if skip >= 0 {
				return u128{}, ipErr("At most one '::' permitted in %s", strRepr(s))
			}
			skip = i
		}
	}
	var hi, lo, skipped int
	if skip >= 0 {
		hi, lo = skip, len(parts)-skip-1
		if parts[0] == "" {
			if hi--; hi != 0 {
				return u128{}, ipErr("Leading ':' only permitted as part of '::' in %s", strRepr(s))
			}
		}
		if parts[len(parts)-1] == "" {
			if lo--; lo != 0 {
				return u128{}, ipErr("Trailing ':' only permitted as part of '::' in %s", strRepr(s))
			}
		}
		skipped = hextets - (hi + lo)
		if skipped < 1 {
			return u128{}, ipErr("Expected at most %d other parts with '::' in %s", hextets-1, strRepr(s))
		}
	} else {
		if len(parts) != hextets {
			return u128{}, ipErr("Exactly %d parts expected without '::' in %s", hextets, strRepr(s))
		}
		if parts[0] == "" {
			return u128{}, ipErr("Leading ':' only permitted as part of '::' in %s", strRepr(s))
		}
		if parts[len(parts)-1] == "" {
			return u128{}, ipErr("Trailing ':' only permitted as part of '::' in %s", strRepr(s))
		}
		hi = len(parts)
	}
	var words [8]uint64
	w := 0
	for i := 0; i < hi; i++ {
		n, err := parseHextet(parts[i])
		if err != nil {
			return u128{}, ipErr("%s in %s", err, strRepr(s))
		}
		words[w] = n
		w++
	}
	w += skipped
	for i := len(parts) - lo; i < len(parts); i++ {
		n, err := parseHextet(parts[i])
		if err != nil {
			return u128{}, ipErr("%s in %s", err, strRepr(s))
		}
		words[w] = n
		w++
	}
	var ip u128
	for i := 0; i < 4; i++ {
		ip.hi = ip.hi<<16 | words[i]
		ip.lo = ip.lo<<16 | words[i+4]
	}
	return ip, nil
}

// parseIPv6Address is IPv6Address(text): a "%scope" is allowed, as in
// Python, and kept (callers refuse it).
func parseIPv6Address(s string) (ipv6Addr, error) {
	if strings.Contains(s, "/") {
		return ipv6Addr{}, ipErr("Unexpected '/' in %s", strRepr(s))
	}
	addr, scope, found := strings.Cut(s, "%")
	if found && (scope == "" || strings.Contains(scope, "%")) {
		return ipv6Addr{}, ipErr("Invalid IPv6 address: \"%s\"", strRepr(s))
	}
	ip, err := v6FromString(addr)
	if err != nil {
		return ipv6Addr{}, err
	}
	return ipv6Addr{ip, scope, found}, nil
}

// v6Compressed is IPv6's _string_from_ip_int: hextets in hex, the first
// longest run of two or more zero hextets as "::".
func v6Compressed(ip u128) string {
	var h [8]string
	for i := 0; i < 4; i++ {
		h[i] = fmt.Sprintf("%x", ip.hi>>(48-16*i)&0xffff)
		h[i+4] = fmt.Sprintf("%x", ip.lo>>(48-16*i)&0xffff)
	}
	return compressHextets(h[:])
}

func compressHextets(h []string) string {
	bestStart, bestLen, start, n := -1, 0, -1, 0
	for i, x := range h {
		if x == "0" {
			n++
			if start == -1 {
				start = i
			}
			if n > bestLen {
				bestLen, bestStart = n, start
			}
		} else {
			n, start = 0, -1
		}
	}
	if bestLen <= 1 {
		return strings.Join(h, ":")
	}
	left := strings.Join(h[:bestStart], ":")
	right := strings.Join(h[bestStart+bestLen:], ":")
	return left + "::" + right
}

func (a ipv6Addr) String() string {
	var s string
	if a.ip.hi == 0 && a.ip.lo>>32 == 0xffff {
		// IPv4-mapped: Python 3.13 writes the IPv4 part in dotted decimal.
		s = "::ffff:" + v4String(uint32(a.ip.lo))
	} else {
		s = v6Compressed(a.ip)
	}
	if a.hasScope {
		s += "%" + a.scope
	}
	return s
}

type ipv6Net struct {
	addr   ipv6Addr // the scope survives only when no host bits were masked off
	prefix int
}

func (n ipv6Net) String() string  { return fmt.Sprintf("%s/%d", n.addr, n.prefix) }
func (n ipv6Net) broadcast() u128 { return n.addr.ip.or(mask128(n.prefix).not()) }
func (n ipv6Net) contains(ip u128) bool {
	return ip.and(mask128(n.prefix)) == n.addr.ip
}
func (n ipv6Net) overlaps(o ipv6Net) bool {
	return o.contains(n.addr.ip) || o.contains(n.broadcast()) || n.contains(o.addr.ip) || n.contains(o.broadcast())
}
func (n ipv6Net) subnetOf(o ipv6Net) bool {
	return o.addr.ip.cmp(n.addr.ip) <= 0 && o.broadcast().cmp(n.broadcast()) >= 0
}
func (n ipv6Net) equal(o ipv6Net) bool { return n.addr.ip == o.addr.ip && n.prefix == o.prefix }

// parseIPv6Network is IPv6Network(text, strict).
func parseIPv6Network(s string, strict bool) (ipv6Net, error) {
	addr, mask, hasMask, err := splitAddrPrefix(s)
	if err != nil {
		return ipv6Net{}, err
	}
	a, err := parseIPv6Address(addr)
	if err != nil {
		return ipv6Net{}, err
	}
	prefix := 128
	if hasMask {
		if prefix, err = prefixFromPrefixString(mask, 128); err != nil {
			return ipv6Net{}, err
		}
	}
	masked := a.ip.and(mask128(prefix))
	if masked != a.ip {
		if strict {
			return ipv6Net{}, fmt.Errorf("%s/%d has host bits set", a, prefix)
		}
		a = ipv6Addr{ip: masked}
	}
	return ipv6Net{a, prefix}, nil
}

func mustV6Net(s string) ipv6Net {
	n, err := parseIPv6Network(s, true)
	if err != nil {
		panic(err)
	}
	return n
}

// ipNet is ip_network's result: one of the two families.
type ipNet struct {
	version int
	v4      ipv4Net
	v6      ipv6Net
}

func (n ipNet) String() string {
	if n.version == 4 {
		return n.v4.String()
	}
	return n.v6.String()
}

// parseIPNetwork is ip_network(text, strict=False): IPv4 first, then
// IPv6.
func parseIPNetwork(s string) (ipNet, error) {
	if n, err := parseIPv4Network(s, false); err == nil {
		return ipNet{version: 4, v4: n}, nil
	}
	if n, err := parseIPv6Network(s, false); err == nil {
		return ipNet{version: 6, v6: n}, nil
	}
	return ipNet{}, ipErr("%s does not appear to be an IPv4 or IPv6 network", strRepr(s))
}
