package config

import (
	"errors"
	"math/big"
	"strings"
)

// Python's ipaddress for other packages of this module: the ruleset
// builder re-checks the addresses it carries over a reload (they come
// from `nft -j` output) and prints them as 1.x does.

// IPv4Address is str(ipaddress.IPv4Address(text)).
func IPv4Address(text string) (string, error) {
	ip, err := parseIPv4Address(text)
	if err != nil {
		return "", err
	}
	return v4String(ip), nil
}

// IPAddress is ipaddress.ip_address(text): its text and its version.
func IPAddress(text string) (string, int, error) {
	if ip, err := parseIPv4Address(text); err == nil {
		return v4String(ip), 4, nil
	}
	a, err := parseIPv6Address(text)
	if err != nil {
		return "", 0, ipErr("%s does not appear to be an IPv4 or IPv6 address", strRepr(text))
	}
	return a.String(), 6, nil
}

// IPv6Network is ipaddress.IPv6Network(text): strict, so host bits set
// are an error.
type IPv6Network struct{ n ipv6Net }

// ParseIPv6Network is IPv6Network(text).
func ParseIPv6Network(text string) (IPv6Network, error) {
	n, err := parseIPv6Network(text, true)
	return IPv6Network{n}, err
}

func (n IPv6Network) String() string { return n.n.String() }

// Prefix is its prefix length.
func (n IPv6Network) Prefix() int { return n.n.prefix }

// Address is its network address.
func (n IPv6Network) Address() string { return n.n.addr.String() }

// Equal is Python's ==.
func (n IPv6Network) Equal(o IPv6Network) bool { return n.n.equal(o.n) }

// SubnetOf is subnet_of.
func (n IPv6Network) SubnetOf(o IPv6Network) bool { return n.n.subnetOf(o.n) }

// PyAddr is an ipaddress.IPv4Address or IPv6Address: what the
// apply-helper's commands check the addresses of a request, and of the
// kernel's neighbour table, with (frfw.ztna, frfw.bruteforce,
// frfw.ids_quarantine).
type PyAddr struct {
	version int
	v4      uint32
	v6      ipv6Addr
}

// ParsePyIPv4 is IPv4Address(v).
func ParsePyIPv4(v Value) (PyAddr, error) {
	ip, err := parseIPv4Address(v)
	if err != nil {
		return PyAddr{}, err
	}
	return PyAddr{version: 4, v4: ip}, nil
}

// ParsePyIPv6 is IPv6Address(v).
func ParsePyIPv6(v Value) (PyAddr, error) {
	if isInt(v) {
		n := intOf(v)
		if n.Sign() < 0 {
			return PyAddr{}, ipErr("%s (< 0) is not permitted as an IPv6 address", n)
		}
		if n.BitLen() > 128 {
			return PyAddr{}, ipErr("%s (>= 2**128) is not permitted as an IPv6 address", n)
		}
		return pyAddr6(n), nil
	}
	a, err := parseIPv6Address(pyStr(v))
	if err != nil {
		var ie *ipError
		if errors.As(err, &ie) && strings.HasPrefix(ie.msg, "Unexpected '/' in ") {
			return PyAddr{}, ipErr("Unexpected '/' in %s", repr(v))
		}
		return PyAddr{}, err
	}
	return PyAddr{version: 6, v6: a}, nil
}

// ParsePyIP is ip_address(v): IPv4 first, then IPv6.
func ParsePyIP(v Value) (PyAddr, error) {
	if a, err := ParsePyIPv4(v); err == nil {
		return a, nil
	}
	if a, err := ParsePyIPv6(v); err == nil {
		return a, nil
	}
	return PyAddr{}, ipErr("%s does not appear to be an IPv4 or IPv6 address", repr(v))
}

func pyAddr6(n *big.Int) PyAddr {
	var b [16]byte
	n.FillBytes(b[:])
	var ip u128
	for i := 0; i < 8; i++ {
		ip.hi = ip.hi<<8 | uint64(b[i])
		ip.lo = ip.lo<<8 | uint64(b[i+8])
	}
	return PyAddr{version: 6, v6: ipv6Addr{ip: ip}}
}

// PyAddrFromInt is IPv4Address(n) or IPv6Address(n).
func PyAddrFromInt(version int, n *big.Int) (PyAddr, error) {
	if version == 4 {
		ip, err := v4FromInt(n)
		return PyAddr{version: 4, v4: ip}, err
	}
	return ParsePyIPv6(n)
}

// Version is 4 or 6.
func (a PyAddr) Version() int { return a.version }

// String is str(a): an IPv6 scope included.
func (a PyAddr) String() string {
	if a.version == 4 {
		return v4String(a.v4)
	}
	return a.v6.String()
}

// HasScope is `a.scope_id is not None`.
func (a PyAddr) HasScope() bool { return a.version == 6 && a.v6.hasScope }

// Int is int(a).
func (a PyAddr) Int() *big.Int {
	if a.version == 4 {
		return new(big.Int).SetUint64(uint64(a.v4))
	}
	n := new(big.Int).SetUint64(a.v6.ip.hi)
	return n.Lsh(n, 64).Or(n, new(big.Int).SetUint64(a.v6.ip.lo))
}

// IPv4Mapped is a.ipv4_mapped: ::ffff:a.b.c.d as a.b.c.d.
func (a PyAddr) IPv4Mapped() (PyAddr, bool) {
	if a.version != 6 || a.v6.ip.hi != 0 || a.v6.ip.lo>>32 != 0xffff {
		return PyAddr{}, false
	}
	return PyAddr{version: 4, v4: uint32(a.v6.ip.lo)}, true
}

// Equal is ==: the same family, address and (IPv6) scope.
func (a PyAddr) Equal(o PyAddr) bool {
	if a.version != o.version {
		return false
	}
	if a.version == 4 {
		return a.v4 == o.v4
	}
	return a.v6 == o.v6
}

// In is `a in network`, network an IPv4 or IPv6 network's text.
func (a PyAddr) in(network string) bool {
	if a.version == 4 {
		n, _ := parseIPv4Network(network, true)
		return n.contains(a.v4)
	}
	return mustV6Net(network).contains(a.v6.ip)
}

// Python 3.13's ipaddress: an IPv4-mapped IPv6 address answers as its
// IPv4 address does.
func (a PyAddr) mapped() PyAddr {
	if m, ok := a.IPv4Mapped(); ok {
		return m
	}
	return a
}

// IsLoopback is a.is_loopback.
func (a PyAddr) IsLoopback() bool {
	a = a.mapped()
	if a.version == 4 {
		return a.in("127.0.0.0/8")
	}
	return a.v6.ip == u128{0, 1}
}

// IsUnspecified is a.is_unspecified.
func (a PyAddr) IsUnspecified() bool {
	a = a.mapped()
	if a.version == 4 {
		return a.v4 == 0
	}
	return a.v6.ip == u128{}
}

// IsMulticast is a.is_multicast.
func (a PyAddr) IsMulticast() bool {
	a = a.mapped()
	if a.version == 4 {
		return a.in("224.0.0.0/4")
	}
	return a.in("ff00::/8")
}

// IsLinkLocal is a.is_link_local.
func (a PyAddr) IsLinkLocal() bool {
	a = a.mapped()
	if a.version == 4 {
		return a.in("169.254.0.0/16")
	}
	return a.in("fe80::/10")
}

// reserved6 are IPv6's _reserved_networks.
var reserved6 = []string{"::/8", "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "4000::/3", "6000::/3",
	"8000::/3", "a000::/3", "c000::/3", "e000::/4", "f000::/5", "f800::/6", "fe00::/9"}

// IsReserved is a.is_reserved.
func (a PyAddr) IsReserved() bool {
	a = a.mapped()
	if a.version == 4 {
		return a.in("240.0.0.0/4")
	}
	for _, n := range reserved6 {
		if a.in(n) {
			return true
		}
	}
	return false
}

// IPv4InterfaceOf is IPv4Interface(text): the address, and its
// network's address and prefix length.
func IPv4InterfaceOf(text string) (ip, network PyAddr, prefix int, err error) {
	i, err := parseIPv4Interface(text)
	if err != nil {
		return PyAddr{}, PyAddr{}, 0, err
	}
	n := i.network()
	return PyAddr{version: 4, v4: i.ip}, PyAddr{version: 4, v4: n.addr}, n.prefix, nil
}
