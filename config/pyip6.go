package config

import (
	"math/big"
	"strconv"
)

// Python's IPv6Interface and IPv6Network for the apply-helper's views of
// the kernel's IPv6 state (frfw.ipv6.status): `ip -j -6` writes the
// addresses and routes, which 1.x reads with ipaddress and words its
// errors after.

// PyIPv6Interface is an ipaddress.IPv6Interface: the address with its
// host bits (and scope) and its network.
type PyIPv6Interface struct {
	addr ipv6Addr
	net  ipv6Net
}

// ParsePyIPv6Interface is IPv6Interface(text): the address is read
// first, then the prefix length.
func ParsePyIPv6Interface(text string) (PyIPv6Interface, error) {
	addr, mask, hasMask, err := splitAddrPrefix(text)
	if err != nil {
		return PyIPv6Interface{}, err
	}
	a, err := parseIPv6Address(addr)
	if err != nil {
		return PyIPv6Interface{}, err
	}
	prefix := 128
	if hasMask {
		if prefix, err = prefixFromPrefixString(mask, 128); err != nil {
			return PyIPv6Interface{}, err
		}
	}
	n := ipv6Net{a, prefix}
	if masked := a.ip.and(mask128(prefix)); masked != a.ip {
		n.addr = ipv6Addr{ip: masked}
	}
	return PyIPv6Interface{a, n}, nil
}

// String is str(i): "address/prefixlen", the scope included.
func (i PyIPv6Interface) String() string { return i.addr.String() + "/" + strconv.Itoa(i.net.prefix) }

// Prefix is its prefix length.
func (i PyIPv6Interface) Prefix() int { return i.net.prefix }

// Network is i.network.
func (i PyIPv6Interface) Network() IPv6Network { return IPv6Network{i.net} }

// InULA is `i.ip in IPv6Network("fc00::/7")`.
func (i PyIPv6Interface) InULA() bool { return ulaNet.contains(i.addr.ip) }

var (
	ulaNet       = mustV6Net("fc00::/7")
	linkLocalNet = mustV6Net("fe80::/10")
	multicastNet = mustV6Net("ff00::/8")
)

// ParsePyIPv6Network is IPv6Network(v), strict: an int (a bool too) is
// one address, /128; anything else is read as its str().
func ParsePyIPv6Network(v Value) (IPv6Network, error) {
	if isInt(v) {
		a, err := ParsePyIPv6(v)
		if err != nil {
			return IPv6Network{}, err
		}
		return IPv6Network{ipv6Net{a.v6, 128}}, nil
	}
	n, err := parseIPv6Network(pyStr(v), true)
	return IPv6Network{n}, err
}

// IsLinkLocal, IsMulticast and IsLoopback are the network's: true when
// its first and its last address both are.
func (n IPv6Network) IsLinkLocal() bool {
	return linkLocalNet.contains(n.n.addr.ip) && linkLocalNet.contains(n.n.broadcast())
}

func (n IPv6Network) IsMulticast() bool {
	return multicastNet.contains(n.n.addr.ip) && multicastNet.contains(n.n.broadcast())
}

func (n IPv6Network) IsLoopback() bool {
	one := u128{0, 1}
	return n.n.addr.ip == one && n.n.broadcast() == one
}

// AddressPlus is `n.network_address + k`: an IPv6Address, refused past
// the last one.
func (n IPv6Network) AddressPlus(k *big.Int) (PyAddr, error) {
	base := PyAddr{version: 6, v6: ipv6Addr{ip: n.n.addr.ip}}
	return ParsePyIPv6(new(big.Int).Add(base.Int(), k))
}
