package config

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
