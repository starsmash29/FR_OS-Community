package config

import "testing"

// Expected values are what Python 3.13's ipaddress printed for each
// input: str(ip_network(s, strict=False)) and str(IPv4Interface(s)), or
// "ERR " and the exception's message.
var ipCases = []struct{ in, network, iface string }{
	{"10.0.0.1", "10.0.0.1/32", "10.0.0.1/32"},
	{"10.0.0.1/24", "10.0.0.0/24", "10.0.0.1/24"},
	{"10.0.0.1/255.255.255.0", "10.0.0.0/24", "10.0.0.1/24"},
	{"10.0.0.1/0.0.0.255", "10.0.0.0/24", "10.0.0.1/24"},
	{"10.0.0.1/024", "10.0.0.0/24", "10.0.0.1/24"},
	{"10.0.0.1/33", "ERR '10.0.0.1/33' does not appear to be an IPv4 or IPv6 network", "ERR '33' is not a valid netmask"},
	{"1.2.3", "ERR '1.2.3' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '1.2.3'"},
	{"01.2.3.4", "ERR '01.2.3.4' does not appear to be an IPv4 or IPv6 network", "ERR Leading zeros are not permitted in '01' in '01.2.3.4'"},
	{"1.2.3.256", "ERR '1.2.3.256' does not appear to be an IPv4 or IPv6 network", "ERR Octet 256 (> 255) not permitted in '1.2.3.256'"},
	{"::", "::/128", "ERR Expected 4 octets in '::'"},
	{"::1", "::1/128", "ERR Expected 4 octets in '::1'"},
	{"1::", "1::/128", "ERR Expected 4 octets in '1::'"},
	{"2001:db8::1/64", "2001:db8::/64", "ERR Expected 4 octets in '2001:db8::1'"},
	{"2001:DB8:0:0:1:0:0:1", "2001:db8::1:0:0:1/128", "ERR Expected 4 octets in '2001:DB8:0:0:1:0:0:1'"},
	{"1:0:0:2:0:0:0:3", "1:0:0:2::3/128", "ERR Expected 4 octets in '1:0:0:2:0:0:0:3'"},
	{"0:0:1:0:0:1:0:0", "::1:0:0:1:0:0/128", "ERR Expected 4 octets in '0:0:1:0:0:1:0:0'"},
	{"::ffff:10.0.0.1", "::ffff:10.0.0.1/128", "ERR Only decimal digits permitted in '::ffff:10' in '::ffff:10.0.0.1'"},
	{"::ffff:10.0.0.1/96", "::ffff:0.0.0.0/96", "ERR Only decimal digits permitted in '::ffff:10' in '::ffff:10.0.0.1'"},
	{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304/128", "ERR Only decimal digits permitted in '1:2:3:4:5:6:1' in '1:2:3:4:5:6:1.2.3.4'"},
	{"fe80::1%eth0/64", "fe80::/64", "ERR Expected 4 octets in 'fe80::1%eth0'"},
	{"fe80::%eth0/64", "fe80::%eth0/64", "ERR Expected 4 octets in 'fe80::%eth0'"},
	{"fe80::1%", "ERR 'fe80::1%' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in 'fe80::1%'"},
	{"1::2::3", "ERR '1::2::3' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '1::2::3'"},
	{":1::", "ERR ':1::' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in ':1::'"},
	{"1::2:", "ERR '1::2:' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '1::2:'"},
	{"1:2:3:4:5:6:7:8:9", "ERR '1:2:3:4:5:6:7:8:9' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '1:2:3:4:5:6:7:8:9'"},
	{"1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:0/128", "ERR Expected 4 octets in '1:2:3:4:5:6:7::'"},
	{"::1:2:3:4:5:6:7:8", "ERR '::1:2:3:4:5:6:7:8' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '::1:2:3:4:5:6:7:8'"},
	{"12345::", "ERR '12345::' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '12345::'"},
	{"::g", "ERR '::g' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '::g'"},
	{"1:2", "ERR '1:2' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '1:2'"},
	{"10.0.0.0/8/8", "ERR '10.0.0.0/8/8' does not appear to be an IPv4 or IPv6 network", "ERR Only one '/' permitted in '10.0.0.0/8/8'"},
	{"::1.2.3", "ERR '::1.2.3' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '::1.2.3'"},
	{"1:2:3:4:5:6:7:1.2.3.4", "ERR '1:2:3:4:5:6:7:1.2.3.4' does not appear to be an IPv4 or IPv6 network", "ERR Only decimal digits permitted in '1:2:3:4:5:6:7:1' in '1:2:3:4:5:6:7:1.2.3.4'"},
	{"a:b:c:d:e:f:0:0", "a:b:c:d:e:f::/128", "ERR Expected 4 octets in 'a:b:c:d:e:f:0:0'"},
	{"0:0:0:a:0:0:0:0", "0:0:0:a::/128", "ERR Expected 4 octets in '0:0:0:a:0:0:0:0'"},
	{"2001:db8::/129", "ERR '2001:db8::/129' does not appear to be an IPv4 or IPv6 network", "ERR Expected 4 octets in '2001:db8::'"},
	{"", "ERR '' does not appear to be an IPv4 or IPv6 network", "ERR Address cannot be empty"},
	{"/24", "ERR '/24' does not appear to be an IPv4 or IPv6 network", "ERR Address cannot be empty"},
	{"10.0.0.1/", "ERR '10.0.0.1/' does not appear to be an IPv4 or IPv6 network", "ERR '' is not a valid netmask"},
}

func TestPythonIPAddress(t *testing.T) {
	for _, c := range ipCases {
		got := "ERR "
		if n, err := parseIPNetwork(c.in); err == nil {
			got = n.String()
		} else {
			got += err.Error()
		}
		if got != c.network {
			t.Errorf("ip_network(%q) = %q, Python %q", c.in, got, c.network)
		}
		got = "ERR "
		if i, err := parseIPv4Interface(c.in); err == nil {
			got = i.String()
		} else {
			got += err.Error()
		}
		if got != c.iface {
			t.Errorf("IPv4Interface(%q) = %q, Python %q", c.in, got, c.iface)
		}
	}
}
