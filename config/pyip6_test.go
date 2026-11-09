package config

import (
	"math/big"
	"testing"
)

// The expected values are Python 3.13's.

func TestPyIPv6Interface(t *testing.T) {
	for _, c := range []struct {
		text, str, network string
		prefix             int
		ula                bool
	}{
		{"2001:db8::1/64", "2001:db8::1/64", "2001:db8::/64", 64, false},
		{"fe80::1%eth0/64", "fe80::1%eth0/64", "fe80::/64", 64, false},
		{"2001:DB8:0::5", "2001:db8::5/128", "2001:db8::5/128", 128, false},
		{"fd00::1/128", "fd00::1/128", "fd00::1/128", 128, true},
		{"fe80::1%eth0/10", "fe80::1%eth0/10", "fe80::/10", 10, false},
	} {
		i, err := ParsePyIPv6Interface(c.text)
		if err != nil || i.String() != c.str || i.Network().String() != c.network || i.Prefix() != c.prefix ||
			i.InULA() != c.ula {
			t.Errorf("%s: got %s %s %d %v (%v)", c.text, i, i.Network(), i.Prefix(), i.InULA(), err)
		}
	}
	for text, want := range map[string]string{
		"::1/64/2":    "Only one '/' permitted in '::1/64/2'",
		"nonsense/64": "At least 3 parts expected in 'nonsense'",
		"::1/x":       "'x' is not a valid netmask",
		"::1/129":     "'129' is not a valid netmask",
	} {
		if _, err := ParsePyIPv6Interface(text); err == nil || err.Error() != want {
			t.Errorf("%s: got %v, want %s", text, err, want)
		}
	}
}

func TestPyIPv6Network(t *testing.T) {
	for _, c := range []struct {
		v                          Value
		str                        string
		linkLocal, multi, loopback bool
	}{
		{big.NewInt(5), "::5/128", false, false, false},
		{true, "::1/128", false, false, true},
		{"fe80::/64", "fe80::/64", true, false, false},
		{"ff02::/16", "ff02::/16", false, true, false},
		{"::1/128", "::1/128", false, false, true},
		{"2001:db8::/32", "2001:db8::/32", false, false, false},
	} {
		n, err := ParsePyIPv6Network(c.v)
		if err != nil || n.String() != c.str || n.IsLinkLocal() != c.linkLocal || n.IsMulticast() != c.multi ||
			n.IsLoopback() != c.loopback {
			t.Errorf("%v: got %s %v %v %v (%v)", c.v, n, n.IsLinkLocal(), n.IsMulticast(), n.IsLoopback(), err)
		}
	}
	n, _ := ParsePyIPv6Network("2001:db8::/64")
	if a, err := n.AddressPlus(big.NewInt(0x10)); err != nil || a.String() != "2001:db8::10" {
		t.Errorf("2001:db8::/64 + 0x10: %s (%v)", a, err)
	}
	n, _ = ParsePyIPv6Network("ffff:ffff:ffff:ffff::/64")
	_, err := n.AddressPlus(new(big.Int).Lsh(big.NewInt(1), 64))
	if want := "340282366920938463463374607431768211456 (>= 2**128) is not permitted as an IPv6 address"; err == nil ||
		err.Error() != want {
		t.Errorf("past the last address: %v", err)
	}
}

// TestPyJSONKeys: json.dumps writes a number, bool or None key as its
// JSON text, and 1 and True are one key.
func TestPyJSONKeys(t *testing.T) {
	m := NewMap()
	m.SetKey(big.NewInt(1), "a")
	m.SetKey(nil, big.NewInt(2))
	m.SetKey(true, big.NewInt(3))
	m.SetKey(1.5, big.NewInt(4))
	m.SetKey(false, big.NewInt(5))
	got, err := PyJSON(m, -1, false)
	if want := `{"1": 3, "null": 2, "1.5": 4, "false": 5}`; err != nil || got != want {
		t.Errorf("got %s (%v), want %s", got, err, want)
	}
}
