package apply

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"

	"github.com/starsmash29/fr_os-community/config"
)

// The minimal config firewall-cli assign-interfaces (and first boot)
// writes from a WAN/LAN/OPT assignment (frfw.skeleton).

// DefaultLANAddress is the out-of-the-box LAN: the router at .1, DHCP
// for .100-.199, so a laptop plugged in gets an address and can open the
// webUI. Not 192.168.0.x/1.x or the other ranges home routers and ISP
// boxes hand out (ROADMAP NET-12): FR_OS's WAN is usually such a box's
// LAN, and a LAN in the WAN's range leaves the router unable to tell
// the two apart.
const DefaultLANAddress = "10.73.1.1/24"

// LANAddressChoices are where the LAN goes when the upstream network
// overlaps the default, in order: three different private blocks, so a
// WAN in any one of them (a whole 10.0.0.0/8 included) leaves another.
var LANAddressChoices = []string{"10.73.1.1/24", "172.29.73.1/24", "192.168.173.1/24"}

// defaultLANDNS: the router runs no resolver until DNS filtering is
// turned on, so the LAN gets public resolvers; the Ad-Block screen
// switches clients to the router's own when enabled.
var defaultLANDNS = []string{"1.1.1.1", "9.9.9.9"}

// LANAddressAvoiding is the first of LANAddressChoices whose network
// overlaps none of networks (the upstream networks first boot saw
// offered).
func LANAddressAvoiding(networks []string) (string, error) {
	var upstream []netip.Prefix
	for _, n := range networks {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return "", err
		}
		upstream = append(upstream, p.Masked())
	}
	for _, choice := range LANAddressChoices {
		lan := netip.MustParsePrefix(choice).Masked()
		clear := true
		for _, u := range upstream {
			if lan.Overlaps(u) {
				clear = false
			}
		}
		if clear {
			return choice, nil
		}
	}
	return "", errors.New("every LAN address choice overlaps the upstream network")
}

// OptDevice is one more zone: its name and its device.
type OptDevice struct{ Zone, Device string }

func rule(fields ...any) *config.Map {
	m := config.NewMap()
	for i := 0; i < len(fields); i += 2 {
		v := fields[i+1]
		if n, ok := v.(int); ok {
			v = big.NewInt(int64(n))
		}
		m.Set(fields[i].(string), v)
	}
	return m
}

// BuildSkeleton is the YAML of a minimal config assigning wan to the wan
// zone, lan to lan, and each OPT device to a zone of its name (LAN<->OPT
// traffic is not pre-authorized). With lanAddress ("" for none) the LAN
// also gets that static address and, for a /24, a DHCP pool in its
// .100-.199 range. The WAN is left to DHCP from the upstream network.
// The rules: SSH and the webUI from the LAN, the LAN to the internet,
// and outbound NAT on the WAN; nothing is exposed from the WAN.
func BuildSkeleton(wan, lan string, opts []OptDevice, hostname, lanAddress string) (string, error) {
	interfaces := config.NewMap()
	wanIf := rule("device", wan, "zone", "wan")
	lanIf := rule("device", lan, "zone", "lan")
	interfaces.Set("wan", wanIf)
	interfaces.Set("lan", lanIf)
	dhcp := config.NewMap()
	var ip netip.Addr
	if lanAddress != "" {
		p, err := netip.ParsePrefix(lanAddress)
		if err != nil {
			return "", err
		}
		ip = p.Addr()
		lanIf.Set("address", lanAddress)
		if p.Bits() == 24 {
			base := p.Masked().Addr().As4()
			at := func(n byte) string { return fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], n) }
			dns := make([]config.Value, len(defaultLANDNS))
			for i, d := range defaultLANDNS {
				dns[i] = d
			}
			dhcp.Set("lan", rule("range_start", at(100), "range_end", at(199), "dns_servers", dns))
		}
	}
	zones := config.NewMap()
	zones.Set("wan", config.NewMap())
	zones.Set("lan", config.NewMap())
	rules := []config.Value{
		rule("name", "allow-mgmt-from-lan", "action", "accept", "from_zone", "lan", "to_zone", "self",
			"proto", "tcp", "dst_port", 22),
		// The webUI (HTTPS). Without it a freshly booted router drops the
		// admin's browser on its own LAN (input policy is drop).
		rule("name", "webui-from-lan", "action", "accept", "from_zone", "lan", "to_zone", "self",
			"proto", "tcp", "dst_port", 443),
		rule("name", "lan-to-wan", "action", "accept", "from_zone", "lan", "to_zone", "wan"),
	}
	for _, o := range opts {
		interfaces.Set(o.Zone, rule("device", o.Device, "zone", o.Zone))
		zones.Set(o.Zone, config.NewMap())
	}
	top := config.NewMap()
	top.Set("version", big.NewInt(1))
	top.Set("hostname", hostname)
	top.Set("interfaces", interfaces)
	top.Set("zones", zones)
	top.Set("rules", rules)
	top.Set("nat", rule("masquerade", []config.Value{rule("out_zone", "wan")}))
	if dhcp.Len() > 0 {
		top.Set("dhcp", dhcp)
	}
	if lanAddress != "" {
		// ROADMAP SEC-27: where the webUI and SSH listen is the admin's
		// choice from the start, not a side effect of the LAN's address.
		top.Set("management", rule("addresses", []config.Value{ip.String()}))
	}
	// Security-lessons K4: IoT isolation on from the start. Devices the
	// scanner classifies as IoT reach the internet but not the rest of
	// the LAN or the router's management.
	top.Set("iot", rule("enabled", true, "zones", []config.Value{"lan"}, "auto_isolate", true,
		"isolation_mode", "internet_only"))
	return config.DumpYAML(top)
}
