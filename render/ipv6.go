package render

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

const dhcpcdHead = `# Managed by FR_OS (frfw.ipv6) -- regenerated on every ` + "`apply`" + `, do not edit.
# IPv6 (ROADMAP FND-1): SLAAC from the provider's Router Advertisement,
# DHCPv6 for an address and a delegated prefix on the WAN; a /64 of the
# prefix for each LAN device (FND-1b), with an unreachable route installed
# for the rest of it.
ipv6only
noipv4
noipv4ll
# Router Advertisements are read on the WAN only (its block below): never
# on a LAN, which must not configure the router -- and dhcpcd.conf(5)
# advises it when asking for a delegated prefix.
noipv6rs
# No hostname and no FQDN option: the router doesn't name itself to the
# provider.
fqdn disable
# No hook script: nothing the provider sends is written to the router's
# own files (resolv.conf, its hostname, NTP servers).
script /bin/true
# Stable addresses that don't carry the MAC (RFC 7217).
slaac private
# The LAN devices too: dhcpcd only assigns a prefix to an interface it
# runs on.
allowinterfaces `

// Dhcpcd is fr-dhcp6's config (frfw.ipv6.render_dhcpcd_conf): IPv6
// only, SLAAC and DHCPv6 on each WAN device, the delegated prefix's /64s
// handed to the LAN devices from the first WAN device only (two WANs
// delegating to one LAN would give it two providers' prefixes), no hook
// script and no hostname.
func Dhcpcd(c *config.Config) string {
	wan := c.WanDevices()
	lan := c.LanDevices()
	var blocks strings.Builder
	for i, device := range wan {
		n := i + 1
		fmt.Fprintf(&blocks, "\ninterface %s\n\tipv6rs\n\tia_na %d\n\tia_pd %d %s\n", device, n, n+100, delegation(lan, n == 1))
	}
	devices := slices.Clone(wan)
	for _, zd := range lan {
		if !slices.Contains(wan, zd.Device) {
			devices = append(devices, zd.Device)
		}
	}
	return dhcpcdHead + strings.Join(devices, " ") + "\n" + blocks.String()
}

// delegation is ia_pd's interfaces, `<device>/<sla_id>/64` for each LAN
// device; "-" (to no interface) on any but the first WAN device, and
// with no LAN: with none named dhcpcd would give every other interface
// a prefix.
func delegation(lan []config.ZoneDevice, first bool) string {
	if !first || len(lan) == 0 {
		return "-"
	}
	parts := make([]string, len(lan))
	for sla, zd := range lan {
		parts[sla] = zd.Device + "/" + strconv.Itoa(sla) + "/64"
	}
	return strings.Join(parts, " ")
}

const raHead = `# Managed by FR_OS (frfw.ipv6) -- regenerated on every ` + "`apply`" + `, do not edit.
# Router Advertisements on the LAN (ROADMAP FND-1b/1c), and nothing else:
# each device's /64s, for SLAAC -- the one dhcpcd gave it from the
# provider's prefix and the stable ULA one -- and, where the router's
# resolver serves the zone, the resolver's address (RDNSS).
# No DNS here: the ad-block resolver (fr-adblock-dns) answers it.
port=0
no-resolv
no-hosts
# Nothing is written: /run is read-only in fr-ra's sandbox, and there are
# no leases to keep.
pid-file=
leasefile-ro
# No log line for every advertisement sent.
quiet-ra
enable-ra
`

// RA is fr-ra's dnsmasq config (frfw.ipv6.render_ra_conf): an RA-only
// context per LAN device, its prefixes taken from the device's own
// addresses (`constructor:`, so a renumbered prefix follows), SLAAC with
// no DHCPv6. With ula, on the devices of the zones the resolver serves,
// the router's ULA address there is the DNS server (RDNSS).
func RA(c *config.Config, ula *netip.Prefix) string {
	served := map[string]bool{}
	for _, z := range c.DNSResolverZones() {
		served[z] = true
	}
	addresses := map[string]string{}
	for _, a := range ULAAddresses(c, ula) {
		addresses[a.Device] = a.Address
	}
	var b strings.Builder
	b.WriteString(raHead)
	for _, zd := range c.LanDevices() {
		fmt.Fprintf(&b, "interface=%s\ndhcp-range=::,constructor:%s,ra-only\n", zd.Device, zd.Device)
		if address, ok := addresses[zd.Device]; served[zd.Zone] && ok {
			fmt.Fprintf(&b, "dhcp-option=tag:%s,option6:dns-server,[%s]\n", zd.Device, strings.TrimSuffix(address, "/64"))
		}
	}
	return b.String()
}

// tunnelSLA is the VPN tunnel's /64 of the ULA /48 (ROADMAP FND-1d): the
// last one, far from the LAN devices', which count up from the first.
const tunnelSLA = 0xffff

// ULAPrefix is the ULA /48 of the LAN's stable networks (FND-1c,
// frfw.ipv6.ula_prefix): ipv6.ula_prefix, or generated, the one the
// router picked and keeps in its state file (nil before an apply made
// one).
func ULAPrefix(c *config.Config, generated *netip.Prefix) *netip.Prefix {
	if c.IPv6.UlaPrefix != "" {
		p, err := netip.ParsePrefix(c.IPv6.UlaPrefix)
		if err != nil {
			panic(err) // the config package normalized it
		}
		return &p
	}
	return generated
}

// subnet64 is the /64 at position sla of the /48 prefix.
func subnet64(prefix netip.Prefix, sla uint64) netip.Addr {
	a := prefix.Masked().Addr().As16()
	hi := binary.BigEndian.Uint64(a[:8]) | sla
	binary.BigEndian.PutUint64(a[:8], hi)
	return netip.AddrFrom16(a)
}

// ULAAddress is a LAN device's ULA address.
type ULAAddress struct {
	Zone, Device string
	Address      string // "<network>::1/64"
}

// ULAAddresses are the router's ULA address on every LAN device (FND-1c,
// frfw.ipv6.ula_addresses): its /64 of the ULA /48 at the same position
// ("sla_id") as in the provider's prefix. None without a prefix.
func ULAAddresses(c *config.Config, prefix *netip.Prefix) []ULAAddress {
	if prefix == nil {
		return nil
	}
	var out []ULAAddress
	for sla, zd := range c.LanDevices() {
		network := subnet64(*prefix, uint64(sla)).As16()
		network[15] |= 1
		out = append(out, ULAAddress{zd.Zone, zd.Device, netip.AddrFrom16(network).String() + "/64"})
	}
	return out
}

// TunnelNetwork6 is the VPN tunnel's IPv6 network, `<ULA>:ffff::/64`
// (FND-1d): from the ULA, so a provider's renumbering never touches it.
func TunnelNetwork6(prefix netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(subnet64(prefix, tunnelSLA), 64)
}

// Sysctl is one kernel setting, its key under /proc/sys/net.
type Sysctl struct{ Key, Value string }

// Sysctls are the kernel's IPv6 settings an apply writes
// (frfw.ipv6.sysctl_settings), in 1.x's order: no Router Advertisement,
// redirect, source route or SLAAC taken anywhere (dhcpcd reads the WAN's
// RA itself), IPv6 routed only while there is a LAN or a VPN to route
// for, and every value dhcpcd would otherwise write itself, which its
// sandbox can't (/proc/sys is read-only there).
func Sysctls(c *config.Config) []Sysctl {
	var out []Sysctl
	at := map[string]int{}
	set := func(k, v string) { // a dict: a key set again keeps its place
		if i, ok := at[k]; ok {
			out[i].Value = v
			return
		}
		at[k] = len(out)
		out = append(out, Sysctl{k, v})
	}
	forwarding := "0"
	if c.IPv6ForwardingWanted() {
		forwarding = "1"
	}
	set("ipv6/conf/all/forwarding", forwarding)
	var devices []string
	for _, i := range c.Interfaces.Values() {
		if !slices.Contains(devices, i.Device) {
			devices = append(devices, i.Device)
		}
	}
	slices.Sort(devices)
	for _, d := range append([]string{"all", "default"}, devices...) {
		for _, k := range []string{"accept_ra", "accept_redirects", "accept_source_route", "autoconf"} {
			set("ipv6/conf/"+d+"/"+k, "0")
		}
	}
	var lan []string
	for _, zd := range c.LanDevices() {
		lan = append(lan, zd.Device)
	}
	for _, d := range append(c.WanDevices(), lan...) {
		set("ipv6/conf/"+d+"/disable_ipv6", "0")
		set("ipv4/conf/"+d+"/promote_secondaries", "1")
	}
	for _, d := range lan {
		// FND-1c: the ULA address stays when the link goes down, as an
		// IPv4 one does; the webUI and SSH listen on it.
		set("ipv6/conf/"+d+"/keep_addr_on_down", "1")
	}
	return out
}
