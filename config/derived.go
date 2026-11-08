package config

import "slices"

// ZoneDevice is a zone and one of its interfaces' devices.
type ZoneDevice struct{ Zone, Device string }

// WanDevices are the internet-facing interfaces' devices, where IPv6
// comes from (frfw.ipv6.wan_devices), in config order.
func (c *Config) WanDevices() []string {
	facing := c.InternetFacingZones()
	var out []string
	for _, i := range c.Interfaces.Values() {
		if facing[i.Zone] && !slices.Contains(out, i.Device) {
			out = append(out, i.Device)
		}
	}
	return out
}

// LanDevices are (zone, device) for every device the delegated prefix is
// handed to (frfw.ipv6.lan_devices, ROADMAP FND-1b): zone by zone in
// IPv6LanZones order, then in config order. A device's position is its
// /64 in the prefix ("sla_id"), so an added zone or device goes last and
// renumbers nobody. Not the VPN tunnel. Empty while IPv6 is off.
func (c *Config) LanDevices() []ZoneDevice {
	var out []ZoneDevice
	for _, z := range c.IPv6LanZones() {
		for _, i := range c.Interfaces.Values() {
			if i.Zone == z && !slices.ContainsFunc(out, func(zd ZoneDevice) bool { return zd.Device == i.Device }) {
				out = append(out, ZoneDevice{z, i.Device})
			}
		}
	}
	return out
}

// DNSResolverZones are the zones the ad-block resolver serves
// (adblocker.serve_lan, frfw.nft.builder.dns_resolver_zones): the DHCP
// zones, sorted.
func (c *Config) DNSResolverZones() []string {
	if !(c.Adblocker.Enabled && c.Adblocker.ServeLan) {
		return nil
	}
	return slices.Sorted(slices.Values(c.Dhcp.Zones.Keys))
}

// TunnelServed: the router routes IPv6 for the VPN's clients (ROADMAP
// FND-1d, frfw.ipv6.tunnel_served): WireGuard and IPv6 on, and the
// tunnel's zone not kept off IPv6 by an IPv4-only protection.
func (c *Config) TunnelServed() bool {
	wg := c.Wireguard
	if !(wg.Enabled && c.IPv6.Enabled) {
		return false
	}
	_, excluded := c.IPv6LanExclusions()[wg.Zone]
	return !excluded
}

// IPv6ForwardingWanted: the kernel routes IPv6 while a LAN zone gets it
// (FND-1b) and while the VPN is on (FND-1d), whose clients' IPv6 must
// reach the forward chain to be refused there
// (frfw.ipv6.forwarding_wanted).
func (c *Config) IPv6ForwardingWanted() bool {
	return len(c.LanDevices()) > 0 || c.Wireguard.Enabled
}
