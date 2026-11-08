package render

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// Kea's config is JSON, in 1.x's key order (frfw.kea.build_kea_config).
type (
	keaConfig struct {
		Dhcp4 keaDhcp4 `json:"Dhcp4"`
	}
	keaDhcp4 struct {
		InterfacesConfig keaInterfaces `json:"interfaces-config"`
		LeaseDatabase    keaLeaseDB    `json:"lease-database"`
		ValidLifetime    int           `json:"valid-lifetime"`
		Subnet4          []keaSubnet   `json:"subnet4"`
	}
	keaInterfaces struct {
		Interfaces []string `json:"interfaces"`
	}
	keaLeaseDB struct {
		Type        string `json:"type"`
		LfcInterval int    `json:"lfc-interval"`
	}
	keaSubnet struct {
		Subnet        string           `json:"subnet"`
		Pools         []keaPool        `json:"pools"`
		ValidLifetime any              `json:"valid-lifetime"`
		OptionData    []keaOption      `json:"option-data"`
		Reservations  []keaReservation `json:"reservations"`
	}
	keaPool struct {
		Pool string `json:"pool"`
	}
	keaOption struct {
		Name string `json:"name"`
		Data string `json:"data"`
	}
	keaReservation struct {
		HwAddress string `json:"hw-address"`
		IPAddress string `json:"ip-address"`
		Hostname  string `json:"hostname,omitempty"`
	}
)

// Kea is the Kea DHCPv4 config of config.dhcp (frfw.kea.render_kea_config):
// one subnet per zone with a pool, served on that zone's interface. With
// adblocker.serve_lan the router itself is the DNS server every client
// is told about (phase 15); the pools' dns_servers are then the
// resolver's upstreams (Dnsmasq).
func Kea(c *config.Config) (string, error) {
	return KeaListening(c, nil)
}

// KeaListening is Kea's config listening only on the devices keep
// allows (nil: every one). An apply's check runs before the VLAN devices
// exist, and Kea's check refuses a device that isn't there
// (frfw.provision._check_kea).
func KeaListening(c *config.Config, keep func(device string) bool) (string, error) {
	byZone := map[string]config.Interface{}
	for _, i := range c.Interfaces.Values() {
		byZone[i.Zone] = i // the last one, as 1.x's dict comprehension
	}
	serveLan := c.Adblocker.Enabled && c.Adblocker.ServeLan
	cfg := keaConfig{keaDhcp4{
		InterfacesConfig: keaInterfaces{Interfaces: []string{}},
		LeaseDatabase:    keaLeaseDB{Type: "memfile", LfcInterval: 3600},
		ValidLifetime:    3600,
		Subnet4:          []keaSubnet{},
	}}
	for _, zone := range c.Dhcp.Zones.Keys {
		pool, _ := c.Dhcp.Zones.Get(zone)
		iface, ok := byZone[zone]
		if !ok {
			return "", fmt.Errorf("dhcp zone %q has no interface", zone)
		}
		if keep == nil || keep(iface.Device) {
			cfg.Dhcp4.InterfacesConfig.Interfaces = append(cfg.Dhcp4.InterfacesConfig.Interfaces, iface.Device)
		}
		s, err := keaSubnetOf(iface.Address, pool, serveLan)
		if err != nil {
			return "", err
		}
		cfg.Dhcp4.Subnet4 = append(cfg.Dhcp4.Subnet4, s)
	}
	text, err := pythonJSON(cfg)
	if err != nil {
		return "", err
	}
	return text + "\n", nil
}

func keaSubnetOf(address string, pool config.DhcpPool, routerIsDNS bool) (keaSubnet, error) {
	p, err := netip.ParsePrefix(address)
	if err != nil || !p.Addr().Is4() {
		return keaSubnet{}, fmt.Errorf("dhcp zone %q: interface address %q", pool.Zone, address)
	}
	router := p.Addr().String()
	dns := pool.DNSServers
	if routerIsDNS {
		dns = []string{router}
	}
	var lifetime any = pool.LeaseTime
	if pool.LeaseTimeTrue {
		lifetime = true
	}
	s := keaSubnet{
		Subnet:        p.Masked().String(),
		Pools:         []keaPool{{pool.RangeStart + " - " + pool.RangeEnd}},
		ValidLifetime: lifetime,
		OptionData: []keaOption{
			{"routers", router},
			{"domain-name-servers", strings.Join(dns, ", ")},
		},
		Reservations: []keaReservation{},
	}
	for _, r := range pool.Reservations {
		s.Reservations = append(s.Reservations, keaReservation{r.MacAddress, r.Address, r.Hostname})
	}
	return s, nil
}
