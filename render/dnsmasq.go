package render

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/appid"
	"github.com/starsmash29/fr_os-community/config"
)

// FirefoxDoHCanary is the name Firefox asks before it turns DNS over
// HTTPS on by itself; NXDOMAIN keeps it off (adblocker.force_dns,
// frfw.adblock.FIREFOX_DOH_CANARY).
const FirefoxDoHCanary = "use-application-dns.net"

// defaultUpstreams are the resolver's upstreams when no DHCP pool names
// a DNS server (frfw.adblock.dns_service._DEFAULT_UPSTREAM_SERVERS).
var defaultUpstreams = []string{"1.1.1.1", "9.9.9.9"}

// DnsmasqPaths are the files the resolver's config names.
type DnsmasqPaths struct {
	Hosts, CategoryDir, QueryLog string
}

// DefaultDnsmasqPaths are the router's.
var DefaultDnsmasqPaths = DnsmasqPaths{AdblockHostsPath, AdblockCategoryDir, DNSQueryLogPath}

const dnsmasqHead = `# Managed by FR_OS (frfw.adblock.dns_service) -- regenerated on every
# ` + "`apply`" + `, do not edit by hand. A dedicated, frfw-owned dnsmasq
# instance (fr-adblock-dns.service) -- never the system's own
# dnsmasq.service/dnsmasq.conf, which this never touches.
port=53
no-resolv
no-hosts
`

const dnsmasqBind = `# Each address of those interfaces, and the ones they get later (ROADMAP
# FND-1c): IPv6 addresses come and go -- the provider's prefix is
# renumbered, the stable ULA one is added by the next apply.
bind-dynamic
`

const dnsmasqTail = `user=nobody
group=nogroup
# No PID file: systemd tracks the process, and /run is read-only in the
# unit's sandbox (security-lessons I1). Without this dnsmasq writes
# /run/dnsmasq.pid even in the foreground.
pid-file=
`

// Dnsmasq is the ad-block resolver's config
// (frfw.adblock.dns_service.render_dnsmasq_config): its own complete
// instance, fr-adblock-dns, never the system's dnsmasq. It answers from
// the downloaded lists, on lo and the DHCP zones' devices, forwarding
// to the pools' DNS servers but never to the router itself (that would
// loop every query).
func Dnsmasq(c *config.Config, paths DnsmasqPaths, catalog *appid.Catalog) string {
	var b strings.Builder
	b.WriteString(dnsmasqHead)
	categories := slices.Sorted(slices.Values(c.Adblocker.Categories.Keys))
	lines := []string{"addn-hosts=" + paths.Hosts}
	for _, name := range categories {
		lines = append(lines, "addn-hosts="+paths.CategoryDir+"/"+name+".hosts")
	}
	b.WriteString(strings.Join(lines, "\n") + "\n")
	lines = lines[:0]
	for _, d := range listenDevices(c) {
		lines = append(lines, "interface="+d)
	}
	b.WriteString(strings.Join(lines, "\n") + "\n")
	b.WriteString(dnsmasqBind)
	lines = lines[:0]
	for _, s := range upstreamServers(c) {
		lines = append(lines, "server="+s)
	}
	b.WriteString(strings.Join(lines, "\n") + "\n")
	var extra []string
	if c.Adblocker.QueryLogging {
		// "extra": the client's address and a serial on every line, and
		// the hosts file a blocked answer came from (frfw.ai_ids reads it),
		// into a file of its own (ROADMAP SEC-4).
		extra = append(extra, "log-queries=extra", "log-facility="+paths.QueryLog)
	}
	if c.Adblocker.ForceDNS {
		extra = append(extra, "address=/"+FirefoxDoHCanary+"/")
	}
	for _, name := range BlockedAppNames(c, catalog) {
		extra = append(extra, "address=/"+name+"/")
	}
	extra = append(extra, LocalDNSLines(c)...)
	for _, line := range extra {
		b.WriteString(line + "\n")
	}
	b.WriteString(dnsmasqTail)
	return b.String()
}

// BlockedAppNames are the catalog names of app_control.blocked_apps
// while the feature is on (phase 16): NXDOMAIN for them and their
// subdomains.
func BlockedAppNames(c *config.Config, catalog *appid.Catalog) []string {
	ac := c.AppControl
	if !ac.Enabled || len(ac.BlockedApps) == 0 {
		return nil
	}
	return catalog.BlockingNames(ac.BlockedApps)
}

// LocalDNSLines are local_dns as dnsmasq lines (ROADMAP DNS-1): the
// router alone answers for each name (`local=`), so another type is an
// empty answer rather than the upstream's.
func LocalDNSLines(c *config.Config) []string {
	ld := c.LocalDNS
	var lines []string
	if ld.Domain != "" {
		lines = append(lines, "local=/"+ld.Domain+"/")
	}
	for _, name := range slices.Sorted(slices.Values(ld.Hosts.Keys)) {
		address, _ := ld.Hosts.Get(name)
		lines = append(lines, "host-record="+name+","+address, "local=/"+name+"/")
	}
	for _, name := range slices.Sorted(slices.Values(ld.Overrides.Keys)) {
		address, _ := ld.Overrides.Get(name)
		lines = append(lines, "address=/"+name+"/"+address, "local=/"+name+"/")
	}
	return lines
}

// listenDevices: lo, so the router itself is served, and every device
// of a DHCP zone.
func listenDevices(c *config.Config) []string {
	devices := []string{"lo"}
	for _, i := range c.Interfaces.Values() {
		if c.Dhcp.Zones.Has(i.Zone) && !slices.Contains(devices, i.Device) {
			devices = append(devices, i.Device)
		}
	}
	return devices
}

func upstreamServers(c *config.Config) []string {
	own := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		if p, err := netip.ParsePrefix(i.Address); err == nil {
			own[p.Addr().String()] = true
		}
	}
	var servers []string
	for _, pool := range c.Dhcp.Zones.Values() {
		for _, s := range pool.DNSServers {
			if !own[s] && !slices.Contains(servers, s) {
				servers = append(servers, s)
			}
		}
	}
	if len(servers) == 0 {
		return slices.Clone(defaultUpstreams)
	}
	return servers
}
