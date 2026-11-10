package webui

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// The two read-only security views: the hardening checklist (1.x's
// routes/security.py, security-lessons K8) and the attack surface
// (routes/surface.py, I3). Both read the saved config and the
// apply-helper's listening_sockets; neither changes anything.

// knownPorts is frfw.surface.KNOWN_PORTS: what a socket is when ss
// couldn't name its process.
var knownPorts = map[string]string{
	"tcp/22":   "sshd",
	"tcp/443":  "webUI (fr-webui)",
	"udp/53":   "DNS filter (dnsmasq)",
	"tcp/53":   "DNS filter (dnsmasq)",
	"udp/67":   "DHCP server (Kea)",
	"udp/68":   "DHCP client",
	"udp/546":  "DHCPv6 client (dhcpcd)",
	"udp/5353": "mDNS",
	fmt.Sprintf("udp/%d", nft.IotMDNSReplyPort): "IoT scan (mDNS replies)",
}

// Label is the process ss named, else the port's usual service.
func (l listener) Label() string {
	if l.Process != "" {
		return l.Process
	}
	if name, ok := knownPorts[fmt.Sprintf("%s/%d", l.Proto, l.Port)]; ok {
		return name
	}
	return "unknown"
}

func (l listener) Loopback() bool { return l.addr.IsLoopback() }
func (l listener) Wildcard() bool { return l.addr.IsUnspecified() }

// -- the checklist ------------------------------------------------------------------------

func (s *Server) showSecurity(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	sc, err := s.securityScore(raw)
	if err != nil {
		return nil, err
	}
	return s.render(q, "security", &page{Username: q.user.Username, Data: sc})
}

// -- the attack surface -------------------------------------------------------------------

type surfaceCell struct {
	Has, Internet bool
	State, Why    string
}

type surfaceRowView struct {
	*surfaceRow
	Reachable bool
	Cells     []surfaceCell
}

type surfaceData struct {
	Error             string
	Rows              []surfaceRowView
	Exposed, Unneeded []surfaceRowView
	Zones             []string
	Internet          map[string]bool
	InternetList      string // internet|sort|join(", ")
	WANAddresses      []string
	AllowWAN          bool
}

// Colspan spans the table's four columns and one per zone.
func (d *surfaceData) Colspan() int { return 4 + len(d.Zones) }

// ExposedList and UnneededList are the flash lines' service lists.
func (d *surfaceData) ExposedList() string  { return serviceList(d.Exposed) }
func (d *surfaceData) UnneededList() string { return serviceList(d.Unneeded) }

func serviceList(rows []surfaceRowView) string {
	parts := make([]string, len(rows))
	for i, r := range rows {
		parts[i] = fmt.Sprintf("%s/%d %s", r.Listener.Proto, r.Listener.Port, r.Listener.Label())
	}
	return strings.Join(parts, ", ")
}

// wanAddresses is frfw.surface.wan_addresses: the internet-facing
// interfaces' addresses, for the outside-scan hint.
func wanAddresses(c *config.Config, addresses map[string][]string) ([]string, error) {
	internet := c.InternetFacingZones()
	var out []string
	for _, i := range c.Interfaces.Values() {
		if !internet[i.Zone] {
			continue
		}
		for _, a := range addresses[i.Device] {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return nil, errInternal // ipaddress.ip_address raises
			}
			if !ip.IsLinkLocalUnicast() {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func (s *Server) showSurface(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	d := &surfaceData{Internet: map[string]bool{}}
	c, perr := config.Parse(raw)
	if perr != nil {
		c, d.Error = nil, "The saved config doesn't parse: "+perr.Error()
	}
	var rows []*surfaceRow
	if c != nil {
		reply, err := s.helper.ListeningSockets()
		if err != nil {
			if _, ok := err.(*HelperError); !ok {
				return nil, err
			}
			reply = cmdMap("ok", false, "message", err.Error())
		}
		if !config.Truthy(field(reply, "ok")) {
			message := "no answer"
			if v := field(reply, "message"); config.Truthy(v) {
				message = pyStr(v)
			}
			d.Error = "Can't list the listening sockets: " + message
		} else {
			list, has := reply.Get("listeners")
			if !has {
				list = []config.Value{}
			}
			listeners, err := listenersOf(list)
			if err != nil {
				return nil, err
			}
			addresses, err := addressesOf(field(reply, "addresses"))
			if err != nil {
				return nil, err
			}
			rows = surfaceRows(c, listeners, addresses)
			d.Zones = slices.Sorted(slices.Values(c.Zones.Keys))
			d.Internet = c.InternetFacingZones()
			if d.WANAddresses, err = wanAddresses(c, addresses); err != nil {
				return nil, err
			}
		}
	}
	internet := make([]string, 0, len(d.Internet))
	for z := range d.Internet {
		internet = append(internet, z)
	}
	slices.SortFunc(internet, cmp.Compare)
	d.InternetList = strings.Join(internet, ", ")
	for _, r := range rows {
		v := surfaceRowView{surfaceRow: r, Reachable: r.reachable()}
		for _, z := range d.Zones {
			cell := surfaceCell{Internet: d.Internet[z]}
			if verdict, ok := r.Zones[z]; ok {
				cell.Has, cell.State, cell.Why = true, verdict.State, verdict.Why
			}
			v.Cells = append(v.Cells, cell)
		}
		d.Rows = append(d.Rows, v)
		if r.Internet {
			d.Exposed = append(d.Exposed, v)
		}
		if r.unneeded() {
			d.Unneeded = append(d.Unneeded, v)
		}
	}
	d.AllowWAN = c != nil && c.Management.AllowWan
	return s.render(q, "surface", &page{Username: q.user.Username, Error: d.Error, Data: d})
}
