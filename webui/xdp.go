package webui

import (
	"errors"
	"math/big"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// The XDP TLS SNI filter screen (1.x's routes/xdp.py): which interfaces
// run the filter now (the state file names them, `ip -j link` says
// whether the kernel still has it there, no privilege needed), its
// counters (on bpffs, read by the apply-helper, ROADMAP P4-1), where
// QUIC is rejected (SEC-1), and the xdp_sni_filter settings. The live
// log stream is phase 3c.

const xdpProgName = "xdp_sni_filter"

// errXDP is frfw.xdp.XdpError: the page then shows nothing attached.
var errXDP = errors.New("xdp")

type xdpIface struct{ Name, Device, Label, BadgeClass string }

type xdpData struct {
	Enabled                       bool
	Available                     []iotZone
	BlockedDomains                []string
	BlocklistText                 string
	Interface, Status, BadgeClass string
	Interfaces                    []xdpIface
	HasStats                      bool
	Drops                         string
	QUICRejected                  string
}

// kernelMode is _KERNEL_MODES.get(mode): 1 is native, 2 generic.
func kernelMode(v config.Value) string {
	n := -1
	switch x := v.(type) {
	case *big.Int:
		if x.IsInt64() {
			n = int(x.Int64())
		}
	case float64:
		if x == 1 || x == 2 {
			n = int(x)
		}
	case bool:
		if x {
			n = 1
		}
	}
	switch n {
	case 1:
		return "xdpdrv"
	case 2:
		return "xdpgeneric"
	}
	return ""
}

func mapOrEmpty(v config.Value) (*config.Map, error) {
	if !config.Truthy(v) {
		return config.NewMap(), nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, errInternal
	}
	return m, nil
}

// liveAttachment is frfw.xdp.live_attachment's mode: the filter's mode
// on device as the kernel has it, or "".
func (s *Server) liveAttachment(device string) (string, error) {
	if _, err := apply.Ifname(device); err != nil {
		return "", errXDP
	}
	rc, out, err := s.env.Run([]string{"ip", "-j", "link", "show", "dev", device}, 10)
	if err != nil {
		return "", errXDP // no ip binary
	}
	if rc != 0 {
		return "", nil
	}
	v, err := config.ParseJSONLastWins([]byte(out))
	if err != nil {
		return "", nil
	}
	// json.loads(...)[0]: a ValueError, IndexError or TypeError (and a
	// dict's KeyError... which is not caught) means nothing attached.
	var first config.Value
	switch x := v.(type) {
	case []config.Value:
		if len(x) == 0 {
			return "", nil
		}
		first = x[0]
	case string:
		if x == "" {
			return "", nil
		}
		return "", errInternal // "x"[0].get raises
	case *config.Map:
		return "", errInternal // {}[0] is a KeyError, not caught
	default:
		return "", nil
	}
	link, ok := first.(*config.Map)
	if !ok {
		return "", errInternal
	}
	xdp, err := mapOrEmpty(field(link, "xdp"))
	if err != nil {
		return "", err
	}
	entriesV := field(xdp, "attached")
	var entries []config.Value
	if config.Truthy(entriesV) {
		if entries, err = jinjaIter(entriesV, true); err != nil {
			return "", err
		}
	} else if config.Truthy(field(xdp, "prog")) {
		entries = []config.Value{xdp}
	}
	for _, e := range entries {
		entry, ok := e.(*config.Map)
		if !ok {
			return "", errInternal
		}
		prog, err := mapOrEmpty(field(entry, "prog"))
		if err != nil {
			return "", err
		}
		if mode := kernelMode(field(entry, "mode")); mode != "" && strEq(field(prog, "name"), xdpProgName) {
			return mode, nil
		}
	}
	return "", nil
}

// attachedXDP is frfw.xdp.get_attached: device -> mode, for the devices
// the state file names that the kernel still runs the filter on.
func (s *Server) attachedXDP() (map[string]string, error) {
	v, ok, err := readJSONState(s.env.Paths.at("/etc/fr_os/xdp_state.json"))
	if err != nil || !ok {
		return nil, err
	}
	data, isMap := v.(*config.Map)
	if !isMap {
		return nil, errInternal // data.get on a list raises
	}
	attachedV, present := data.Get("attached")
	if !present {
		attachedV = config.NewMap()
	}
	attached, isMap := attachedV.(*config.Map)
	if !isMap {
		return nil, errInternal // dict() of anything else, near enough
	}
	out := map[string]string{}
	for _, k := range attached.Keys() {
		device, ok := k.(string)
		if !ok {
			return nil, errXDP
		}
		mode, err := s.liveAttachment(device)
		if err != nil {
			return nil, err
		}
		if mode != "" {
			out[device] = mode
		}
	}
	return out, nil
}

func xdpStatusFor(mode string) (string, string) {
	if mode == "xdpdrv" {
		return "Native / Driver (xdpdrv)", "badge-green"
	}
	return "Generic / SKB (xdpgeneric)", "badge-yellow"
}

func (s *Server) showXDP(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "xdp_sni_filter")
	if err != nil {
		return nil, err
	}
	d := &xdpData{Enabled: config.Truthy(pyGet(section, "enabled", false))}
	configured, err := pyIter(field(section, "interfaces"))
	if err != nil {
		return nil, err
	}
	if d.BlockedDomains, err = pyStrList(field(section, "blocklist")); err != nil {
		return nil, err
	}
	d.BlocklistText = strings.Join(d.BlockedDomains, "\n")
	ifaces, err := getMapOr(raw, "interfaces")
	if err != nil {
		return nil, err
	}
	var available []string
	deviceName := map[string]string{}
	for i, k := range ifaces.Keys() {
		name, ok := k.(string)
		if !ok {
			return nil, errInternal
		}
		available = append(available, name)
		body, ok := ifaces.Values()[i].(*config.Map)
		if !ok {
			return nil, errInternal
		}
		if dev := field(body, "device"); config.Truthy(dev) {
			deviceName[pyStr(dev)] = name
		}
	}
	sort.Strings(available)
	for _, name := range available {
		d.Available = append(d.Available, iotZone{name, pyIn(name, configured)})
	}

	attached, err := s.attachedXDP()
	if errors.Is(err, errXDP) {
		attached = nil
	} else if err != nil {
		return nil, err
	}
	// The counters live on bpffs, root's: the apply-helper reads them
	// (ROADMAP P4-1). If it can't, say so rather than show zeros that
	// look like "nothing dropped".
	result, err := s.helper.XDPStats()
	var he *HelperError
	if errors.As(err, &he) {
		result = config.NewMap()
	} else if err != nil {
		return nil, err
	}
	if config.Truthy(field(result, "ok")) {
		if stats := field(result, "stats"); stats != nil {
			d.HasStats = true
			d.Drops = jinjaText(stats, "drop_match")
		}
	}
	// ROADMAP SEC-1: where QUIC is rejected, as the next apply's ruleset
	// will have it.
	if cfg, err := config.Parse(raw); err == nil {
		d.QUICRejected = strings.Join(nft.SNIFilteredDevices(cfg), ", ")
	}

	devices := make([]string, 0, len(attached))
	for dev := range attached {
		devices = append(devices, dev)
	}
	sort.Strings(devices)
	for _, dev := range devices {
		label, badge := xdpStatusFor(attached[dev])
		name, ok := deviceName[dev]
		if !ok {
			name = dev
		}
		d.Interfaces = append(d.Interfaces, xdpIface{name, dev, label, badge})
	}
	configuredText := make([]string, len(configured))
	for i, c := range configured {
		configuredText[i] = pyStr(c)
	}
	switch {
	case len(d.Interfaces) > 0:
		d.Interface, d.Status, d.BadgeClass = d.Interfaces[0].Name, d.Interfaces[0].Label, d.Interfaces[0].BadgeClass
	case d.Enabled:
		d.Interface = strings.Join(configuredText, ", ")
		if d.Interface == "" {
			d.Interface = "(none configured)"
		}
		d.Status, d.BadgeClass = "Not attached yet -- run Apply", "badge-red"
	default:
		d.Interface = "-"
		if len(configured) > 0 {
			d.Interface = configuredText[0]
		}
		d.Status, d.BadgeClass = "Disabled", "badge-red"
	}
	return s.render(q, "xdp", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveXDP(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	var interfaces []string
	var blocklist string
	if err = q.fields(func(p *formParams) {
		enabled, interfaces, blocklist = p.boolOr("enabled", false), p.list("interfaces"), p.strOr("blocklist", "")
	}); err != nil {
		return nil, err
	}
	raw.Set("xdp_sni_filter", cmdMap("enabled", enabled, "interfaces", interfaces, "blocklist", textLines(blocklist)))
	return s.saved(raw, "/xdp", "XDP SNI filter settings saved -- click Apply on the dashboard to load them into the kernel")
}

func (s *Server) removeXDPDomain(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var domain string
	if err = q.fields(func(p *formParams) { domain = p.str("domain") }); err != nil {
		return nil, err
	}
	section, err := setdefaultMap(raw, "xdp_sni_filter")
	if err != nil {
		return nil, err
	}
	items, err := pyIter(field(section, "blocklist"))
	if err != nil {
		return nil, err
	}
	kept := []config.Value{}
	for _, item := range items {
		if !strEq(item, domain) {
			kept = append(kept, item)
		}
	}
	section.Set("blocklist", kept)
	return s.saved(raw, "/xdp", "Removed "+config.Repr(domain)+" from the blocklist")
}
