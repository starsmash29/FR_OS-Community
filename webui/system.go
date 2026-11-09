package webui

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The system screen (1.x's routes/system.py): post-quantum key exchange
// (computed here, it needs no privilege), management access and the
// webUI's address (moved only through the apply-helper, held until
// confirmed: ROADMAP SEC-26/27), software integrity, persistence, and
// multi-site monitoring (the metrics token, shown once, and the
// certificate a remote Prometheus pins).

// tlsLibrary is what the "Host OpenSSL" row names: FR_OS 2's webUI
// speaks TLS through Go's crypto/tls, which always offers the hybrid
// group (decisions.md, 3b-3).
const tlsLibrary = "Go crypto/tls (X25519MLKEM768)"

// integrityNote is why the integrity card says "not verifiable": FR_OS 2
// keeps no hash list of its files yet (decisions.md, 3b-3).
const integrityNote = "FR_OS 2 keeps no list of its files' hashes yet"

type pqcView struct {
	EnabledInConfig, QuantumSafe, HostSupportsHybrid bool
	OpenSSLVersion, ConfiguredGroups                 string
	AppliedHybrid                                    bool
	SSHInstalled, SSHSupportsHybrid, SSHDropinActive bool
}

type managementChoice struct {
	Address, What string
	Checked       bool
}

type managementView struct {
	AllowWan                  bool
	Zones, Blocked, Addresses []string
	Warning                   string
	VPNOn, VPNListening       bool
	Choices                   []managementChoice
	ConfirmSeconds            int64
	IPv6, IPv6Available       bool
	IPv6Addresses             []string
}

type persistenceView struct {
	Live, Active, Requested bool
	Devices                 []string
	BootDevice              string
}

type integrityView struct {
	Verifiable, OK bool
	Note, Summary  string
	Changes        []string
}

type systemData struct {
	Status          pqcView
	Management      managementView
	Persistence     persistenceView
	Integrity       integrityView
	MetricsSite     string
	MetricsHostname string
	MetricsTokenSet bool
	CertSHA256      string
	NewToken        string
}

// managementZoneList is frfw.management.management_zones: as listed, or
// sorted when derived.
func managementZoneList(c *config.Config) []string {
	if len(c.Management.Zones) > 0 {
		return slices.Clone(c.Management.Zones)
	}
	var out []string
	for z := range c.ManagementZones() {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

// interfaceChoices is frfw.management.interface_addresses: (address,
// interface) of every management zone's interface with a static address.
func interfaceChoices(c *config.Config) [][2]string {
	zones := c.ManagementZones()
	ifaces := c.Interfaces.Values()
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })
	var found [][2]string
	for _, iface := range ifaces {
		if !zones[iface.Zone] || iface.Address == "" {
			continue
		}
		p, err := netip.ParsePrefix(iface.Address)
		if err != nil {
			continue
		}
		ip := p.Addr().String()
		if !slices.ContainsFunc(found, func(f [2]string) bool { return f[0] == ip }) {
			found = append(found, [2]string{ip, iface.Name})
		}
	}
	return found
}

func (s *Server) managementOf(c *config.Config) managementView {
	ula := apply.ULAPrefixAt(s.ulaStatePath(), c)
	addresses := render.ListenAddresses(c, ula)
	m := managementView{AllowWan: c.Management.AllowWan, Zones: managementZoneList(c),
		Addresses: addresses, Warning: apply.WANWarning, VPNOn: c.Wireguard.Enabled,
		ConfirmSeconds: c.Management.ConfirmApplySeconds, IPv6: c.Management.IPv6,
		IPv6Available: c.IPv6.Enabled}
	zones := c.ManagementZones()
	for _, z := range c.Zones.Keys {
		if !zones[z] {
			m.Blocked = append(m.Blocked, z)
		}
	}
	sort.Strings(m.Blocked)
	wg := c.Wireguard
	var tunnelIP string
	if wg.Address != "" {
		if p, err := netip.ParsePrefix(wg.Address); err == nil {
			tunnelIP = p.Addr().String()
		}
	}
	m.VPNListening = wg.Enabled && wg.Address != "" && slices.Contains(addresses, tunnelIP)
	var choices [][2]string
	for _, f := range interfaceChoices(c) {
		choices = append(choices, [2]string{f[0], "interface " + f[1]})
	}
	if wg.Enabled && wg.Address != "" && zones[wg.Zone] {
		choices = append(choices, [2]string{tunnelIP, "the VPN's tunnel"})
	}
	for _, ch := range choices {
		m.Choices = append(m.Choices, managementChoice{ch[0], ch[1], slices.Contains(addresses, ch[0])})
	}
	// ipv6_addresses: the ULA addresses among the listen addresses.
	if c.Management.IPv6 && c.IPv6.Enabled {
		for _, a := range render.ULAAddresses(c, ula) {
			if zones[a.Zone] {
				m.IPv6Addresses = append(m.IPv6Addresses, strings.TrimSuffix(a.Address, "/64"))
			}
		}
	}
	return m
}

// minimalManagement is the management view of _minimal_config: the
// screen still works when the config doesn't parse.
func minimalManagement() managementView {
	return managementView{Addresses: []string{render.Loopback}, Warning: apply.WANWarning, ConfirmSeconds: 300}
}

// persistenceStatus is frfw.persistence.status(labelled=[]): only
// /proc, which is all the webUI needs.
func (s *Server) persistenceStatus() (persistenceView, error) {
	var p persistenceView
	cmdline, _, err := readOptional(s.env.Paths.at("/proc/cmdline"))
	if err != nil {
		return p, err
	}
	mounts, _, err := readOptional(s.env.Paths.at("/proc/mounts"))
	if err != nil {
		return p, err
	}
	args := config.PySplit(cmdline)
	p.Live, p.Requested = slices.Contains(args, "boot=live"), slices.Contains(args, "persistence")
	devices := map[string]bool{}
	boot := false
	for _, line := range config.PySplitlines(mounts) {
		parts := config.PySplit(line)
		if len(parts) < 2 {
			continue
		}
		src, target := parts[0], strings.ReplaceAll(parts[1], `\040`, " ")
		if strings.HasPrefix(target, "/run/live/persistence/") {
			devices[src] = true
		}
		if target == "/run/live/medium" && !boot {
			p.BootDevice, boot = src, true
		}
	}
	for d := range devices {
		p.Devices = append(p.Devices, d)
	}
	sort.Strings(p.Devices)
	p.Active = p.Live && len(p.Devices) > 0
	return p, nil
}

// stdB64Decode is base64.b64decode without validate: characters outside
// the alphabet are skipped, padding ends the data; false where Python
// raises (binascii.Error, or a str that isn't ASCII).
func stdB64Decode(text string) ([]byte, bool) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out []byte
	quad, pads := 0, 0
	var left byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c >= 0x80 {
			return nil, false
		}
		if c == '=' {
			if quad >= 2 {
				pads++
				if quad+pads >= 4 {
					return out, true
				}
			}
			continue
		}
		v := strings.IndexByte(alphabet, c)
		if v < 0 {
			continue
		}
		b := byte(v)
		pads = 0
		switch quad {
		case 0:
			quad, left = 1, b
		case 1:
			out = append(out, left<<2|b>>4)
			quad, left = 2, b&0x0f
		case 2:
			out = append(out, left<<4|b>>2)
			quad, left = 3, b&0x03
		case 3:
			out = append(out, left<<6|b)
			quad, left = 0, 0
		}
	}
	return out, quad == 0
}

func (s *Server) certPath() string { return s.env.Paths.at("/etc/fr_os/webui/cert.pem") }

// certDER is _cert_der: the certificate's bytes, or false.
func (s *Server) certDER() (string, []byte, bool, error) {
	text, found, err := readOptional(s.certPath())
	if err != nil || !found {
		return "", nil, false, err
	}
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	if !strings.Contains(text, begin) || !strings.Contains(text, end) {
		return text, nil, false, nil
	}
	_, body, _ := strings.Cut(text, begin)
	body, _, _ = strings.Cut(body, end)
	der, ok := stdB64Decode(strings.Join(config.PySplit(body), ""))
	return text, der, ok, nil
}

func (s *Server) renderSystem(q *request, raw *config.Map, newToken string) (*answer, error) {
	d := &systemData{NewToken: newToken, Integrity: integrityView{Note: integrityNote}}
	groups, haveGroups, err := tlsGroups(s.env.Paths.at("/etc/fr_os/webui_pqc_openssl.cnf"))
	if err != nil {
		return nil, err
	}
	cfg, err := config.Parse(raw)
	var enabled bool
	if err != nil {
		section, err := getMapOr(raw, "pqc")
		if err != nil {
			return nil, err
		}
		enabled = config.Truthy(pyGet(section, "enabled", false))
		d.Management = minimalManagement()
	} else {
		enabled = cfg.Pqc.Enabled
		d.Management = s.managementOf(cfg)
	}
	applied := haveGroups && strings.Contains(groups, "MLKEM")
	d.Status = pqcView{EnabledInConfig: enabled, HostSupportsHybrid: true, OpenSSLVersion: tlsLibrary,
		ConfiguredGroups: groups, AppliedHybrid: applied, QuantumSafe: enabled && applied}
	if d.Persistence, err = s.persistenceStatus(); err != nil {
		return nil, err
	}
	metrics, err := getMapOr(raw, "metrics")
	if err != nil {
		return nil, err
	}
	if v := field(metrics, "site"); config.Truthy(v) {
		d.MetricsSite = pyStr(v)
	}
	if v := field(raw, "hostname"); config.Truthy(v) {
		d.MetricsHostname = pyStr(v)
	}
	d.MetricsTokenSet = config.Truthy(field(metrics, "token_sha256"))
	_, der, ok, err := s.certDER()
	if err != nil {
		return nil, err
	}
	if ok {
		sum := sha256.Sum256(der)
		parts := make([]string, len(sum))
		for i, b := range sum {
			parts[i] = fmt.Sprintf("%02X", b)
		}
		d.CertSHA256 = strings.Join(parts, ":")
	}
	return s.render(q, "system", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) showSystem(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	return s.renderSystem(q, raw, "")
}

func (s *Server) savePQC(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	if err = q.fields(func(p *formParams) { enabled = p.boolOr("enabled", false) }); err != nil {
		return nil, err
	}
	raw.Set("pqc", cmdMap("enabled", enabled))
	return s.saved(raw, "/system", "PQC settings saved -- click Apply on the dashboard, then restart fr-webui, to load them")
}

// copiedSection is dict(raw.get(key) or {}).
func copiedSection(raw *config.Map, key string) (*config.Map, error) {
	section, err := getMapOr(raw, key)
	if err != nil {
		return nil, err
	}
	out := config.NewMap()
	for i, k := range section.Keys() {
		out.Set(k.(string), section.Values()[i])
	}
	return out, nil
}

func (s *Server) saveManagement(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var allowWan bool
	if err = q.fields(func(p *formParams) { allowWan = p.boolOr("allow_wan", false) }); err != nil {
		return nil, err
	}
	section, err := copiedSection(raw, "management")
	if err != nil {
		return nil, err
	}
	section.Set("allow_wan", allowWan)
	raw.Set("management", section)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/system", message), nil
	}
	if allowWan {
		// Security-lessons F2/G4: the explicit, warned opt-in.
		s.auditAlert(fmt.Sprintf("%s opened management (webUI, SSH) to the internet", config.Repr(q.user.Username)),
			entry("user", q.user.Username, "client", q.clientIP()))
		return errorRedirect("/system", "Saved. "+apply.WANWarning+" Click Apply to load it."), nil
	}
	return successRedirect("/system", "Management is LAN-only again -- click Apply to load it"), nil
}

func (s *Server) saveManagementIPv6(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var on bool
	if err = q.fields(func(p *formParams) { on = p.boolOr("ipv6", false) }); err != nil {
		return nil, err
	}
	section, err := copiedSection(raw, "management")
	if err != nil {
		return nil, err
	}
	section.Set("ipv6", on)
	raw.Set("management", section)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/system", message), nil
	}
	state := "off"
	if on {
		state = "on"
	}
	s.auditAppend(entry("user", q.user.Username, "client", q.clientIP(), "event", "management over IPv6 turned "+state))
	return successRedirect("/system", "Management over IPv6 "+state+" -- click Apply to load it"), nil
}

func (s *Server) saveManagementAddresses(q *request) (*answer, error) {
	var addresses []string
	if err := q.fields(func(p *formParams) { addresses = p.list("addresses") }); err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return errorRedirect("/system", "Tick at least one address, or only the console could reach the router"), nil
	}
	result, err := s.helper.SetManagementAddresses(addresses, q.user.Username)
	if err != nil {
		return nil, err
	}
	message := field(result, "message")
	if !config.Truthy(field(result, "ok")) {
		if !config.Truthy(message) {
			return errorRedirect("/system", "Could not move the webUI"), nil
		}
		return errorRedirect("/system", pyStr(message)), nil
	}
	s.auditAppend(entry("user", q.user.Username, "client", q.clientIP(),
		"event", "webUI and SSH moved to "+strings.Join(addresses, ", ")))
	if !config.Truthy(message) {
		return successRedirect("/", "Moved"), nil
	}
	return successRedirect("/", pyStr(message)), nil
}

func (s *Server) downloadCert(q *request) (*answer, error) {
	text, _, ok, err := s.certDER()
	if err != nil {
		return nil, err
	}
	if !ok {
		a := &answer{status: http.StatusNotFound, body: []byte("no certificate\n")}
		a.header("content-type", "text/plain; charset=utf-8")
		return a, nil
	}
	a := &answer{status: http.StatusOK, body: []byte(text)}
	a.header("content-disposition", `attachment; filename="fr_os-webui.pem"`)
	a.header("content-type", "application/x-pem-file")
	return a, nil
}

func (s *Server) saveMetricsSite(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var site string
	if err = q.fields(func(p *formParams) { site = p.strOr("site", "") }); err != nil {
		return nil, err
	}
	section, err := copiedSection(raw, "metrics")
	if err != nil {
		return nil, err
	}
	if v := pyStripped(site); v != "" {
		section.Set("site", v)
	} else {
		section.Delete("site")
	}
	raw.Set("metrics", section)
	return s.saved(raw, "/system", "Site name saved")
}

func (s *Server) changeMetricsToken(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var action string
	if err = q.fields(func(p *formParams) { action = p.str("action") }); err != nil {
		return nil, err
	}
	section, err := copiedSection(raw, "metrics")
	if err != nil {
		return nil, err
	}
	var token string
	switch action {
	case "generate":
		token = s.env.tokenURLSafe(32)
		sum := sha256.Sum256([]byte(token))
		section.Set("token_sha256", fmt.Sprintf("%x", sum))
	case "disable":
		section.Delete("token_sha256")
	default:
		return errorRedirect("/system", fmt.Sprintf("unknown action %s", config.Repr(action))), nil
	}
	raw.Set("metrics", section)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/system", message), nil
	}
	if token == "" {
		return successRedirect("/system", "Metrics token removed: /metrics is off"), nil
	}
	// Rendered, never redirected: a token in a URL would end up in the
	// browser's history and the access logs.
	return s.renderSystem(q, raw, token)
}
