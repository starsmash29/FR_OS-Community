package apply

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The IPv6 step (frfw.ipv6, ROADMAP FND-1a/1b/1c): the kernel's IPv6
// settings, dhcpcd on the WAN, the LAN's stable (ULA) addresses and its
// Router Advertisement instance.

var (
	// ulaLocal is fd00::/8, where a generated prefix comes from (RFC
	// 4193's locally assigned half).
	ulaLocal = netip.MustParsePrefix("fd00::/8")
	// ulaAll is every unique local address, fc00::/7.
	ulaAll = netip.MustParsePrefix("fc00::/7")
)

// ipv6Gone are iproute2's answers when there is nothing to take off.
var ipv6Gone = []string{"Cannot assign requested address", "Cannot find device"}

func (s *System) kernelHasIPv6() bool { return isDir(filepath.Join(s.Paths.ProcNet, "ipv6", "conf")) }

const noKernelIPv6 = "this kernel runs without IPv6 (ipv6.disable=1 on its command line)"

// checkIPv6 is the preflight of an apply with IPv6 on: a kernel with
// IPv6, dhcpcd, and dnsmasq for the LAN's RAs.
func (s *System) checkIPv6(c *config.Config) error {
	if !s.kernelHasIPv6() {
		return &StepError{noKernelIPv6}
	}
	if !isFile(s.Paths.DhcpcdBinary) {
		return stepErr("%s is not installed (Debian's dhcpcd-base)", s.Paths.DhcpcdBinary)
	}
	if len(c.LanDevices()) > 0 && !isFile(s.Paths.RADnsmasqBinary) {
		return stepErr("%s is not installed (Debian's dnsmasq-base), and the LAN's "+
			"Router Advertisements need it", s.Paths.RADnsmasqBinary)
	}
	return nil
}

// --- the ULA state file -------------------------------------------------------

// readULAState is the state file as a dict; empty when it can't be read
// or isn't one.
func (s *System) readULAState() *config.Map {
	text, ok := readText(s.Paths.IPv6ULAState)
	if !ok {
		return config.NewMap()
	}
	v, err := config.ParseJSONLastWins([]byte(text))
	if m, isMap := v.(*config.Map); err == nil && isMap {
		return m
	}
	return config.NewMap()
}

func (s *System) writeULAState(state *config.Map) error {
	text, err := config.PyJSON(state, 1, true)
	if err != nil {
		return err
	}
	name := filepath.Base(s.Paths.IPv6ULAState)
	return pyOSError(replaceFile(s.Paths.IPv6ULAState, "."+name+".tmp", text+"\n", 0o644))
}

// validULA is the /48 a state file names, when it is one of fd00::/8.
func validULA(v config.Value) *netip.Prefix {
	text, ok := v.(string)
	if !ok {
		return nil
	}
	p, err := netip.ParsePrefix(text)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() || p.Addr().Zone() != "" || p.Masked() != p ||
		p.Bits() != 48 || !ulaLocal.Contains(p.Addr()) {
		return nil
	}
	return &p
}

// ULAPrefix is the ULA /48 of the LAN's stable networks: ipv6.ula_prefix,
// or the one the router generated (nil until an apply generated it).
func (s *System) ULAPrefix(c *config.Config) *netip.Prefix {
	generated, _ := s.readULAState().Get("generated")
	return render.ULAPrefix(c, validULA(generated))
}

// ensureULA is ULAPrefix, generating and keeping one the first time. The
// generated one is kept even while ipv6.ula_prefix overrides it, so
// taking the override out doesn't renumber the LAN again.
func (s *System) ensureULA(c *config.Config) (*netip.Prefix, error) {
	state := s.readULAState()
	if g, _ := state.Get("generated"); validULA(g) == nil {
		p, err := s.generateULA()
		if err != nil {
			return nil, err
		}
		state.Set("generated", p.String())
		if err := s.writeULAState(state); err != nil {
			return nil, err
		}
	}
	return s.ULAPrefix(c), nil
}

// generateULA is a ULA /48 with a 40-bit random global ID (RFC 4193
// 3.2) from the OS's CSPRNG, never fd00::/48.
func (s *System) generateULA() (netip.Prefix, error) {
	var id [5]byte
	if err := s.Random(id[:]); err != nil {
		return netip.Prefix{}, err
	}
	if id == [5]byte{} {
		id[4] = 1
	}
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:6], id[:])
	return netip.PrefixFrom(netip.AddrFrom16(a), 48), nil
}

// appliedULA are the (device, address) pairs the state file says an
// apply put on: only well-formed ones, and only ULAs.
func appliedULA(state *config.Map) [][2]string {
	v, _ := state.Get("addresses")
	items, _ := v.([]config.Value)
	var pairs [][2]string
	for _, item := range items {
		pair, ok := item.([]config.Value)
		if !ok || len(pair) != 2 {
			continue
		}
		device, ok1 := pair[0].(string)
		address, ok2 := pair[1].(string)
		if !ok1 || !ok2 {
			continue
		}
		if _, err := Ifname(device); err != nil {
			continue
		}
		p, err := ipv6Interface(address)
		if err != nil || !ulaAll.Contains(p.Addr()) {
			continue
		}
		pairs = append(pairs, [2]string{device, address})
	}
	return pairs
}

// ipv6Interface is ipaddress.IPv6Interface(text): an address with an
// optional prefix length, host bits allowed.
func ipv6Interface(text string) (netip.Prefix, error) {
	if !strings.Contains(text, "/") {
		text += "/128"
	}
	p, err := netip.ParsePrefix(text)
	if err != nil || !p.Addr().Is6() || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("not an IPv6 interface: %s", text)
	}
	return p, nil
}

func (s *System) ip6(timeoutArgs ...string) (Result, error) {
	argv := append([]string{"ip", "-6"}, timeoutArgs...)
	res, err := s.Run(Cmd{Argv: argv, Timeout: 10 * time.Second})
	switch {
	case errors.Is(err, ErrNotFound):
		return res, stepErr("'ip' binary not found; install the iproute2 package")
	}
	return res, err
}

// setULA takes off the ULA addresses an earlier apply put on and this
// one doesn't want (gone already is fine), then puts on the wanted ones,
// without duplicate address detection (the router's own address on its
// own link). Security-lessons F1: the device always after `dev`.
func (s *System) setULA(wanted, before [][2]string) error {
	for _, p := range before {
		if slices.Contains(wanted, p) {
			continue
		}
		device, address, err := ula(p)
		if err != nil {
			return err
		}
		res, err := s.ip6("addr", "del", address, "dev", device)
		if err != nil {
			return err
		}
		if res.Code != 0 && !slices.ContainsFunc(ipv6Gone, func(g string) bool { return strings.Contains(res.Stderr, g) }) {
			return stepErr("cannot take %s off %s: %s", address, device, config.PyStrip(res.Stderr))
		}
	}
	for _, p := range wanted {
		device, address, err := ula(p)
		if err != nil {
			return err
		}
		res, err := s.ip6("addr", "replace", address, "dev", device, "nodad")
		if err != nil {
			return err
		}
		if res.Code != 0 {
			return stepErr("cannot put %s on %s: %s", address, device, config.PyStrip(res.Stderr))
		}
	}
	return nil
}

func ula(p [2]string) (device, address string, err error) {
	if device, err = Ifname(p[0]); err != nil {
		return "", "", err
	}
	a, err := ipv6Interface(p[1])
	if err != nil {
		return "", "", err
	}
	return device, a.String(), nil
}

// syncULA puts the LAN devices' ULA addresses on, takes the stale ones
// off, and records what is on.
func (s *System) syncULA(c *config.Config) ([]render.ULAAddress, error) {
	lan := c.LanDevices()
	var prefix *netip.Prefix
	if len(lan) > 0 {
		var err error
		if prefix, err = s.ensureULA(c); err != nil {
			return nil, err
		}
	} else {
		prefix = s.ULAPrefix(c)
	}
	var addresses []render.ULAAddress
	if len(lan) > 0 {
		addresses = render.ULAAddresses(c, prefix)
	}
	state := s.readULAState()
	wanted := [][2]string{}
	recorded := []config.Value{}
	for _, a := range addresses {
		wanted = append(wanted, [2]string{a.Device, a.Address})
		recorded = append(recorded, []config.Value{a.Device, a.Address})
	}
	if err := s.setULA(wanted, appliedULA(state)); err != nil {
		return nil, err
	}
	state.Set("addresses", recorded)
	return addresses, s.writeULAState(state)
}

// ULAState is the ULA addresses an apply's IPv6 step may change, as they
// were: on undo the step's own additions come off and its removals go
// back.
type ULAState struct {
	text   string
	exists bool
}

func (s *System) captureULA() ULAState {
	text, ok := readText(s.Paths.IPv6ULAState)
	return ULAState{text, ok}
}

func (s *System) restoreULA(u ULAState) error {
	var before [][2]string
	if u.text != "" {
		v, err := config.ParseJSONLastWins([]byte(u.text))
		if err != nil {
			return err
		}
		m, ok := v.(*config.Map)
		if !ok {
			return errors.New("the recorded ULA state is not a mapping")
		}
		before = appliedULA(m)
	}
	if err := s.setULA(before, appliedULA(s.readULAState())); err != nil {
		return err
	}
	if !u.exists {
		return pyOSError(unlinkMissingOK(s.Paths.IPv6ULAState))
	}
	return pyOSError(writeText(s.Paths.IPv6ULAState, u.text))
}

// --- the kernel's settings ----------------------------------------------------

// sysctlValue is one setting as read: ok false for a device that isn't
// there.
type sysctlValue struct {
	Key, Value string
	OK         bool
}

func (s *System) readSysctls(keys []string) []sysctlValue {
	out := make([]sysctlValue, 0, len(keys))
	for _, k := range keys {
		text, ok := readText(filepath.Join(s.Paths.ProcNet, k))
		out = append(out, sysctlValue{k, config.PyStrip(text), ok})
	}
	return out
}

// writeSysctls writes each value; a device that isn't there (yet) is
// skipped.
func (s *System) writeSysctls(settings []sysctlValue) error {
	for _, kv := range settings {
		if !kv.OK {
			continue
		}
		path := filepath.Join(s.Paths.ProcNet, kv.Key)
		if !isDir(filepath.Dir(path)) {
			continue
		}
		current, err := readFile(path)
		if err == nil && config.PyStrip(current) != kv.Value {
			err = writeText(path, kv.Value+"\n")
		}
		if err != nil {
			return stepErr("cannot set net.%s = %s: %s", strings.ReplaceAll(kv.Key, "/", "."), kv.Value, osErrorText(err))
		}
	}
	return nil
}

func set(key, value string) sysctlValue { return sysctlValue{key, value, true} }

func sysctlsOf(c *config.Config) []sysctlValue {
	var out []sysctlValue
	for _, kv := range render.Sysctls(c) {
		out = append(out, set(kv.Key, kv.Value))
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// --- the services -------------------------------------------------------------

// serviceActive is frfw.ipv6.service_active: active, activating or
// reloading; no systemd is not active.
func (s *System) serviceActive(unit string) bool {
	res, err := Systemctl(s.Run, "is-active", unit, 30*time.Second)
	if err != nil {
		return false
	}
	switch config.PyStrip(res.Stdout) {
	case "active", "activating", "reloading":
		return true
	}
	return false
}

func (s *System) ipv6Systemctl(action, unit string) error {
	res, err := Systemctl(s.Run, action, unit, 60*time.Second)
	switch {
	case errors.Is(err, ErrNotFound):
		return stepErr("'systemctl' not found")
	case err != nil:
		return err
	}
	if res.Code != 0 {
		return stepErr("systemctl %s %s failed: %s (see journalctl -u %s)", action, unit, config.PyStrip(orStdout(res)), unit)
	}
	return nil
}

// orStdout is `proc.stderr or proc.stdout`.
func orStdout(res Result) string {
	if res.Stderr != "" {
		return res.Stderr
	}
	return res.Stdout
}

func (s *System) stopRA() error {
	if exists(s.Paths.IPv6RAConf) || s.serviceActive(IPv6RAService) {
		if err := s.ipv6Systemctl("stop", IPv6RAService); err != nil {
			return err
		}
		return pyOSError(unlinkMissingOK(s.Paths.IPv6RAConf))
	}
	return nil
}

// testRA is `dnsmasq --test` of the new RA config before it replaces the
// old one.
func (s *System) testRA(text string) error {
	if err := mkdirParent(s.Paths.IPv6RAConf); err != nil {
		return pyOSError(err)
	}
	candidate := s.Paths.IPv6RAConf + ".new"
	if err := writeText(candidate, text); err != nil {
		return pyOSError(err)
	}
	argv := []string{s.Paths.RADnsmasqBinary, "--test", "--conf-file=" + candidate}
	res, err := s.Run(Cmd{Argv: argv, Timeout: 30 * time.Second})
	if rmErr := unlinkMissingOK(candidate); err == nil && rmErr != nil {
		return pyOSError(rmErr)
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return stepErr("%s is not installed (Debian's dnsmasq-base)", s.Paths.RADnsmasqBinary)
	case err != nil:
		return err
	}
	if res.Code != 0 {
		return stepErr("dnsmasq rejected the Router Advertisement config: %s", config.PyStrip(orStdout(res)))
	}
	return nil
}

// --- the step -----------------------------------------------------------------

// syncIPv6 reconciles the kernel's IPv6 settings, dhcpcd, the LAN's ULA
// addresses and its RA instance with config.ipv6.
func (s *System) syncIPv6(c *config.Config, dryRun bool) (string, error) {
	p := s.Paths
	lan := c.LanDevices()
	if !c.IPv6.Enabled {
		// Nothing to do -- not even a systemctl call -- unless an earlier
		// apply turned it on.
		if !(exists(p.IPv6DhcpcdConf) || exists(p.IPv6RAConf) || len(appliedULA(s.readULAState())) > 0 ||
			s.serviceActive(IPv6Service) || s.serviceActive(IPv6RAService)) {
			return "IPv6 off", nil
		}
		if dryRun {
			return "Would turn IPv6 off (dry-run)", nil
		}
		if !s.root() {
			return "", stepErr("Setting up IPv6 requires root privileges.")
		}
		if err := s.stopRA(); err != nil {
			return "", err
		}
		if _, err := s.syncULA(c); err != nil {
			return "", err
		}
		if err := s.ipv6Systemctl("stop", IPv6Service); err != nil {
			return "", err
		}
		if err := unlinkMissingOK(p.IPv6DhcpcdConf); err != nil {
			return "", pyOSError(err)
		}
		// Routing off with it (but for the VPN); the kernel's other
		// settings stay as safe as they are.
		if err := s.writeSysctls([]sysctlValue{set("ipv6/conf/all/forwarding", onOff(c.IPv6ForwardingWanted()))}); err != nil {
			return "", err
		}
		return "IPv6 turned off", nil
	}

	devices := c.WanDevices()
	if !s.kernelHasIPv6() {
		return "", &StepError{noKernelIPv6}
	}
	where := "; no LAN zone gets IPv6"
	if len(lan) > 0 {
		var names []string
		for _, zd := range lan {
			names = append(names, zd.Device)
		}
		where = "; the LAN gets a /64 each on " + strings.Join(names, ", ") + " (Router Advertisements, SLAAC)"
	}
	if dryRun {
		return "Would take IPv6 from the provider on " + strings.Join(devices, ", ") + where + " (dry-run)", nil
	}
	if !s.root() {
		return "", stepErr("Setting up IPv6 requires root privileges.")
	}
	var raText string
	if len(lan) > 0 {
		prefix, err := s.ensureULA(c)
		if err != nil {
			return "", err
		}
		raText = render.RA(c, prefix)
		if err := s.testRA(raText); err != nil {
			return "", err
		}
	}
	if err := s.writeSysctls(sysctlsOf(c)); err != nil {
		return "", err
	}
	text := render.Dhcpcd(c)
	current, ok := readText(p.IPv6DhcpcdConf)
	changed := !ok || current != text
	if changed {
		if err := mkdirParent(p.IPv6DhcpcdConf); err != nil {
			return "", pyOSError(err)
		}
		if err := writeText(p.IPv6DhcpcdConf, text); err != nil {
			return "", pyOSError(err)
		}
	}
	// A restart drops the addresses and asks the provider again: only for
	// a new config, not on every apply.
	if err := s.ipv6Systemctl(restartOrStart(changed), IPv6Service); err != nil {
		return "", err
	}
	// FND-1c: the stable addresses, after dhcpcd (which takes off only
	// what it put on) and before the RA instance advertises them.
	stable, err := s.syncULA(c)
	if err != nil {
		return "", err
	}
	if len(stable) > 0 {
		var parts []string
		for _, a := range stable {
			parts = append(parts, a.Device+" "+a.Address)
		}
		where += "; stable addresses " + strings.Join(parts, ", ")
	}
	if len(lan) == 0 {
		if err := s.stopRA(); err != nil {
			return "", err
		}
	} else {
		current, ok := readText(p.IPv6RAConf)
		raChanged := !ok || current != raText
		if raChanged {
			if err := writeText(p.IPv6RAConf, raText); err != nil {
				return "", pyOSError(err)
			}
			// fr-ra's dynamic account reads it; it holds device names only.
			if err := os.Chmod(p.IPv6RAConf, 0o644); err != nil {
				return "", pyOSError(err)
			}
		}
		if err := s.ipv6Systemctl(restartOrStart(raChanged), IPv6RAService); err != nil {
			return "", err
		}
	}
	return "IPv6: dhcpcd on " + strings.Join(devices, ", ") +
		" (SLAAC, DHCPv6 address and prefix delegation)" + where, nil
}

func restartOrStart(changed bool) string {
	if changed {
		return "restart"
	}
	return "start"
}

// ipv6Touched: the IPv6 step has something to undo -- it is on, or an
// earlier apply left something behind.
func (s *System) ipv6Touched(c, previous *config.Config) bool {
	p := s.Paths
	return c.IPv6.Enabled || exists(p.IPv6DhcpcdConf) || exists(p.IPv6RAConf) || exists(p.IPv6ULAState) ||
		(previous != nil && previous.IPv6.Enabled)
}
