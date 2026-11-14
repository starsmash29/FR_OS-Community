package apply

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// What the console's login screen shows besides /etc/issue: agetty runs
// as root and prints the /etc/issue.d/*.issue files after /etc/issue
// before every login prompt.
//
//   - The router's ports, kept current (frfw.console_ports): every
//     physical port with its link, the role the applied config gives it
//     and its IPv4 addresses, the webUI's address, and a warning when the
//     LAN port has no link while a port no role uses has one -- the LAN
//     cable is likely in the wrong port. Roles are never changed here (a
//     cable in the wrong port must not move the LAN, and the webUI with
//     it, onto the upstream network). Not secret: 0644, like /etc/issue.
//   - The generated admin password (frfw.initial_password), root-only
//     (0600), until it no longer signs in (review triage A5: it used to be
//     in the world-readable /etc/issue, forever).

// --- the ports -----------------------------------------------------------------------

// consoleLegacyPrefixes start first boot's one-off lines in /etc/issue
// (before the port summary): now stale copies of what it shows.
var consoleLegacyPrefixes = []string{"FR_OS webUI: ", "FR_OS no LAN port assigned "}

// consoleRole is one config interface on a device.
type consoleRole struct {
	name, zone string
	// vlan is the VLAN id's text, "" for none (Python: falsy).
	vlan string
}

// consoleRoles is which config interfaces sit on each device: by
// `device`, or by `vlan.parent` for a VLAN of it. Read without
// validating: a summary of a config the loader would refuse is still
// better than none.
func consoleRoles(text *string) map[string][]consoleRole {
	roles := map[string][]consoleRole{}
	if text == nil || *text == "" {
		return roles
	}
	raw, err := config.LoadYAML(*text)
	if err != nil {
		return roles
	}
	top, _ := raw.(*config.Map)
	if top == nil {
		return roles
	}
	iv, _ := top.Get("interfaces")
	interfaces, _ := iv.(*config.Map)
	if interfaces == nil {
		return roles
	}
	for i, name := range interfaces.Keys() {
		entry, _ := interfaces.Values()[i].(*config.Map)
		if entry == nil {
			continue
		}
		vv, _ := entry.Get("vlan")
		vlan, _ := vv.(*config.Map)
		var device config.Value
		if vlan != nil && vlan.Len() > 0 {
			device, _ = vlan.Get("parent")
		} else {
			device, _ = entry.Get("device")
		}
		d, ok := device.(string)
		if !ok {
			continue
		}
		id := ""
		if vlan != nil && vlan.Len() > 0 {
			switch x, _ := vlan.Get("id"); v := x.(type) {
			case *big.Int:
				if v.Sign() != 0 {
					id = v.String()
				}
			case bool:
				if v {
					id = "True"
				}
			}
		}
		zone := config.Value("?")
		if z, ok := entry.Get("zone"); ok {
			zone = z
		}
		roles[d] = append(roles[d], consoleRole{name: config.Str(name), zone: config.Str(zone), vlan: id})
	}
	return roles
}

// ipv4Addresses is each device's IPv4 addresses, from `ip -j` (the
// kernel's, so a WAN's DHCP lease is there too); none when ip fails.
func (s *System) ipv4Addresses() map[string][]string {
	res, err := s.Run(Cmd{Argv: []string{"ip", "-j", "-4", "address", "show"}, Timeout: 10 * time.Second})
	found := map[string][]string{}
	if err != nil {
		return found
	}
	var entries config.Value = []config.Value{}
	if res.Code == 0 {
		if entries, err = config.ParseJSONLastWins([]byte(res.Stdout)); err != nil {
			return found
		}
	}
	list, _ := entries.([]config.Value)
	for _, e := range list {
		entry, _ := e.(*config.Map)
		if entry == nil {
			continue
		}
		ifv, _ := entry.Get("ifname")
		ifname, ok := ifv.(string)
		if !ok {
			continue
		}
		ai, _ := entry.Get("addr_info")
		infos, _ := ai.([]config.Value)
		for _, i := range infos {
			info, _ := i.(*config.Map)
			if info == nil {
				continue
			}
			local, _ := info.Get("local")
			prefix, hasPrefix := info.Get("prefixlen")
			if !config.Truthy(local) || !hasPrefix || prefix == nil {
				continue
			}
			found[ifname] = append(found[ifname], config.Str(local)+"/"+config.Str(prefix))
		}
	}
	return found
}

// agettyEscape: agetty reads `\x` sequences in issue files; print them
// literally.
func agettyEscape(text string) string { return strings.ReplaceAll(text, `\`, `\\`) }

func linkText(iface DetectedInterface) string {
	// A port that is down has no readable carrier (nil): no link either.
	if iface.Link == nil || !*iface.Link {
		return "no link"
	}
	if iface.SpeedMbps > 0 {
		return fmt.Sprintf("link %d Mbit/s", iface.SpeedMbps)
	}
	return "link up"
}

func roleText(roles []consoleRole) string {
	if len(roles) == 0 {
		return "not assigned"
	}
	var parts []string
	for _, r := range roles {
		text := r.name + " (zone " + r.zone + ")"
		if r.name == r.zone {
			text = strings.ToUpper(r.name)
		}
		if r.vlan != "" {
			text += " on VLAN " + r.vlan
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ", ")
}

// RenderConsolePorts is the summary agetty shows: a header, one line
// per port, the webUI's address, and a warning when the LAN cable looks
// misplaced.
func renderConsolePorts(ifaces []DetectedInterface, roles map[string][]consoleRole, addresses map[string][]string,
	webui []string) string {
	lines := []string{"FR_OS ports:"}
	width := 0
	for _, i := range ifaces {
		width = max(width, len([]rune(i.Name)))
	}
	for _, i := range ifaces {
		address := strings.Join(addresses[i.Name], ", ")
		if address == "" {
			address = "no address"
		}
		lines = append(lines, fmt.Sprintf("  %-*s  %-18s %-14s  %s", width, i.Name, linkText(i), roleText(roles[i.Name]), address))
	}
	if len(ifaces) == 0 {
		lines = append(lines, "  no network ports found")
	}
	var reachable []string
	for _, a := range webui {
		if a != render.Loopback {
			reachable = append(reachable, "https://"+a+"/")
		}
	}
	switch {
	case len(reachable) > 0:
		lines = append(lines, "webUI: "+strings.Join(reachable, ", ")+" (from the LAN)")
	case len(roles) == 0:
		lines = append(lines, "No port has a role yet: run 'firewall-cli assign-interfaces' or the first-boot setup.")
	}
	var lan, spare []string
	lanLinked := false
	for _, i := range ifaces {
		isLAN := false
		for _, r := range roles[i.Name] {
			if r.name == "lan" || r.zone == "lan" {
				isLAN = true
			}
		}
		up := i.Link != nil && *i.Link
		if isLAN {
			lan = append(lan, i.Name)
			lanLinked = lanLinked || up
		}
		if len(roles[i.Name]) == 0 && up {
			spare = append(spare, i.Name)
		}
	}
	if len(lan) > 0 && !lanLinked && len(spare) > 0 {
		lines = append(lines, "WARNING: the LAN port ("+strings.Join(lan, ", ")+") has no link, but "+
			strings.Join(spare, ", ")+" (no role) has one: is the LAN cable in the wrong port? Move it, or give that "+
			"port the LAN role in the webUI.")
	}
	for i, l := range lines {
		lines[i] = agettyEscape(l)
	}
	return strings.Join(lines, "\n") + "\n\n"
}

// runningConfigText is the config the router runs: the last one applied
// in full (ROADMAP SEC-5), else config.yaml (first boot, before any
// apply).
func (s *System) runningConfigText() *string {
	for _, path := range []string{s.Paths.AppliedConfig, s.Paths.Config} {
		if data, err := os.ReadFile(path); err == nil {
			text := string(data)
			return &text
		}
	}
	return nil
}

// RecordedWebUIListen is the addresses the last applied config has the
// webUI listen on, each as ipaddress.ip_address writes it, or nil when
// none are recorded or the record is not one
// (frfw.management.recorded_webui_listen).
func RecordedWebUIListen(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil
	}
	raw, _ := m.Get("addresses")
	list, ok := raw.([]config.Value)
	if !ok || len(list) == 0 {
		return nil
	}
	var out []string
	for _, a := range list {
		addr, err := config.ParsePyIP(a)
		if err != nil {
			return nil
		}
		out = append(out, addr.String())
	}
	return out
}

// ConsolePorts is the port summary as it stands.
func (s *System) ConsolePorts() string {
	return renderConsolePorts(ListInterfaces(s.Paths.NetClass, false), consoleRoles(s.runningConfigText()),
		s.ipv4Addresses(), RecordedWebUIListen(s.Paths.WebUIListen))
}

// writeConsolePorts replaces the file when its text changed; true when
// it did.
func (s *System) writeConsolePorts(text string) (bool, error) {
	path := s.Paths.PortsIssue
	if old, err := os.ReadFile(path); err == nil && string(old) == text {
		return false, nil
	}
	if err := mkdirMode(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, replaceFile(path, "."+filepath.Base(path)+".tmp", text, 0o644)
}

// mkdirMode is path.mkdir(mode=mode, parents=True, exist_ok=True).
func mkdirMode(path string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// removeLegacyConsoleLine takes first boot's old one-off lines (and the
// blank line after each) out of /etc/issue, in place.
func (s *System) removeLegacyConsoleLine() error {
	data, err := os.ReadFile(s.Paths.Issue)
	if err != nil {
		return nil
	}
	var kept []string
	dropped, skipBlank := false, false
	for _, line := range config.PySplitlinesKeepends(string(data)) {
		legacy := false
		for _, p := range consoleLegacyPrefixes {
			legacy = legacy || strings.HasPrefix(line, p)
		}
		if legacy {
			dropped, skipBlank = true, true
			continue
		}
		if skipBlank && config.PyStrip(line) == "" {
			skipBlank = false
			continue
		}
		skipBlank = false
		kept = append(kept, line)
	}
	if !dropped {
		return nil
	}
	return writeInPlace(s.Paths.Issue, strings.Join(kept, ""))
}

// writeInPlace is open(path, "w"): truncated, its mode and owner kept.
func writeInPlace(path, text string) error {
	return os.WriteFile(path, []byte(text), 0o666)
}

// RefreshConsolePorts rewrites the summary, takes the old line out of
// /etc/issue and, when the summary changed, asks the running gettys to
// print the login screen again.
func (s *System) RefreshConsolePorts() (bool, error) {
	if err := s.removeLegacyConsoleLine(); err != nil {
		return false, err
	}
	changed, err := s.writeConsolePorts(s.ConsolePorts())
	if err != nil {
		return false, err
	}
	if changed {
		s.Run(Cmd{Argv: []string{"agetty", "--reload"}, Timeout: 10 * time.Second})
	}
	return changed, nil
}

// rtnetlink multicast groups (linux/rtnetlink.h): link up/down and
// renamed devices, IPv4 addresses added or removed (a DHCP lease).
const (
	rtmgrpLink       = 0x1
	rtmgrpIPv4Ifaddr = 0x10
	// consolePoll is how often WatchConsolePorts looks at the config
	// files between kernel events; consoleSettle how long it lets a
	// burst of messages (a link flapping) end before redrawing.
	consolePoll   = 5 * time.Second
	consoleSettle = time.Second
)

func (s *System) consoleMtimes() [3]int64 {
	var out [3]int64
	for i, p := range []string{s.Paths.AppliedConfig, s.Paths.Config, s.Paths.WebUIListen} {
		if st, err := os.Stat(p); err == nil {
			out[i] = st.ModTime().UnixNano()
		} else {
			out[i] = -1
		}
	}
	return out
}

// WatchConsolePorts keeps the summary current (fr-console-ports.service):
// at start, on every link or address change the kernel reports, and
// when the applied config or the webUI's addresses change. It returns
// only when the kernel's notifications can't be read.
func (s *System) WatchConsolePorts() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK,
		Groups: rtmgrpLink | rtmgrpIPv4Ifaddr}); err != nil {
		return err
	}
	if _, err := s.RefreshConsolePorts(); err != nil {
		return err
	}
	seen := s.consoleMtimes()
	buf := make([]byte, 65536)
	for {
		ready, err := waitReadable(fd, consolePoll)
		if err != nil {
			return err
		}
		if ready {
			time.Sleep(consoleSettle)
			for {
				more, err := waitReadable(fd, 0)
				if err != nil {
					return err
				}
				if !more {
					break
				}
				if _, _, err := syscall.Recvfrom(fd, buf, 0); err != nil && !errors.Is(err, syscall.EINTR) {
					return err
				}
			}
		}
		now := s.consoleMtimes()
		if ready || now != seen {
			seen = now
			if _, err := s.RefreshConsolePorts(); err != nil {
				return err
			}
		}
	}
}

// waitReadable is select([fd], [], [], timeout) on one descriptor.
func waitReadable(fd int, timeout time.Duration) (bool, error) {
	for {
		var set syscall.FdSet
		set.Bits[fd/64] |= 1 << (uint(fd) % 64)
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		n, err := syscall.Select(fd+1, &set, nil, nil, &tv)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return n > 0, err
	}
}

// --- the initial admin password ------------------------------------------------------

var (
	initialLineRE = regexp.MustCompile(`(?m)^FR_OS: initial webUI admin login is '([^']+)' / '([^']+)'$`)
	// The v0.1.0 block in /etc/issue: the login line, the optional hint
	// and the "Change it..." line, then a blank line.
	legacyBlockRE = regexp.MustCompile(`(?m)^FR_OS: initial webUI admin login is '[^']+' / '[^']+'\n` +
		`(?:webUI: .*\n)?` +
		`Change it after logging in, then this line stays until you edit /etc/issue\.\n\n?`)
)

// WriteInitialPassword puts the generated login on the console: a
// root-only file (0600 from the start, never briefly readable).
func (s *System) WriteInitialPassword(username, password string) error {
	path := s.Paths.InitialIssue
	if err := mkdirMode(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := unlinkMissingOK(tmp); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	text := "FR_OS: initial webUI admin login is '" + username + "' / '" + password + "'\n" +
		"It disappears from this screen once you change it in the webUI.\n\n"
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readInitialLogin is the login a console file shows, ok false when it
// shows none.
func readInitialLogin(path string) (username, password string, ok bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	m := initialLineRE.FindStringSubmatch(string(data))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// InitialLogin is the login on the console, ok false when none is shown.
func (s *System) InitialLogin() (username, password string, ok bool) {
	return readInitialLogin(s.Paths.InitialIssue)
}

// RemoveInitialLogin takes it off the console.
func (s *System) RemoveInitialLogin() error { return unlinkMissingOK(s.Paths.InitialIssue) }

// MigrateLegacyInitialPassword moves a v0.1.0-style password line out of
// the world-readable /etc/issue into the root-only file; true when there
// was one.
func (s *System) MigrateLegacyInitialPassword() (bool, error) {
	data, err := os.ReadFile(s.Paths.Issue)
	if err != nil {
		return false, nil
	}
	text := string(data)
	found := initialLineRE.FindStringSubmatch(text)
	if found == nil {
		return false, nil
	}
	if _, _, ok := s.InitialLogin(); !ok {
		if err := s.WriteInitialPassword(found[1], found[2]); err != nil {
			return false, err
		}
	}
	cleaned := legacyBlockRE.ReplaceAllLiteralString(text, "")
	if initialLineRE.MatchString(cleaned) {
		cleaned = initialLineRE.ReplaceAllLiteralString(cleaned, "")
	}
	return true, writeInPlace(s.Paths.Issue, cleaned)
}
