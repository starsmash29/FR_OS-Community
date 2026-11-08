package apply

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// StepError is a step's own refusal or failure (1.x's IfaddrError,
// KeaError, Ipv6Error, ...): its text is what the admin reads.
type StepError struct{ Msg string }

func (e *StepError) Error() string { return e.Msg }

func stepErr(format string, args ...any) error { return &StepError{fmt.Sprintf(format, args...)} }

// pyOSError is an OSError's text where 1.x lets one through to the
// apply's error.
func pyOSError(err error) error {
	if err == nil {
		return nil
	}
	var se *StepError
	if errors.As(err, &se) {
		return err
	}
	return &StepError{osErrorText(err)}
}

// --- IPv4 forwarding (frfw.forwarding) --------------------------------------

// enableForwarding turns the kernel's IPv4 forwarding on. Only once the
// forward chain is loaded: never a moment in which the kernel routes and
// nothing filters it.
func (s *System) enableForwarding(dryRun bool) (string, error) {
	if dryRun {
		return "Would turn IPv4 forwarding on (dry-run)", nil
	}
	path := s.Paths.IPForward
	text, err := readFile(path)
	if err == nil && config.PyStrip(text) == "1" {
		return "IPv4 forwarding on", nil
	}
	if err == nil {
		err = writeText(path, "1\n")
	}
	if err != nil {
		return "", stepErr("cannot turn IPv4 forwarding on (%s): %s", path, osErrorText(err))
	}
	return "IPv4 forwarding turned on", nil
}

// --- interface addresses (frfw.ifaddr) --------------------------------------

func ifaddrErr(err error) error {
	var ae *ArgumentError
	if errors.As(err, &ae) {
		return &StepError{ae.Msg}
	}
	return err
}

// syncAddresses creates the missing VLAN devices (security-lessons K4),
// takes off the addresses the last applied config set that this one no
// longer has (review v0.2.1 FR-NEW-005), then puts on every interface's
// static address. An address FR_OS never set is never touched.
func (s *System) syncAddresses(c, previous *config.Config, dryRun bool) (string, error) {
	var vlans, addressed []config.Interface
	for _, i := range c.Interfaces.Values() {
		if i.VlanParent != "" {
			vlans = append(vlans, i)
		}
		if i.Address != "" {
			addressed = append(addressed, i)
		}
	}
	if len(vlans) > 0 && !dryRun {
		if !s.root() {
			return "", stepErr("Applying interface addresses requires root privileges.")
		}
		for _, i := range vlans {
			if err := s.ensureVlan(i); err != nil {
				return "", err
			}
		}
	}
	stale := staleAddresses(c, previous)
	if len(addressed) == 0 && len(stale) == 0 {
		return "No interface addresses to sync", nil
	}
	var set, gone []string
	for _, i := range addressed {
		set = append(set, i.Device+"="+i.Address)
	}
	for _, p := range stale {
		gone = append(gone, p[0]+"="+p[1])
	}
	summary, removed := strings.Join(set, ", "), strings.Join(gone, ", ")
	var parts []string
	if dryRun {
		if len(addressed) > 0 {
			parts = append(parts, "Would set addresses: "+summary)
		}
		if len(stale) > 0 {
			parts = append(parts, "Would remove addresses: "+removed)
		}
		return strings.Join(parts, "; "), nil
	}
	if !s.root() {
		return "", stepErr("Applying interface addresses requires root privileges.")
	}
	// Removed first: an address that moves to another device is then
	// never on two devices at once.
	for _, p := range stale {
		if err := s.removeAddress(p[0], p[1]); err != nil {
			return "", err
		}
	}
	for _, i := range addressed {
		device, err := Ifname(i.Device)
		if err != nil {
			return "", ifaddrErr(err)
		}
		address, err := IPv4Interface(i.Address)
		if err != nil {
			return "", ifaddrErr(err)
		}
		// Security-lessons F1: the device always after `dev` -- iproute2
		// has no `--`, but takes whatever follows `dev` as the name.
		if err := s.ip("addr", "replace", address, "dev", device); err != nil {
			return "", err
		}
		if err := s.ip("link", "set", "dev", device, "up"); err != nil {
			return "", err
		}
	}
	if len(addressed) > 0 {
		parts = append(parts, "Addresses applied: "+summary)
	}
	if len(stale) > 0 {
		parts = append(parts, "Addresses removed: "+removed)
	}
	return strings.Join(parts, "; "), nil
}

// staleAddresses are the (device, address) pairs previous set that c
// doesn't: what an apply of c takes off.
func staleAddresses(c, previous *config.Config) [][2]string {
	if previous == nil {
		return nil
	}
	wanted := map[[2]string]bool{}
	for _, i := range c.Interfaces.Values() {
		if i.Address != "" {
			wanted[[2]string{i.Device, canonicalInterface(i.Address)}] = true
		}
	}
	var stale [][2]string
	for _, i := range previous.Interfaces.Values() {
		if i.Address == "" {
			continue
		}
		pair := [2]string{i.Device, canonicalInterface(i.Address)}
		if !wanted[pair] && !slices.Contains(stale, pair) {
			stale = append(stale, pair)
		}
	}
	return stale
}

// canonicalInterface is str(IPv4Interface(address)).
func canonicalInterface(address string) string {
	p, err := netip.ParsePrefix(address)
	if err != nil {
		return address
	}
	return p.String()
}

// DeviceExists: this machine has network device `device` (the preflight
// of an apply).
func (s *System) DeviceExists(device string) (bool, error) {
	name, err := Ifname(device)
	if err != nil {
		return false, ifaddrErr(err)
	}
	return exists(filepath.Join(s.Paths.NetClass, name)), nil
}

func (s *System) removeAddress(device, address string) error {
	device, err := Ifname(device)
	if err != nil {
		return ifaddrErr(err)
	}
	if address, err = IPv4Interface(address); err != nil {
		return ifaddrErr(err)
	}
	have, err := s.addressesOf(device)
	if err != nil {
		return err
	}
	if !have[address] {
		return nil // gone already: a reboot, by hand, the device unplugged
	}
	return s.ip("addr", "del", address, "dev", device)
}

// addressesOf are the IPv4 addresses device has now; none if it isn't
// there.
func (s *System) addressesOf(device string) (map[string]bool, error) {
	res, err := s.Run(Cmd{Argv: []string{"ip", "-j", "addr", "show", "dev", device}})
	if errors.Is(err, ErrNotFound) {
		return nil, stepErr("'ip' binary not found; install the iproute2 package")
	}
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return map[string]bool{}, nil
	}
	links, err := parseIPJSON(res.Stdout)
	if err != nil {
		return nil, stepErr("could not read the addresses of %s: %s", device, err)
	}
	out := map[string]bool{}
	for _, l := range links {
		for _, a := range l.AddrInfo {
			if a.Family == "inet" {
				out[canonicalInterface(a.Local+"/"+strconv.Itoa(a.Prefixlen))] = true
			}
		}
	}
	return out, nil
}

func (s *System) ensureVlan(i config.Interface) error {
	device, err := Ifname(i.Device)
	if err != nil {
		return ifaddrErr(err)
	}
	parent, err := Ifname(i.VlanParent)
	if err != nil {
		return ifaddrErr(err)
	}
	res, err := s.Run(Cmd{Argv: []string{"ip", "link", "show", "dev", device}})
	if errors.Is(err, ErrNotFound) {
		return stepErr("'ip' binary not found; install the iproute2 package")
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if err := s.ip("link", "add", "link", parent, "name", device, "type", "vlan", "id", strconv.Itoa(i.VlanID)); err != nil {
			return err
		}
	}
	if err := s.ip("link", "set", "dev", parent, "up"); err != nil {
		return err
	}
	return s.ip("link", "set", "dev", device, "up")
}

// ip is frfw.ifaddr._run_ip: a failure is the program's own words.
func (s *System) ip(args ...string) error {
	res, err := s.Run(Cmd{Argv: append([]string{"ip"}, args...)})
	if errors.Is(err, ErrNotFound) {
		return stepErr("'ip' binary not found; install the iproute2 package")
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return &StepError{msg}
		}
		return stepErr("ip exited with status %d", res.Code)
	}
	return nil
}

// addressDevices are what syncAddresses may change: the devices it
// addresses or creates (VLANs), the VLANs' parents, which it brings up,
// and the devices the last applied config addressed.
func addressDevices(c, previous *config.Config) []string {
	var devices []string
	add := func(d string) {
		if !slices.Contains(devices, d) {
			devices = append(devices, d)
		}
	}
	if previous != nil {
		for _, i := range previous.Interfaces.Values() {
			if i.Address != "" {
				add(i.Device)
			}
		}
	}
	for _, i := range c.Interfaces.Values() {
		if i.VlanParent != "" {
			add(i.VlanParent)
		}
	}
	for _, i := range c.Interfaces.Values() {
		if i.Address != "" || i.VlanParent != "" {
			add(i.Device)
		}
	}
	return devices
}

// readFile is Path.read_text() with its error.
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	return string(data), err
}

// parseIPJSON is `ip -j addr show`'s list of devices.
func parseIPJSON(text string) ([]ipLink, error) {
	var links []ipLink
	if err := json.Unmarshal([]byte(text), &links); err != nil {
		return nil, err
	}
	return links, nil
}
