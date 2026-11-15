package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// Kernel fixes without a new image: a kernel staged on the persistence
// partition, tried once, and kept only when the router comes up on it
// (ROADMAP SEC-14, review v0.2.0 R3; 1.x's frfw.kernel_boot).
//
// A live-booted FR_OS boots the kernel on its boot medium. A kernel and
// an initrd built for it can be staged on the persistence partition's
// own root, next to the overlay's rw/ and never inside it:
//
//	fr_os-boot/staged/vmlinuz, initrd.img, SHA256SUMS (and expect.json)
//	fr_os-boot/grubenv          (a GRUB environment block)
//
// GRUB, which both firmwares run (installer/live-build/config/
// includes.binary/boot/grub/grub.cfg), reads fr_os_staged and
// fr_os_state from grubenv and runs the state machine:
//
//	trial    staged, never booted   -> GRUB writes "trying", boots it
//	good     confirmed              -> GRUB writes "booting", boots it
//	trying / booting still there    -> that boot never confirmed: GRUB
//	         writes "failed" and boots the image's own kernel
//	failed / nothing staged         -> the image's own kernel
//
// GRUB writes the new state before it boots the staged kernel, and only
// boots it if the write worked, so a kernel that panics (panic=10) or
// hangs (the hardware watchdog, systemd's RuntimeWatchdogSec) is tried
// once, not over and over. It checks the files against SHA256SUMS first.
//
// Late in every boot GRUB marked (fr_os.kernel= on the command line),
// ConfirmBoot runs (fr-kernel-confirm.service): on the staged kernel it
// checks the router is up (the ruleset loaded, the applied config's
// devices there, the webUI answering, persistence active) and that what
// worked when it was staged works again (ROADMAP SEC-23, review v0.2.1
// FR-NEW-003): then it writes "good". A trial that fails the check
// reboots once into the image's kernel; a confirmed kernel that fails it
// later stays up, says so, and the next boot falls back. Nothing here
// reboots the router otherwise: the admin reboots into a trial.
//
// The hashes protect against corruption, not root: whoever is root on
// the router can rewrite the stick anyway.

const (
	KernelBootDirName = "fr_os-boot"
	grubEnvName       = "grubenv"
	kernelSlot        = "staged"
	stagedKernel      = "vmlinuz"
	stagedInitrd      = "initrd.img"
	stagedSums        = "SHA256SUMS"
	// stagedExpect is what worked when the kernel was staged, to work
	// again on its boot (ROADMAP SEC-23).
	stagedExpect = "expect.json"

	envState  = "fr_os_state"
	envStaged = "fr_os_staged"

	KernelTrial, KernelTrying, KernelGood, KernelBooting, KernelFailed = "trial", "trying", "good", "booting", "failed"

	// What GRUB puts on the kernel command line (fr_os.kernel=): the
	// staged kernel on its first boot or a later one, the image's kernel
	// because the staged one failed, or the image's kernel as usual.
	BootTrial, BootStaged, BootFallback, BootImage = "trial", "staged", "fallback", "image"

	// GRUB's environment block: exactly this size, this header, '#'
	// padding (grub-core/lib/envblk.c).
	grubEnvSize   = 1024
	grubEnvHeader = "# GRUB Environment Block\n"

	// spareBytes is the room left on the persistence partition after
	// staging.
	spareBytes = 64 << 20

	// healthTimeout is how long a staged kernel's boot has to come up,
	// healthInterval how often it is checked, in seconds.
	healthTimeout  = 180.0
	healthInterval = 2.0
)

// kernelVersion is a Debian kernel release ("6.1.0-28-amd64"); it is
// shown in GRUB's menu and written to grubenv, so nothing else.
var kernelVersion = regexp.MustCompile(`\A[0-9][A-Za-z0-9.+~_-]{0,63}\z`)

var (
	envName  = regexp.MustCompile(`\A[A-Za-z_][A-Za-z0-9_]*\z`)
	envValue = regexp.MustCompile(`\A[A-Za-z0-9.+~_-]*\z`)
)

// expectedServices are the services a trial must find running again if
// they ran before it: what FR_OS starts, and the servers it configures.
var expectedServices = []string{
	"fr-webui.service", "fr-apply-helper.socket", "kea-dhcp4-server.service", "fr-adblock-dns.service",
	"fr-xdp-sni-logger.service", "fr-ai-ids.service", "fr-appid.service", "fr-tls-fp.service", "ssh.service",
}

// KernelBootError is a kernel that could not be staged or unstaged;
// nothing was changed unless the message says otherwise.
type KernelBootError struct{ msg string }

func (e *KernelBootError) Error() string { return e.msg }

func kernelErr(format string, a ...any) error { return &KernelBootError{fmt.Sprintf(format, a...)} }

// --- the environment block ------------------------------------------------------

// envVar is one variable of a block, in the block's order.
type envVar struct{ name, value string }

type grubEnv []envVar

func (e grubEnv) get(name string) string {
	for _, v := range e {
		if v.name == name {
			return v.value
		}
	}
	return ""
}

// with is {**e, name: value}: replaced where it is, else added last.
func (e grubEnv) with(name, value string) grubEnv {
	out := slices.Clone(e)
	for i := range out {
		if out[i].name == name {
			out[i].value = value
			return out
		}
	}
	return append(out, envVar{name, value})
}

func formatEnv(values grubEnv) ([]byte, error) {
	body := grubEnvHeader
	for _, v := range values {
		if !envName.MatchString(v.name) || !envValue.MatchString(v.value) {
			return nil, kernelErr("not a value for the boot environment: %s=%s", v.name, config.Repr(v.value))
		}
		body += v.name + "=" + v.value + "\n"
	}
	if len(body) > grubEnvSize {
		return nil, kernelErr("the boot environment is full")
	}
	return []byte(body + strings.Repeat("#", grubEnvSize-len(body))), nil
}

// parseEnv is the variables of a block; none for anything else.
func parseEnv(data []byte) grubEnv {
	if len(data) != grubEnvSize || !strings.HasPrefix(string(data), grubEnvHeader) {
		return nil
	}
	var values grubEnv
	text := strings.ToValidUTF8(string(data[len(grubEnvHeader):]), "�")
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		name, value, _ := strings.Cut(line, "=")
		values = values.with(name, value)
	}
	return values
}

func readEnv(path string) grubEnv {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseEnv(data)
}

func fsyncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func copySynced(source, target string) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// writeEnv replaces the block in one step (a new file, synced, renamed
// over the old one, the directory synced): a power cut leaves the old
// block or the new one. GRUB finds the file's blocks again at every boot.
func writeEnv(path string, values grubEnv) error {
	data, err := formatEnv(values)
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".new")
	if err := writeSynced(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

// --- where it lives -----------------------------------------------------------------

// pyPath is str(Path(p)): repeated and trailing slashes and "."
// components dropped, ".." kept.
func pyPath(p string) string {
	if p == "" {
		return "."
	}
	var parts []string
	for _, part := range strings.Split(p, "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	out := strings.Join(parts, "/")
	switch {
	case strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///"):
		return "//" + out
	case strings.HasPrefix(p, "/"):
		return "/" + out
	case out == "":
		return "."
	}
	return out
}

// PersistenceRoot is where live-boot mounted the persistence filesystem
// it uses (the one holding rw/), ok false: not live, or no persistence.
func (s *System) PersistenceRoot() (string, bool) {
	text, ok := readText(s.Paths.Mounts)
	if !ok {
		return "", false
	}
	for _, line := range config.PySplitlines(text) {
		parts := config.PySplit(line)
		if len(parts) >= 2 && strings.HasPrefix(parts[1], livePersistencePrefix) {
			return filepath.Join(s.Paths.LiveRoot, pyPath(strings.ReplaceAll(parts[1], `\040`, " "))), true
		}
	}
	return "", false
}

// KernelBootDir is where a kernel is staged, ok false without
// persistence.
func (s *System) KernelBootDir() (string, bool) {
	root, ok := s.PersistenceRoot()
	if !ok {
		return "", false
	}
	return filepath.Join(root, KernelBootDirName), true
}

// BootMode is fr_os.kernel= of this boot, "" when FR_OS's GRUB did not
// start it.
func (s *System) BootMode() string {
	text, ok := readText(s.Paths.Cmdline)
	if !ok {
		return ""
	}
	for _, arg := range config.PySplit(text) {
		if value, ok := strings.CutPrefix(arg, "fr_os.kernel="); ok {
			return value
		}
	}
	return ""
}

// --- staging --------------------------------------------------------------------

func checkKernelVersion(version string) error {
	if !kernelVersion.MatchString(version) {
		return kernelErr("not a kernel version: %s", config.Repr(version))
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isLinuxKernel: an x86 Linux boot image, the setup header's "HdrS" at
// 0x202.
func isLinuxKernel(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	n, _ := f.ReadAt(magic, 0x202)
	return n == 4 && string(magic) == "HdrS"
}

// StageKernel makes kernel and initrd the staged kernel, tried at the
// next boot. A crash at any point leaves the previous state or nothing
// staged, never a half-copied kernel marked for a trial. expect is what
// works now (Expectations), checked again on its boot; nil: what the
// applied config turns on is.
func (s *System) StageKernel(kernel, initrd, version, bootDir string, expect *KernelExpect) error {
	if err := checkKernelVersion(version); err != nil {
		return err
	}
	if !isLinuxKernel(kernel) {
		return kernelErr("%s is not a Linux kernel image", pyPath(kernel))
	}
	ist, err := os.Stat(initrd)
	if err != nil || !ist.Mode().IsRegular() || ist.Size() == 0 {
		return kernelErr("%s is not an initrd", pyPath(initrd))
	}
	parent := filepath.Dir(bootDir)
	if !isDir(parent) {
		return kernelErr("%s is not there: no persistence partition in use", parent)
	}
	kst, err := os.Stat(kernel)
	if err != nil {
		return pyOSError(err)
	}
	needed := uint64(kst.Size()) + uint64(ist.Size()) + spareBytes
	free, err := s.DiskFree(parent)
	if err != nil {
		return pyOSError(err)
	}
	if free < needed {
		return kernelErr("only %d MiB free on the persistence partition, %d MiB needed", free>>20, needed>>20)
	}
	if err := os.Mkdir(bootDir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return pyOSError(err)
	}
	envPath := filepath.Join(bootDir, grubEnvName)
	slot := filepath.Join(bootDir, kernelSlot)
	// Nothing staged while the slot changes.
	if err := writeEnv(envPath, nil); err != nil {
		return wrapOS(err)
	}
	staging := filepath.Join(bootDir, kernelSlot+".new")
	os.RemoveAll(staging)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return pyOSError(err)
	}
	var sums strings.Builder
	for _, f := range [][2]string{{kernel, stagedKernel}, {initrd, stagedInitrd}} {
		target := filepath.Join(staging, f[1])
		if err := copySynced(f[0], target); err != nil {
			return pyOSError(err)
		}
		digest, err := sha256File(target)
		if err != nil {
			return pyOSError(err)
		}
		sums.WriteString(digest + "  " + f[1] + "\n")
	}
	if err := writeSynced(filepath.Join(staging, stagedSums), []byte(sums.String())); err != nil {
		return pyOSError(err)
	}
	if expect != nil {
		text, err := expect.json()
		if err != nil {
			return err
		}
		if err := writeSynced(filepath.Join(staging, stagedExpect), []byte(text)); err != nil {
			return pyOSError(err)
		}
	}
	if err := fsyncDir(staging); err != nil {
		return pyOSError(err)
	}
	os.RemoveAll(slot)
	if err := os.Rename(staging, slot); err != nil {
		return pyOSError(err)
	}
	if err := fsyncDir(bootDir); err != nil {
		return pyOSError(err)
	}
	return wrapOS(writeEnv(envPath, grubEnv{{envState, KernelTrial}, {envStaged, version}}))
}

// wrapOS is err as 1.x shows it: a KernelBootError as it is, an OSError
// as Python words it.
func wrapOS(err error) error {
	var ke *KernelBootError
	if err == nil || errors.As(err, &ke) {
		return err
	}
	return pyOSError(err)
}

// UnstageKernel goes back to the image's kernel at the next boot; false:
// nothing was staged.
func UnstageKernel(bootDir string) (bool, error) {
	envPath := filepath.Join(bootDir, grubEnvName)
	slot := filepath.Join(bootDir, kernelSlot)
	if !exists(envPath) && !exists(slot) {
		return false, nil
	}
	if err := writeEnv(envPath, nil); err != nil {
		return false, wrapOS(err)
	}
	os.RemoveAll(slot)
	return true, nil
}

// StagedFiles are the staged files' SHA256 digests as they are now, by
// name.
func StagedFiles(bootDir string) map[string]string {
	out := map[string]string{}
	for _, name := range []string{stagedKernel, stagedInitrd} {
		path := filepath.Join(bootDir, kernelSlot, name)
		if !isFile(path) {
			continue
		}
		if digest, err := sha256File(path); err == nil {
			out[name] = digest
		}
	}
	return out
}

// pySplitOnce is str.split(None, 1).
func pySplitOnce(s string) []string {
	fields := config.PySplit(s)
	if len(fields) <= 1 {
		return fields
	}
	// The rest after the first field and the whitespace after it, as is.
	rest := s
	rest = strings.TrimLeftFunc(rest, func(r rune) bool { return config.PyStrip(string(r)) == "" })
	rest = rest[len(fields[0]):]
	rest = strings.TrimLeftFunc(rest, func(r rune) bool { return config.PyStrip(string(r)) == "" })
	return []string{fields[0], rest}
}

// FilesIntact is whether the staged files match their SHA256SUMS: GRUB's
// check.
func FilesIntact(bootDir string) bool {
	data, err := os.ReadFile(filepath.Join(bootDir, kernelSlot, stagedSums))
	if err != nil || !utf8.Valid(data) {
		return false
	}
	listed := map[string]string{}
	for _, line := range config.PySplitlines(string(data)) {
		if config.PyStrip(line) == "" {
			continue
		}
		parts := pySplitOnce(line)
		if len(parts) != 2 {
			return false // dict() of a one-field line: ValueError
		}
		listed[config.PyStrip(parts[1])] = parts[0]
	}
	if len(listed) != 2 || listed[stagedKernel] == "" || listed[stagedInitrd] == "" {
		return false
	}
	now := StagedFiles(bootDir)
	return len(now) == 2 && now[stagedKernel] == listed[stagedKernel] && now[stagedInitrd] == listed[stagedInitrd]
}

// --- status -----------------------------------------------------------------------

// KernelStatus is what firewall-cli kernel status and the Update screen
// show.
type KernelStatus struct {
	// Available: a live system with persistence, where a kernel can be
	// staged.
	Available     bool
	State, Staged string
	Boot          string // this boot's fr_os.kernel=
	Running       string
	// Intact is whether the staged files match their hashes; nil when
	// not checked.
	Intact *bool
}

func (k KernelStatus) Summary() string {
	if !k.Available {
		return "no persistence partition in use: a kernel can't be staged"
	}
	running := "running kernel " + k.Running
	switch k.Boot {
	case BootFallback:
		running += " -- the image's own: the staged kernel failed, see the security alerts"
	case BootTrial, BootStaged:
		running += " -- the staged one"
	}
	if k.State == "" {
		return running + "; nothing staged"
	}
	what, ok := map[string]string{
		KernelTrial:   "staged, tried at the next reboot",
		KernelTrying:  "on its trial boot",
		KernelGood:    "confirmed: boots by default, every boot checked",
		KernelBooting: "booted, not confirmed yet",
		KernelFailed:  "failed: the image's own kernel boots",
	}[k.State]
	if !ok {
		what = "in an unknown state (" + k.State + ")"
	}
	broken := ""
	if k.Intact != nil && !*k.Intact {
		broken = " -- ITS FILES DON'T MATCH THEIR HASHES"
	}
	staged := k.Staged
	if staged == "" {
		staged = "?"
	}
	return running + "; kernel " + staged + " " + what + broken
}

// KernelStatus is the staged kernel's state now.
func (s *System) KernelStatus(checkFiles bool) KernelStatus {
	st := KernelStatus{Boot: s.BootMode(), Running: s.KernelRelease()}
	dir, ok := s.KernelBootDir()
	if !ok {
		return st
	}
	st.Available = true
	env := readEnv(filepath.Join(dir, grubEnvName))
	st.State, st.Staged = env.get(envState), env.get(envStaged)
	if st.State != "" && checkFiles {
		intact := FilesIntact(dir)
		st.Intact = &intact
	}
	return st
}

// --- what worked before the trial (ROADMAP SEC-23) ---------------------------------

// KernelExpect is what works now and must work again on a staged
// kernel's boot: the config's ports with a link, its addresses that are
// there (by device), the XDP filter's attachments, the WireGuard tunnel,
// the services that ran.
type KernelExpect struct {
	Carrier   []string
	Addresses [][2]string // device, address; sorted by device
	XDP       []string
	Wireguard bool
	Services  []string
}

// json is json.dumps(expect, sort_keys=True), as 1.x writes expect.json.
func (e *KernelExpect) json() (string, error) {
	list := func(items []string) []config.Value {
		out := make([]config.Value, 0, len(items))
		for _, s := range items {
			out = append(out, s)
		}
		return out
	}
	addresses := config.NewMap()
	for _, a := range e.Addresses {
		addresses.Set(a[0], a[1])
	}
	m := config.NewMap()
	m.Set("addresses", addresses)
	m.Set("carrier", list(e.Carrier))
	m.Set("services", list(e.Services))
	m.Set("wireguard", e.Wireguard)
	m.Set("xdp", list(e.XDP))
	return config.PyJSON(m, -1, true)
}

// readKernelExpect is the staged kernel's record, nil without one.
func readKernelExpect(bootDir string) *KernelExpect {
	data, err := os.ReadFile(filepath.Join(bootDir, kernelSlot, stagedExpect))
	if err != nil {
		return nil
	}
	v, err := config.ParseJSON(data)
	if err != nil {
		return nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil
	}
	strs := func(key string) []string {
		raw, _ := m.Get(key)
		items, _ := raw.([]config.Value)
		var out []string
		for _, item := range items {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	e := &KernelExpect{Carrier: strs("carrier"), XDP: strs("xdp"), Services: strs("services")}
	if raw, ok := m.Get("addresses"); ok {
		if am, ok := raw.(*config.Map); ok {
			for _, k := range am.Keys() {
				key, _ := k.(string)
				value, _ := am.Get(key)
				if s, ok := value.(string); ok {
					e.Addresses = append(e.Addresses, [2]string{key, s})
				}
			}
		}
	}
	slices.SortStableFunc(e.Addresses, func(a, b [2]string) int { return strings.Compare(a[0], b[0]) })
	if raw, ok := m.Get("wireguard"); ok {
		e.Wireguard = config.Truthy(raw)
	}
	return e
}

// netDevice is one network device as `ip -j` reports it.
type netDevice struct {
	up, carrier, xdp bool
	addresses        []string // IPv4, "a.b.c.d/n", sorted
}

// networkNow is every network device: up, with a link (carrier), with an
// XDP program, and its IPv4 addresses, from `ip -j` (netlink only).
func (s *System) networkNow() map[string]*netDevice {
	ipJSON := func(args ...string) []config.Value {
		res, err := s.Run(Cmd{Argv: append([]string{"ip", "-j"}, args...)})
		if err != nil || res.Code != 0 {
			return nil
		}
		v, err := config.ParseJSON([]byte(res.Stdout))
		if err != nil {
			return nil
		}
		list, _ := v.([]config.Value)
		return list
	}
	field := func(m *config.Map, key string) config.Value { v, _ := m.Get(key); return v }
	devices := map[string]*netDevice{}
	for _, item := range ipJSON("link", "show") {
		link, ok := item.(*config.Map)
		if !ok {
			continue
		}
		name, ok := field(link, "ifname").(string)
		if !ok {
			continue
		}
		flags, _ := field(link, "flags").([]config.Value)
		_, hasXDP := link.Get("xdp")
		devices[name] = &netDevice{up: slices.Contains(flags, config.Value("UP")),
			carrier: slices.Contains(flags, config.Value("LOWER_UP")), xdp: hasXDP}
	}
	for _, item := range ipJSON("addr", "show") {
		link, ok := item.(*config.Map)
		if !ok {
			continue
		}
		name, ok := field(link, "ifname").(string)
		if !ok {
			continue
		}
		d := devices[name]
		if d == nil {
			d = &netDevice{}
			devices[name] = d
		}
		infos, _ := field(link, "addr_info").([]config.Value)
		d.addresses = nil
		for _, info := range infos {
			a, ok := info.(*config.Map)
			if !ok || field(a, "family") != "inet" {
				continue
			}
			d.addresses = append(d.addresses, config.Str(field(a, "local"))+"/"+config.Str(field(a, "prefixlen")))
		}
		slices.Sort(d.addresses)
	}
	return devices
}

// unitActive is `systemctl is-active --quiet` of unit.
func (s *System) unitActive(unit string) bool {
	res, err := s.Run(Cmd{Argv: []string{"systemctl", "is-active", "--quiet", "--", unit}, Timeout: 30 * time.Second})
	return err == nil && res.Code == 0
}

// configDevices are the devices the config uses, its addresses (by
// device, in the config's order) and the devices the XDP filter
// attaches to (a VLAN's parent carries it).
func configDevices(c *config.Config) (map[string]bool, [][2]string, []string) {
	devices := map[string]bool{}
	var addresses [][2]string
	vlans := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		if i.VlanParent != "" {
			vlans[i.Device] = true
		}
	}
	for _, i := range c.Interfaces.Values() {
		if i.VlanParent != "" {
			devices[i.VlanParent] = true
		} else {
			devices[i.Device] = true
		}
		if i.Address != "" {
			address := i.Address
			if p, err := netip.ParsePrefix(i.Address); err == nil {
				address = p.String()
			}
			addresses = setPair(addresses, i.Device, address)
		}
	}
	var xdp []string
	if c.XdpSniFilter.Enabled {
		set := map[string]bool{}
		for _, name := range c.XdpSniFilter.Interfaces {
			if i, ok := c.Interfaces.Get(name); ok && !vlans[i.Device] {
				set[i.Device] = true
			}
		}
		xdp = sortedKeys(set)
	}
	return devices, addresses, xdp
}

// setPair is pairs[key] = value: replaced where it is, else added.
func setPair(pairs [][2]string, key, value string) [][2]string {
	for i := range pairs {
		if pairs[i][0] == key {
			pairs[i][1] = value
			return pairs
		}
	}
	return append(pairs, [2]string{key, value})
}

func sortPairs(pairs [][2]string) [][2]string {
	out := slices.Clone(pairs)
	slices.SortStableFunc(out, func(a, b [2]string) int { return strings.Compare(a[0], b[0]) })
	return out
}

// configExpectations: without a record of the moment it was staged,
// what the applied config turns on: no links (a port may have no cable)
// and no services.
func configExpectations(c *config.Config) *KernelExpect {
	_, addresses, xdp := configDevices(c)
	return &KernelExpect{Addresses: sortPairs(addresses), XDP: xdp, Wireguard: c.Wireguard.Enabled}
}

// Expectations are what works now and must work again on a staged
// kernel's boot (ROADMAP SEC-23).
func (s *System) Expectations(c *config.Config) *KernelExpect {
	now := s.networkNow()
	devices, addresses, xdp := configDevices(c)
	e := &KernelExpect{}
	for _, d := range sortedKeys(devices) {
		if n := now[d]; n != nil && n.carrier {
			e.Carrier = append(e.Carrier, d)
		}
	}
	var present [][2]string
	for _, a := range addresses {
		if n := now[a[0]]; n != nil && slices.Contains(n.addresses, a[1]) {
			present = append(present, a)
		}
	}
	e.Addresses = sortPairs(present)
	for _, d := range xdp {
		if n := now[d]; n != nil && n.xdp {
			e.XDP = append(e.XDP, d)
		}
	}
	if c.Wireguard.Enabled {
		if n := now[WireguardIface]; n != nil && n.up {
			e.Wireguard = true
		}
	}
	for _, u := range expectedServices {
		if s.unitActive(u) {
			e.Services = append(e.Services, u)
		}
	}
	return e
}

// CurrentExpectations is what works on this router now, for a stage;
// nil without a config applied in full to read it against.
func (s *System) CurrentExpectations() *KernelExpect {
	applied := s.LoadAppliedConfig()
	if applied == nil {
		return nil
	}
	return s.Expectations(applied)
}

// expectationProblems is what of e doesn't work now.
func (s *System) expectationProblems(e *KernelExpect) []string {
	now := s.networkNow()
	dev := func(name string) *netDevice {
		if n := now[name]; n != nil {
			return n
		}
		return &netDevice{}
	}
	var problems []string
	for _, d := range e.Carrier {
		if !dev(d).carrier {
			problems = append(problems, d+" had a link before the trial and has none now")
		}
	}
	for _, a := range e.Addresses {
		n := dev(a[0])
		if !slices.Contains(n.addresses, a[1]) || !n.up {
			problems = append(problems, a[0]+" is not up with its address "+a[1])
		}
	}
	for _, d := range e.XDP {
		if !dev(d).xdp {
			problems = append(problems, "the XDP SNI filter is not attached to "+d)
		}
	}
	if e.Wireguard && !dev(WireguardIface).up {
		problems = append(problems, "the WireGuard tunnel "+WireguardIface+" is not up")
	}
	for _, u := range e.Services {
		if !s.unitActive(u) {
			problems = append(problems, u+" ran before the trial and is not running")
		}
	}
	return problems
}

// summary is what a confirmed boot was checked for, for the journal.
func (e *KernelExpect) summary() string {
	var parts []string
	if len(e.Carrier) > 0 {
		parts = append(parts, "links "+strings.Join(e.Carrier, ", "))
	}
	if len(e.Addresses) > 0 {
		var a []string
		for _, p := range e.Addresses {
			a = append(a, p[0]+" "+p[1])
		}
		parts = append(parts, "addresses "+strings.Join(a, ", "))
	}
	if len(e.XDP) > 0 {
		parts = append(parts, "XDP on "+strings.Join(e.XDP, ", "))
	}
	if e.Wireguard {
		parts = append(parts, WireguardIface)
	}
	if len(e.Services) > 0 {
		parts = append(parts, "services "+strings.Join(e.Services, ", "))
	}
	if len(parts) == 0 {
		return "nothing recorded"
	}
	return strings.Join(parts, "; ")
}

// --- the boot-time check ---------------------------------------------------------

func (s *System) firewallLoaded() bool {
	res, err := s.Run(Cmd{Argv: []string{"nft", "list", "table", "inet", nft.Table}})
	return err == nil && res.Code == 0
}

// HealthProblems is what is wrong with this boot now, none when the
// router is up. expect is what worked before the trial: nil reads the
// staged kernel's record, and without one, what the applied config
// turns on.
func (s *System) HealthProblems(expect *KernelExpect) []string {
	if expect == nil {
		if dir, ok := s.KernelBootDir(); ok {
			expect = readKernelExpect(dir)
		}
	}
	var problems []string
	if !s.firewallLoaded() {
		problems = append(problems, "the firewall's ruleset is not loaded")
	}
	if applied := s.LoadAppliedConfig(); applied != nil {
		if missing, err := s.MissingDevices(applied); err == nil && len(missing) > 0 {
			problems = append(problems, "network devices of the applied config are missing: "+strings.Join(missing, ", "))
		}
		if expect == nil {
			expect = configExpectations(applied)
		}
	}
	if expect != nil {
		problems = append(problems, s.expectationProblems(expect)...)
	}
	// On loopback, which the webUI always listens on.
	if s.Dial("127.0.0.1", webUIPort, 3*time.Second) != nil {
		problems = append(problems, "the webUI does not answer")
	}
	if !s.Persistence().Active {
		problems = append(problems, "persistence is not active")
	}
	return problems
}

// waitHealthy is none as soon as the check passes, else its problems at
// the deadline.
func (s *System) waitHealthy() []string {
	deadline := s.HealthClock() + healthTimeout
	for {
		problems := s.HealthProblems(nil)
		if len(problems) == 0 || s.HealthClock() >= deadline {
			return problems
		}
		s.HealthSleep(healthInterval)
	}
}

// BootOutcome is what the boot-time check found.
type BootOutcome struct {
	Message string
	Alert   string // a security alert to raise, "" for none
	Reboot  bool   // into the image's kernel: a failed trial
}

// ConfirmBoot is the step at the end of every boot GRUB started. A state
// it doesn't expect is said and left as it is.
func (s *System) ConfirmBoot(bootDir string) (BootOutcome, error) {
	expect := readKernelExpect(bootDir)
	mode := s.BootMode()
	envPath := filepath.Join(bootDir, grubEnvName)
	env := readEnv(envPath)
	state := env.get(envState)
	version := env.get(envStaged)
	if version == "" {
		version = "?"
	}
	stateRepr := "None"
	if _, ok := envLookup(env, envState); ok {
		stateRepr = config.Repr(state)
	}
	switch {
	case mode == BootTrial || mode == BootStaged:
		expected := KernelTrying
		if mode == BootStaged {
			expected = KernelBooting
		}
		if state != expected || stateRepr == "None" {
			return BootOutcome{Message: fmt.Sprintf("booted the staged kernel %s, but its state is %s, not %s: left as it is",
				version, stateRepr, config.Repr(expected))}, nil
		}
		problems := s.waitHealthy()
		if len(problems) == 0 {
			if err := writeEnv(envPath, env.with(envState, KernelGood)); err != nil {
				return BootOutcome{}, wrapOS(err)
			}
			checked := "; checked against the applied config (no record of the moment it was staged)"
			if expect != nil {
				checked = "; what worked before it works: " + expect.summary()
			}
			trial := ""
			if mode == BootTrial {
				trial = " (its trial boot)"
			}
			return BootOutcome{Message: "kernel " + version + " confirmed: the router came up on it" + trial + checked}, nil
		}
		why := strings.Join(problems, "; ")
		if mode == BootTrial {
			return BootOutcome{
				Message: "kernel " + version + " failed its trial boot (" + why + "): rebooting into the image's own kernel",
				Alert:   "kernel " + version + " failed its trial boot (" + why + "); the router reboots into the image's own kernel",
				Reboot:  true}, nil
		}
		return BootOutcome{
			Message: "kernel " + version + " booted but the router is not up (" + why + "): the next boot uses the image's own kernel",
			Alert:   "the router came up badly on kernel " + version + " (" + why + "); the next boot uses the image's own kernel"}, nil
	case mode == BootFallback:
		return BootOutcome{
			Message: "kernel " + version + " did not come up; the image's own kernel booted instead",
			Alert: "kernel " + version + " did not come up (a panic, a hang or a failed check, or its files were damaged); " +
				"the router booted the image's own kernel instead"}, nil
	case mode == BootImage && (state == KernelTrying || state == KernelBooting):
		// GRUB chose the staged kernel, but the image's was picked from
		// the menu: the staged one wasn't tried, so it isn't a failure.
		restored := KernelTrial
		if state == KernelBooting {
			restored = KernelGood
		}
		if err := writeEnv(envPath, env.with(envState, restored)); err != nil {
			return BootOutcome{}, wrapOS(err)
		}
		return BootOutcome{Message: "the image's kernel was chosen from the boot menu; kernel " + version +
			" stays " + config.Repr(restored)}, nil
	}
	message := "the image's own kernel"
	if state != "" {
		message += "; kernel " + version + " is " + config.Repr(state)
	}
	return BootOutcome{Message: message}, nil
}

func envLookup(e grubEnv, name string) (string, bool) {
	for _, v := range e {
		if v.name == name {
			return v.value, true
		}
	}
	return "", false
}

// --- the machine --------------------------------------------------------------------

func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	var b strings.Builder
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	return b.String()
}

// diskFree is shutil.disk_usage(path).free: the blocks an unprivileged
// user may use.
func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Frsize), nil
}

func dialTCP(host string, port int, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func monotonic() func() float64 {
	start := time.Now()
	return func() float64 { return time.Since(start).Seconds() }
}
