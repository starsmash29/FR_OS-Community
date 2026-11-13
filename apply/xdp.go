package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// --- the XDP SNI filter (frfw.xdp) ------------------------------------------------
//
// The kernel program is crates/fros-xdp-ebpf (Rust, aya), shipped at
// Paths.XdpObject. It is loaded once and pinned with its maps under
// Paths.XdpPins, so every device it runs on shares one blocklist and
// one set of counters, and the readers (the event logger, the
// fingerprinting daemon) find its ring buffers. The pins are made and
// kept by fr-xdp (XdpTool, crates/fros-xdp), where 1.x ran bpftool:
// bpftool's libbpf no longer reads aya's map section. Everything else
// is 1.x's sync_sni_filter step for step: attaching with `ip link`
// (native first, then generic), GRO off in generic mode, the state
// file, replacing a program that didn't come from the shipped object.

const (
	// MaxSNILen is the kernel filter's bound: a name this long or longer
	// never matches there.
	MaxSNILen = 32
	// LPMKeySize is struct lpm_sni_key: prefixlen (4) and the reversed
	// name (MaxSNILen + 1), padded to 8-byte alignment.
	LPMKeySize = 40
	// BlocklistMaxEntries is the blocklist map's max_entries.
	BlocklistMaxEntries = 4096
	// XdpTool runs the pins (crates/fros-xdp's fr-xdp).
	XdpTool = "/usr/libexec/fr_os/fr-xdp"

	settingReportPass  = 0x1
	settingReportHello = 0x2
	xdpProgName        = "xdp_sni_filter"
	xdpNative          = "xdpdrv"
	xdpGeneric         = "xdpgeneric"
)

// xdpReaders read the pinned ring buffers. They open the maps once, as
// root, then drop their privileges for good, so a reader can't reopen a
// map that was replaced under it: each is restarted after new maps are
// pinned (ROADMAP SEC-19).
var xdpReaders = []string{"fr-xdp-sni-logger.service", TLSFPService}

// errXdpToolMissing: fr-xdp is part of FR_OS itself, where 1.x's
// bpftool was a package of its own (decisions.md, phase 4d-2).
var errXdpToolMissing = &StepError{"'" + XdpTool + "' not found; this FR_OS installation is incomplete"}

func (p Paths) xdpProgPin() string     { return filepath.Join(p.XdpPins, "prog", xdpProgName) }
func (p Paths) xdpMap(n string) string { return filepath.Join(p.XdpPins, "maps", n) }

// xdpStaging is where a new program is loaded before it replaces the
// pinned one (no dot in the name: bpffs refuses one).
func (p Paths) xdpStaging() string { return p.XdpPins + "_next" }

// NormalizeSNI is the blocklist form of a name, byte for byte what the
// kernel program makes of the same wire bytes: A-Z folded to lower case
// (and nothing else, never a blind | 0x20), trailing dots removed.
func NormalizeSNI(name string) string {
	b := []byte(name)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c | 0x20
		}
	}
	return strings.TrimRight(string(b), ".")
}

// LPMKey is the blocklist map's key for hostname: reverse("." +
// normalized name), its length in bits as the prefix, so a name blocks
// itself and its subdomains and nothing that merely ends the same. The
// length is checked on the raw name, before normalizing, as the kernel
// program refuses a wire name of MaxSNILen or more before it looks at
// case or dots.
func LPMKey(hostname string) ([]byte, error) {
	n := len([]rune(hostname))
	if n <= 0 || n >= MaxSNILen {
		return nil, stepErr("hostname length must be in (0, %d): %s is %d bytes, so it is NOT blocked by "+
			"the kernel filter", MaxSNILen, config.Repr(hostname), n)
	}
	normalized := NormalizeSNI(hostname)
	if normalized == "" {
		return nil, stepErr("hostname is only dots after normalization: %s", config.Repr(hostname))
	}
	for _, r := range hostname {
		if r >= 0x80 {
			return nil, stepErr("hostname is not ASCII: %s", config.Repr(hostname))
		}
	}
	content := []byte("." + normalized)
	slices.Reverse(content)
	key := make([]byte, LPMKeySize)
	prefix := uint32(len(normalized)+1) * 8
	key[0], key[1], key[2], key[3] = byte(prefix), byte(prefix>>8), byte(prefix>>16), byte(prefix>>24)
	copy(key[4:], content)
	return key, nil
}

// xdpBlocklist is the blocklist the kernel gets (frfw.provision.
// xdp_config_for): the config's, and, merged in memory only, up to
// adblocker.xdp_critical_limit names of the ad-block list and the
// blocked apps' names when app_control.block_via_xdp. The merged names
// too long for the kernel filter are left out and returned, for the
// apply to name (ROADMAP SEC-17).
func (s *System) xdpBlocklist(c *config.Config) (blocklist, tooLong []string, err error) {
	extra := map[string]bool{}
	if c.Adblocker.Enabled && c.Adblocker.XdpCriticalLimit > 0 {
		names, err := criticalDomains(s.Paths.AdblockHosts, c.Adblocker.XdpCriticalLimit)
		if err != nil {
			return nil, nil, err
		}
		for _, n := range names {
			extra[n] = true
		}
	}
	if c.AppControl.BlockViaXdp {
		for _, n := range render.BlockedAppNames(c, s.Catalog) {
			extra[n] = true
		}
	}
	for n := range extra {
		if len([]rune(n)) >= MaxSNILen {
			tooLong = append(tooLong, n)
			delete(extra, n)
		}
	}
	slices.Sort(tooLong)
	if len(extra) == 0 {
		return c.XdpSniFilter.Blocklist, tooLong, nil
	}
	for _, n := range c.XdpSniFilter.Blocklist {
		extra[n] = true
	}
	return sortedKeys(extra), tooLong, nil
}

// checkXDP is the preflight: a blocklist the map can't hold, or a name
// it can't key, is refused before anything changes.
func (s *System) checkXDP(c *config.Config) error {
	names, _, err := s.xdpBlocklist(c)
	if err != nil {
		return err
	}
	if len(names) > BlocklistMaxEntries {
		return stepErr("XDP blocklist has %d names, more than the kernel map's %d", len(names), BlocklistMaxEntries)
	}
	for _, n := range names {
		if _, err := LPMKey(n); err != nil {
			return err
		}
	}
	return nil
}

// --- the state file ----------------------------------------------------------------

// xdpState is /etc/fr_os/xdp_state.json: which devices FR_OS attached
// the filter to and in which mode, the digest of the object the pinned
// program came from (nil: unknown), and the devices whose GRO FR_OS
// turned off for generic mode.
type xdpState struct {
	attached *config.Map
	program  *string
	groOff   []string
}

func (s *System) loadXdpState() xdpState {
	st := xdpState{attached: config.NewMap()}
	if !isFile(s.Paths.XdpState) {
		return st
	}
	text, ok := readText(s.Paths.XdpState)
	if !ok {
		return st
	}
	v, err := config.ParseJSONLastWins([]byte(text))
	m, isMap := v.(*config.Map)
	if err != nil || !isMap {
		return st
	}
	if a, ok := m.Get("attached"); ok {
		if am, ok := a.(*config.Map); ok {
			st.attached = am
		}
	}
	if p, ok := m.Get("program"); ok {
		if text, ok := p.(string); ok {
			st.program = &text
		}
	}
	if g, ok := m.Get("gro_off"); ok {
		if list, ok := g.([]config.Value); ok {
			for _, d := range list {
				if name, ok := d.(string); ok {
					st.groOff = append(st.groOff, name)
				}
			}
		}
	}
	return st
}

func (s *System) saveXdpState(st xdpState) error {
	m := config.NewMap()
	m.Set("attached", st.attached)
	if st.program != nil {
		m.Set("program", *st.program)
	} else {
		m.Set("program", nil)
	}
	gro := make([]config.Value, len(st.groOff))
	for i, d := range st.groOff {
		gro[i] = d
	}
	m.Set("gro_off", gro)
	text, err := config.PyJSON(m, -1, false)
	if err != nil {
		return err
	}
	path := s.Paths.XdpState
	return pyOSError(replaceFile(path, filepath.Base(path)+".tmp", text, 0))
}

func attachedNames(m *config.Map) []string {
	var out []string
	for _, k := range m.Keys() {
		if name, ok := k.(string); ok {
			out = append(out, name)
		}
	}
	return out
}

// --- the programs it runs ------------------------------------------------------------

// xdpIP is frfw.xdp._run_ip: the result as it is.
func (s *System) xdpIP(args ...string) (Result, error) {
	res, err := s.Run(Cmd{Argv: append([]string{"ip"}, args...)})
	if errors.Is(err, ErrNotFound) {
		return res, &StepError{"'ip' binary not found; install the iproute2 package"}
	}
	return res, err
}

func (s *System) xdpTool(stdin string, args ...string) (Result, error) {
	res, err := s.Run(Cmd{Argv: append([]string{XdpTool}, args...), Stdin: stdin})
	if errors.Is(err, ErrNotFound) {
		return res, errXdpToolMissing
	}
	return res, err
}

func xdpDevice(device string) (string, error) {
	d, err := Ifname(device)
	if err != nil {
		return "", &StepError{err.Error()}
	}
	return d, nil
}

// --- loading and pinning ----------------------------------------------------------

func (s *System) xdpLoaded() bool { return exists(s.Paths.xdpProgPin()) }

// ensureXdpObject is the object to load: the image ships it, and each
// release installs its own (ROADMAP P4-1). A router never compiles it.
func (s *System) ensureXdpObject() (string, error) {
	obj := s.Paths.XdpObject
	if !isFile(obj) {
		return "", stepErr("No compiled XDP program at %s: this installation did not ship one, so the SNI "+
			"filter can't be turned on (ROADMAP P4-1).", obj)
	}
	return obj, nil
}

// objectDigest is the object's sha256, to tell whether the pinned
// program came from it; nil if it can't be read.
func objectDigest(path string) *string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(data)
	text := hex.EncodeToString(sum[:])
	return &text
}

func (s *System) xdpLoadInto(obj, pinDir string) error {
	for _, d := range []string{"prog", "maps"} {
		if err := os.MkdirAll(filepath.Join(pinDir, d), 0o777); err != nil {
			return pyOSError(err)
		}
	}
	res, err := s.xdpTool("", "load", "--", obj, filepath.Join(pinDir, "prog"), filepath.Join(pinDir, "maps"))
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return stepErr("Loading %s failed:\n%s", obj, res.Stderr)
	}
	return nil
}

// xdpLoadAndPin loads the object once; pinned already, it does nothing
// (and never empties a blocklist in use). Whether the pinned program is
// the right one is the sync's question.
func (s *System) xdpLoadAndPin(obj string) (bool, error) {
	if s.xdpLoaded() {
		return false, nil
	}
	return true, s.xdpLoadInto(obj, s.Paths.XdpPins)
}

// removePinTree unpins everything under dir and removes it. A program
// or map lives on while an attachment or an open descriptor holds it.
func removePinTree(dir string) error {
	if !exists(dir) {
		return nil
	}
	var files, dirs []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			dirs = append(dirs, path)
		} else {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return pyOSError(err)
	}
	for _, f := range files {
		if err := os.Remove(f); err != nil {
			return pyOSError(err)
		}
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := os.Remove(dirs[i]); err != nil {
			return pyOSError(err)
		}
	}
	return nil
}

// xdpReplacePinned swaps the pinned program and maps for a fresh load
// (ROADMAP SEC-19), loading into a staging directory first: if the
// kernel refuses the new program, the old one keeps filtering. Devices
// keep running the old program until the sync re-attaches them; the new
// maps start empty and get the blocklist again.
func (s *System) xdpReplacePinned(obj string) error {
	staging := s.Paths.xdpStaging()
	if err := removePinTree(staging); err != nil {
		return err
	}
	if err := s.xdpLoadInto(obj, staging); err != nil {
		if rmErr := removePinTree(staging); rmErr != nil {
			return rmErr
		}
		return err
	}
	if err := removePinTree(s.Paths.XdpPins); err != nil {
		return err
	}
	if exists(s.Paths.XdpPins) {
		if err := removePinTree(staging); err != nil {
			return err
		}
		return stepErr("%s still holds unknown pins; remove them and apply again", s.Paths.XdpPins)
	}
	return pyOSError(os.Rename(staging, s.Paths.XdpPins))
}

// restartXdpReaders try-restarts each reader after new maps were pinned:
// the units that couldn't be. A unit that isn't running stays stopped.
func (s *System) restartXdpReaders() []string {
	var failed []string
	for _, unit := range xdpReaders {
		res, err := Systemctl(s.Run, "try-restart", unit, 30*time.Second)
		if err != nil || res.Code != 0 {
			failed = append(failed, unit)
		}
	}
	return failed
}

// --- attaching ----------------------------------------------------------------------

func (s *System) xdpAttach(device string) (string, error) {
	device, err := xdpDevice(device)
	if err != nil {
		return "", err
	}
	last := ""
	for _, mode := range []string{xdpNative, xdpGeneric} {
		res, err := s.xdpIP("link", "set", "dev", device, mode, "pinned", s.Paths.xdpProgPin())
		if err != nil {
			return "", err
		}
		if res.Code == 0 {
			return mode, nil
		}
		last = res.Stderr
	}
	return "", stepErr("Failed to attach XDP program to %s in either native or generic mode: %s", device,
		config.PyStrip(last))
}

func (s *System) xdpDetach(device, mode string) error {
	device, err := xdpDevice(device)
	if err != nil {
		return err
	}
	res, err := s.xdpIP("link", "set", "dev", device, mode, "off")
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return stepErr("Failed to detach XDP program from %s: %s", device, config.PyStrip(res.Stderr))
	}
	return nil
}

// xdpLive is the filter as the kernel has it on device now (`ip -j link
// show`): its mode and program id, ok false if it isn't there. The only
// source of truth for "attached": attachments don't survive a reboot,
// the state file does (review triage B1).
func (s *System) xdpLive(device string) (mode string, id int64, ok bool, err error) {
	device, err = xdpDevice(device)
	if err != nil {
		return "", 0, false, err
	}
	res, err := s.xdpIP("-j", "link", "show", "dev", device)
	if err != nil || res.Code != 0 {
		return "", 0, false, err
	}
	v, perr := config.ParseJSONLastWins([]byte(res.Stdout))
	list, isList := v.([]config.Value)
	if perr != nil || !isList || len(list) == 0 {
		return "", 0, false, nil
	}
	link, _ := list[0].(*config.Map)
	if link == nil {
		return "", 0, false, nil
	}
	x, _ := link.Get("xdp")
	xdp, _ := x.(*config.Map)
	if xdp == nil {
		return "", 0, false, nil
	}
	var entries []config.Value
	if a, _ := xdp.Get("attached"); config.Truthy(a) {
		entries, _ = a.([]config.Value)
	} else if p, _ := xdp.Get("prog"); config.Truthy(p) {
		entries = []config.Value{xdp}
	}
	for _, e := range entries {
		entry, _ := e.(*config.Map)
		if entry == nil {
			continue
		}
		p, _ := entry.Get("prog")
		prog, _ := p.(*config.Map)
		if prog == nil {
			prog = config.NewMap()
		}
		m, _ := entry.Get("mode")
		mode := kernelMode(m)
		name, _ := prog.Get("name")
		if mode != "" && name == xdpProgName {
			idv, _ := prog.Get("id")
			if !config.Truthy(idv) {
				idv = big.NewInt(0)
			}
			id, ok := pyInt(idv)
			if !ok {
				return "", 0, false, stepErr("invalid literal for int() with base 10: %s", config.Repr(idv))
			}
			return mode, id, true, nil
		}
	}
	return "", 0, false, nil
}

// kernelMode is an XDP_ATTACHED_* value as `ip -j link` reports it
// (1 driver, 2 generic); "" for any other. As a Python dict key, 1.0
// and true are 1.
func kernelMode(v config.Value) string {
	n := int64(-1)
	switch x := v.(type) {
	case *big.Int:
		if x.IsInt64() {
			n = x.Int64()
		}
	case float64:
		if x == float64(int64(x)) {
			n = int64(x)
		}
	case bool:
		if x {
			n = 1
		} else {
			n = 0
		}
	}
	return map[int64]string{1: xdpNative, 2: xdpGeneric}[n]
}

// pyInt is int(v) for a value read from JSON: a number (a float
// truncated), a bool, or a decimal string; ok false where Python's int()
// raises.
func pyInt(v config.Value) (int64, bool) {
	switch x := v.(type) {
	case *big.Int:
		return x.Int64(), x.IsInt64()
	case float64:
		return int64(x), x == x && x < 9.3e18 && x > -9.3e18
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case string:
		n, err := strconv.ParseInt(config.PyStrip(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// xdpPinnedID is the pinned program's id, if fr-xdp can tell.
func (s *System) xdpPinnedID() (int64, bool) {
	res, err := s.xdpTool("", "prog-id", "--", s.Paths.xdpProgPin())
	if err != nil || res.Code != 0 {
		return 0, false
	}
	v, perr := config.ParseJSONLastWins([]byte(res.Stdout))
	m, _ := v.(*config.Map)
	if perr != nil || m == nil {
		return 0, false
	}
	id, ok := m.Get("id")
	if !ok {
		return 0, false
	}
	return pyInt(id)
}

// --- GRO (ROADMAP SEC-28) -------------------------------------------------------------
//
// The program checks the TCP checksum of each segment of a split
// ClientHello it follows. Generic mode runs after GRO, which merges a
// flow's segments and leaves the checksum for a NIC to finish: the
// program would drop the merged segment. So while the filter runs on a
// device in generic mode, its GRO is off; where FR_OS turned it off, it
// goes back on once the filter leaves or runs there natively. Native
// mode runs before GRO.

func errnoText(err error) string {
	var no syscall.Errno
	if errors.As(err, &no) {
		text := no.Error()
		if text != "" {
			text = strings.ToUpper(text[:1]) + text[1:]
		}
		return "[Errno " + strconv.Itoa(int(no)) + "] " + text
	}
	return err.Error()
}

func (s *System) gro(device string) (bool, error) {
	device, err := xdpDevice(device)
	if err != nil {
		return false, err
	}
	on, err := s.GRO(device)
	if err != nil {
		return false, stepErr("Could not read GRO of %s: %s", device, errnoText(err))
	}
	return on, nil
}

func (s *System) setGRO(device string, on bool) error {
	device, err := xdpDevice(device)
	if err != nil {
		return err
	}
	if err := s.SetGRO(device, on); err != nil {
		word := "off"
		if on {
			word = "on"
		}
		return stepErr("Could not turn GRO %s for %s: %s", word, device, errnoText(err))
	}
	return nil
}

// matchGRO: GRO off while the filter runs on device in generic mode;
// back on where FR_OS turned it off once it doesn't (mode "": detached).
func (s *System) matchGRO(device, mode string, groOff *[]string) error {
	if mode == xdpGeneric {
		on, err := s.gro(device)
		if err != nil {
			return err
		}
		if on {
			if err := s.setGRO(device, false); err != nil {
				return err
			}
			if !slices.Contains(*groOff, device) {
				*groOff = append(*groOff, device)
			}
		}
		return nil
	}
	if i := slices.Index(*groOff, device); i >= 0 {
		if err := s.setGRO(device, true); err != nil && mode != "" {
			return err
		}
		// Detached from a device that is gone: nothing to turn back on.
		*groOff = slices.Delete(*groOff, i, i+1)
	}
	return nil
}

// --- the blocklist and the switches ---------------------------------------------------

// syncXdpBlocklist makes the pinned map hold exactly the names' keys
// (fr-xdp removes what is no longer wanted, adds what is missing, and
// touches nothing else). A name the kernel filter can never match
// refuses the whole sync, naming every such name.
func (s *System) syncXdpBlocklist(names []string) error {
	keys := map[string]bool{}
	var rejected []string
	for _, n := range names {
		key, err := LPMKey(n)
		if err != nil {
			rejected = append(rejected, n)
			continue
		}
		keys[hex.EncodeToString(key)] = true
	}
	if len(rejected) > 0 {
		return stepErr("%d blocklist name(s) cannot be enforced by the kernel SNI filter and are NOT blocked: %s. "+
			"Nothing was applied -- the whole sync is refused rather than left half done. A name of %d bytes or "+
			"more is refused by the filter before it ever builds a key, and that cap comes from the kernel's "+
			"512-byte BPF stack limit rather than from a choice here, so the fix is on this side: shorten these "+
			"names to under %d bytes, or block them in the DNS/adblock layer instead.",
			len(rejected), sampleNames(rejected), MaxSNILen, MaxSNILen)
	}
	var stdin strings.Builder
	for _, k := range sortedKeys(keys) {
		stdin.WriteString(k + "\n")
	}
	res, err := s.xdpTool(stdin.String(), "blocklist", "--", s.Paths.xdpMap("sni_blocklist"))
	if err != nil {
		return err
	}
	if res.Code != 0 {
		// fr-xdp says which step failed, in 1.x's words.
		return &StepError{res.Stderr}
	}
	return nil
}

func (s *System) setXdpSettings(flags int) error {
	path := s.Paths.xdpMap("settings")
	if !exists(path) {
		return stepErr("The loaded XDP program has no settings map (it predates SNI observation); disable and " +
			"re-enable the XDP SNI filter to reload it.")
	}
	res, err := s.xdpTool("", "settings", "--", path, strconv.Itoa(flags))
	if err != nil {
		return err
	}
	if res.Code != 0 {
		return stepErr("Updating %s failed:\n%s", path, res.Stderr)
	}
	return nil
}

// --- the step ------------------------------------------------------------------------

// syncXDP makes the running filter match the config (1.x's
// sync_sni_filter, with the blocklist xdpBlocklist merged): attach and
// detach devices, keep or replace the program, sync the blocklist and
// the switches. What is attached is written down as it happens, so a
// failure part-way leaves no attachment unrecorded (ROADMAP SEC-19).
func (s *System) syncXDP(c *config.Config, blocklist []string, dryRun bool) (string, error) {
	cfg := c.XdpSniFilter
	st := s.loadXdpState()
	reportPass := c.AppControl.Enabled && c.AppControl.ObserveSni
	reportHello := c.TlsFingerprint.Enabled

	if !cfg.Enabled {
		if st.attached.Len() == 0 {
			return "XDP SNI filter disabled; nothing to do", nil
		}
		devices := slices.Sorted(slices.Values(attachedNames(st.attached)))
		if dryRun {
			return "Would detach XDP SNI filter from: " + strings.Join(devices, ", "), nil
		}
		if !s.root() {
			return "", stepErr("This operation requires root privileges.")
		}
		for _, d := range attachedNames(st.attached) {
			mode, _, ok, err := s.xdpLive(d)
			if err != nil {
				return "", err
			}
			if ok {
				if err := s.xdpDetach(d, mode); err != nil {
					return "", err
				}
			}
		}
		for _, d := range slices.Clone(st.groOff) {
			if err := s.matchGRO(d, "", &st.groOff); err != nil {
				return "", err
			}
		}
		if err := removePinTree(s.Paths.XdpPins); err != nil {
			return "", err
		}
		if err := s.saveXdpState(xdpState{attached: config.NewMap()}); err != nil {
			return "", err
		}
		return "Detached XDP SNI filter from: " + strings.Join(devices, ", "), nil
	}

	var devices []string
	for _, name := range cfg.Interfaces {
		i, _ := c.Interfaces.Get(name)
		devices = append(devices, i.Device)
	}
	if len(blocklist) > BlocklistMaxEntries {
		return "", stepErr("XDP blocklist has %d names, more than the kernel map's %d; lower "+
			"adblocker.xdp_critical_limit or block fewer apps via XDP", len(blocklist), BlocklistMaxEntries)
	}
	observing := ""
	if reportPass {
		observing += ", reporting passed SNIs"
	}
	if reportHello {
		observing += ", copying ClientHellos for fingerprinting"
	}
	if dryRun {
		return fmt.Sprintf("Would attach XDP SNI filter to: %s (%d blocked hostnames%s)",
			strings.Join(devices, ", "), len(blocklist), observing), nil
	}

	if !s.root() {
		return "", stepErr("This operation requires root privileges.")
	}
	obj, err := s.ensureXdpObject()
	if err != nil {
		return "", err
	}
	digest := objectDigest(obj)
	// ROADMAP SEC-19: a pinned program that didn't come from this object
	// (the previous release's, or one of unknown origin) is replaced.
	var reloaded bool
	if s.xdpLoaded() && digest != nil && (st.program == nil || *digest != *st.program) {
		if err := s.xdpReplacePinned(obj); err != nil {
			return "", err
		}
		reloaded = true
	} else if reloaded, err = s.xdpLoadAndPin(obj); err != nil {
		return "", err
	}

	// The blocklist goes in before any device runs the program: one
	// attached first would pass every name until the sync caught up.
	if err := s.syncXdpBlocklist(blocklist); err != nil {
		return "", err
	}

	program := st.program
	if digest != nil {
		program = digest
	}
	recorded := xdpState{attached: copyMap(st.attached), program: program, groOff: slices.Clone(st.groOff)}
	if err := s.saveXdpState(recorded); err != nil {
		return "", err
	}

	// The kernel, not the state file, says what is attached: after a
	// reboot the file lists every device while nothing is attached
	// (review triage B1). An attachment of an older program is swapped
	// for the pinned one.
	pinnedID, havePinned := s.xdpPinnedID()
	newAttached := config.NewMap()
	var modesUsed []string
	for _, d := range devices {
		mode, id, live, err := s.xdpLive(d)
		if err != nil {
			return "", err
		}
		if live && (!havePinned || id == pinnedID) {
			// Kept; its GRO matched too.
			if err := s.matchGRO(d, mode, &recorded.groOff); err != nil {
				return "", err
			}
			if err := s.saveXdpState(recorded); err != nil {
				return "", err
			}
			newAttached.Set(d, mode)
			continue
		}
		if live {
			if err := s.xdpDetach(d, mode); err != nil {
				return "", err
			}
		}
		mode, err = s.xdpAttach(d)
		if err != nil {
			return "", err
		}
		newAttached.Set(d, mode)
		recorded.attached.Set(d, mode)
		if err := s.saveXdpState(recorded); err != nil {
			return "", err
		}
		if err := s.matchGRO(d, mode, &recorded.groOff); err != nil {
			return "", err
		}
		if err := s.saveXdpState(recorded); err != nil {
			return "", err
		}
		modesUsed = append(modesUsed, d+"="+mode)
	}

	for _, d := range attachedNames(copyMap(recorded.attached)) {
		if newAttached.Has(d) {
			continue
		}
		mode, _, live, err := s.xdpLive(d)
		if err != nil {
			return "", err
		}
		if live {
			if err := s.xdpDetach(d, mode); err != nil {
				return "", err
			}
		}
		recorded.attached.Delete(d)
		if err := s.matchGRO(d, "", &recorded.groOff); err != nil {
			return "", err
		}
		if err := s.saveXdpState(recorded); err != nil {
			return "", err
		}
	}

	if err := s.saveXdpState(xdpState{attached: newAttached, program: recorded.program,
		groOff: recorded.groOff}); err != nil {
		return "", err
	}

	flags := 0
	if reportPass {
		flags |= settingReportPass
	}
	if reportHello {
		flags |= settingReportHello
	}
	settings := exists(s.Paths.xdpMap("settings"))
	switch {
	case settings && (!reportHello || exists(s.Paths.xdpMap("hello_pkts"))):
		if err := s.setXdpSettings(flags); err != nil {
			return "", err
		}
	case flags != 0:
		if settings {
			if err := s.setXdpSettings(flags &^ settingReportHello); err != nil {
				return "", err
			}
		}
		observing = ", SNI observation/fingerprinting unavailable until the filter is disabled and re-enabled " +
			"(the loaded program predates it)"
	}

	if reloaded {
		if failed := s.restartXdpReaders(); len(failed) > 0 {
			observing += "; could not restart " + strings.Join(failed, ", ") +
				" -- restart it by hand, or it keeps reading the previous program's maps"
		}
	}

	detail := ""
	if len(modesUsed) > 0 {
		detail = " (" + strings.Join(modesUsed, ", ") + ")"
	}
	return fmt.Sprintf("XDP SNI filter attached to: %s%s, %d blocked hostnames%s",
		strings.Join(devices, ", "), detail, len(blocklist), observing), nil
}

func copyMap(m *config.Map) *config.Map {
	out := config.NewMap()
	for i, k := range m.Keys() {
		out.SetKey(k, m.Values()[i])
	}
	return out
}

// xdpAttachedLive are the devices of the state file the kernel has the
// filter on now (1.x's get_attached).
func (s *System) xdpAttachedLive() ([]string, error) {
	var out []string
	for _, d := range attachedNames(s.loadXdpState().attached) {
		_, _, ok, err := s.xdpLive(d)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, d)
		}
	}
	return out, nil
}

// xdpUndo is the step's undo: the previous config's filter; with none,
// the filter off when nothing was attached or loaded, else unknown.
func (r *run) xdpUndo() (func() error, string, error) {
	s := r.sys
	if r.previous != nil {
		previous := r.previous
		before, _, err := s.xdpBlocklist(previous)
		if err != nil {
			return nil, "", err
		}
		return func() error { _, err := s.syncXDP(previous, before, false); return err }, "", nil
	}
	live, err := s.xdpAttachedLive()
	if err != nil {
		return nil, "", err
	}
	if len(live) == 0 && !s.xdpLoaded() {
		off := *r.c
		off.XdpSniFilter.Enabled = false
		return func() error { _, err := s.syncXDP(&off, nil, false); return err }, "", nil
	}
	return nil, "no config was recorded as applied before, so its blocklist and devices are unknown", nil
}
