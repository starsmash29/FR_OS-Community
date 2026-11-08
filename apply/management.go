package apply

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
	"github.com/starsmash29/fr_os-community/render"
)

// --- hybrid PQC key exchange (frfw.pqc) ------------------------------------------

// minOpenSSLHybrid is the first OpenSSL with ML-KEM (3.5).
var minOpenSSLHybrid = [3]int{3, 5, 0}

func versionAtLeast(v, min [3]int) bool { return slices.Compare(v[:], min[:]) >= 0 }

// configuredTLSGroups is the Groups= value of a fragment written before,
// ok false when there is none.
func configuredTLSGroups(path string) (string, bool) {
	text, ok := readText(path)
	if !ok {
		return "", false
	}
	for _, line := range config.PySplitlines(text) {
		line = config.PyStrip(line)
		if strings.HasPrefix(line, "Groups") {
			_, value, _ := strings.Cut(line, "=")
			return config.PyStrip(value), true
		}
	}
	return "", false
}

func writeOpenSSLConf(path string, hybrid bool) error {
	if err := mkdirParent(path); err != nil {
		return pyOSError(err)
	}
	return pyOSError(writeText(path, render.OpenSSLConf(hybrid)))
}

// syncTLSPQC refreshes the webUI's OpenSSL fragment to match pqc.enabled
// and what the host's OpenSSL can do. The running webUI reads it at its
// next start.
func (s *System) syncTLSPQC(c *config.Config, dryRun bool) (string, error) {
	path := s.Paths.PqcOpenSSLConf
	if !c.Pqc.Enabled {
		current, ok := configuredTLSGroups(path)
		if !ok || !strings.Contains(current, "MLKEM") {
			return "PQC hybrid TLS disabled (classical X25519/P-256, TLS 1.3-only)", nil
		}
		if dryRun {
			return "Would revert " + path + " to classical-only TLS groups (dry-run)", nil
		}
		if err := writeOpenSSLConf(path, false); err != nil {
			return "", err
		}
		return "PQC hybrid TLS disabled (reverted to classical X25519/P-256)", nil
	}
	version, text := s.OpenSSLVersion()
	supported := versionAtLeast(version, minOpenSSLHybrid)
	if dryRun {
		state := "classical-only (host OpenSSL too old)"
		if supported {
			state = "X25519MLKEM768"
		}
		return "Would enable PQC hybrid TLS (" + state + ", dry-run)", nil
	}
	if err := writeOpenSSLConf(path, supported); err != nil {
		return "", err
	}
	if supported {
		return "PQC hybrid TLS enabled (X25519MLKEM768) -- restart fr-webui to load it", nil
	}
	return "PQC hybrid TLS requested but host OpenSSL " + text + " is older than 3.5 and has no ML-KEM support; " +
		"falling back to classical X25519/P-256 (TLS 1.3-only is still enforced)", nil
}

// sshKexMethods is `ssh -Q kex` of the installed OpenSSH (sshd has no
// -Q; the client of the same build answers): empty when either is
// missing or the query fails.
func (s *System) sshKexMethods() map[string]bool {
	if s.Which(sshdBinary) == "" {
		return nil
	}
	ssh := s.Which("ssh")
	if ssh == "" {
		return nil
	}
	res, err := s.Run(Cmd{Argv: []string{ssh, "-Q", "kex"}})
	if err != nil || res.Code != 0 {
		return nil
	}
	out := map[string]bool{}
	for _, line := range config.PySplitlines(res.Stdout) {
		if m := config.PyStrip(line); m != "" {
			out[m] = true
		}
	}
	return out
}

// testSSHD is `sshd -t`, when sshd's privilege-separation directory is
// there (ssh.service checks it itself as it starts otherwise).
func (s *System) testSSHD(failed string) error {
	if !isDir(s.Paths.SSHDPrivsepDir) {
		return nil
	}
	res, err := s.Run(Cmd{Argv: []string{sshdBinary, "-t"}})
	if errors.Is(err, ErrNotFound) {
		return stepErr("%s binary not found; install openssh-server", config.Repr(sshdBinary))
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return &StepError{msg}
		}
		return &StepError{failed}
	}
	return nil
}

func (s *System) reloadSSH() error {
	// try-: a stopped sshd (nobody can log in) stays stopped.
	res, err := Systemctl(s.Run, "try-reload-or-restart", "ssh", 0)
	if errors.Is(err, ErrNotFound) {
		return stepErr("'systemctl' not found")
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return &StepError{msg}
		}
		return stepErr("failed to reload the ssh service")
	}
	return nil
}

// syncSSHKex reconciles the KexAlgorithms drop-in with pqc.enabled and
// what the installed sshd can do: checked with `sshd -t` (the previous
// drop-in back if it fails), then sshd reloaded, never restarted, so an
// open session stays.
func (s *System) syncSSHKex(c *config.Config, dryRun bool) (string, error) {
	path := s.Paths.SSHKexDropin
	if s.Which(sshdBinary) == "" {
		return "sshd not installed; nothing to do", nil
	}
	if !c.Pqc.Enabled {
		if !exists(path) {
			return "PQC hybrid SSH KEX disabled", nil
		}
		if dryRun {
			return "Would remove " + path + " (PQC disabled, dry-run)", nil
		}
		if !s.root() {
			return "", stepErr("Applying the sshd PQC KexAlgorithms drop-in requires root privileges.")
		}
		if err := os.Remove(path); err != nil {
			return "", pyOSError(err)
		}
		if err := s.reloadSSH(); err != nil {
			return "", err
		}
		return "PQC hybrid SSH KEX disabled", nil
	}
	supported := s.sshKexMethods()[render.MLKEMKex]
	content := render.SSHKexDropin(supported)
	if dryRun {
		state := "classical-only (host sshd too old)"
		if supported {
			state = render.MLKEMKex
		}
		return "Would write " + path + " (" + state + ", dry-run)", nil
	}
	if !s.root() {
		return "", stepErr("Applying the sshd PQC KexAlgorithms drop-in requires root privileges.")
	}
	if err := mkdirParent(path); err != nil {
		return "", pyOSError(err)
	}
	previous, had := readText(path)
	if err := writeText(path, content); err != nil {
		return "", pyOSError(err)
	}
	if err := s.testSSHD("sshd -t rejected the generated KexAlgorithms drop-in"); err != nil {
		if had {
			_ = writeText(path, previous)
		} else {
			_ = unlinkMissingOK(path)
		}
		return "", err
	}
	if err := s.reloadSSH(); err != nil {
		return "", err
	}
	if supported {
		return "PQC hybrid SSH KEX active (" + render.MLKEMKex + ")", nil
	}
	return "PQC hybrid SSH KEX requested but installed sshd is older than OpenSSH 9.9 and doesn't support " +
		render.MLKEMKex + "; falling back to classical-only KexAlgorithms", nil
}

// --- the management plane (frfw.management) ---------------------------------------

// NobodyCanLogIn is why SSH is off.
var NobodyCanLogIn = "nobody can log in with a key yet. Add a user to the " + SSHGroup + " group, give them " +
	"~/.ssh/authorized_keys, then apply -- SSH starts once someone can use it"

// WANWarning is said on every apply with management.allow_wan.
const WANWarning = "management.allow_wan is on: the webUI and SSH are reachable from the internet. " +
	"Use the WireGuard VPN (VPN screen) for remote management instead and turn this off."

const (
	sshPort   = 22
	webUIPort = 443
)

// ListenAddresses are where the webUI and sshd listen with c.
func (s *System) ListenAddresses(c *config.Config) []string {
	return render.ListenAddresses(c, s.ULAPrefix(c))
}

// listening are the addresses something listens on at TCP port (`ss`);
// ok false when that can't be told.
func (s *System) listening(port int) (map[string]bool, bool) {
	res, err := s.Run(Cmd{Argv: []string{"ss", "-Hltn", "sport = :" + strconv.Itoa(port)}, Timeout: 10 * time.Second})
	if err != nil || res.Code != 0 {
		return nil, false
	}
	found := map[string]bool{}
	for _, line := range config.PySplitlines(res.Stdout) {
		fields := config.PySplit(line)
		if len(fields) >= 4 {
			addr := fields[3]
			if i := strings.LastIndex(addr, ":"); i >= 0 {
				addr = addr[:i]
			}
			found[strings.Trim(addr, "[]")] = true
		}
	}
	return found, true
}

// missesAddresses: something listens at port, but not on every one of
// wanted.
func (s *System) missesAddresses(port int, wanted []string) bool {
	found, ok := s.listening(port)
	if !ok || len(found) == 0 {
		return false
	}
	for _, w := range wanted {
		if !found[w] {
			return true
		}
	}
	return false
}

// syncSSHD writes the ListenAddress drop-in, checks it with `sshd -t`
// (the previous one back if sshd refuses it) and reloads sshd. sshd runs
// only while someone can log in; otherwise it is stopped and disabled
// (security-lessons I1).
func (s *System) syncSSHD(c *config.Config, dryRun bool) (string, error) {
	path := s.Paths.SSHManagementDropin
	if s.Which(sshdBinary) == "" {
		return "sshd not installed; nothing to bind", nil
	}
	ula := s.ULAPrefix(c)
	content := render.SSHD(c, ula)
	addresses := render.ListenAddresses(c, ula)
	where := strings.Join(addresses, ", ")
	users := s.LoginUsers()
	if dryRun {
		if len(users) == 0 {
			return "Would turn SSH off: " + NobodyCanLogIn + " (dry-run)", nil
		}
		return "Would make sshd listen on " + where + " (dry-run)", nil
	}
	previous, had := readText(path)
	changed := !had || previous != content
	restore := func() {
		if !had {
			_ = unlinkMissingOK(path)
		} else {
			_ = writeText(path, previous)
		}
	}
	if changed {
		if !s.root() {
			return "", stepErr("writing the sshd drop-in needs root")
		}
		if err := mkdirParent(path); err != nil {
			return "", pyOSError(err)
		}
		if err := writeText(path, content); err != nil {
			return "", pyOSError(err)
		}
		if isDir(s.Paths.SSHDPrivsepDir) {
			res, err := s.Run(Cmd{Argv: []string{sshdBinary, "-t"}})
			if errors.Is(err, ErrNotFound) { // 1.x lets the FileNotFoundError through
				return "", stepErr("[Errno 2] No such file or directory: %s", config.Repr(sshdBinary))
			}
			if err != nil {
				return "", err
			}
			if res.Code != 0 {
				restore()
				if msg := config.PyStrip(res.Stderr); msg != "" {
					return "", &StepError{msg}
				}
				return "", stepErr("sshd -t rejected the ListenAddress drop-in")
			}
		}
	}
	systemctl := func(action, unit string) (Result, error) {
		res, err := Systemctl(s.Run, action, unit, 60*time.Second)
		if errors.Is(err, ErrNotFound) {
			return res, stepErr("[Errno 2] No such file or directory: 'systemctl'")
		}
		return res, err
	}
	if len(users) == 0 {
		// Security-lessons I1: a service nobody can log in to is only
		// attack surface. Off until someone can.
		for _, unit := range sshUnits {
			if _, err := systemctl("disable", unit); err != nil {
				return "", err
			}
			if _, err := systemctl("stop", unit); err != nil {
				return "", err
			}
		}
		return "SSH is off: " + NobodyCanLogIn, nil
	}
	if _, err := systemctl("enable", sshUnits[0]); err != nil {
		return "", err
	}
	var res Result
	var err error
	// Also when the drop-in is as it was but sshd doesn't listen on one of
	// its addresses: sshd skips an address that isn't on the router when
	// it starts (a ULA one this apply only now put on) and never binds it
	// later by itself.
	if changed || s.missesAddresses(sshPort, addresses) {
		res, err = systemctl("reload-or-restart", sshUnits[0])
	} else {
		res, err = systemctl("start", sshUnits[0])
	}
	if err != nil {
		return "", err
	}
	if res.Code != 0 {
		if changed {
			restore()
		}
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return "", &StepError{msg}
		}
		return "", stepErr("failed to start or reload the ssh service")
	}
	return "sshd listens on " + where + "; key login for " + strings.Join(users, ", "), nil
}

// recordWebUIListen records the addresses the webUI binds at its next
// start: the applied config's, not config.yaml's.
func (s *System) recordWebUIListen(addresses []string) error {
	list := make([]config.Value, len(addresses))
	for i, a := range addresses {
		list[i] = a
	}
	m := config.NewMap()
	m.Set("addresses", list)
	text, err := config.PyJSON(m, -1, false)
	if err != nil {
		return err
	}
	name := filepath.Base(s.Paths.WebUIListen)
	return pyOSError(replaceFile(s.Paths.WebUIListen, "."+name+".tmp", text+"\n", 0o644))
}

// syncWebUI: the webUI binds its addresses at start, so when they should
// change it is restarted -- a few seconds later, so the request that
// asked for this apply still gets its answer.
func (s *System) syncWebUI(c *config.Config, dryRun bool) (string, error) {
	addresses := s.ListenAddresses(c)
	wanted := map[string]bool{}
	for _, a := range addresses {
		wanted[a] = true
	}
	sorted := slices.Sorted(mapKeys(wanted))
	if dryRun {
		return "Would make the webUI listen on " + strings.Join(sorted, ", ") + " (dry-run)", nil
	}
	if err := s.recordWebUIListen(addresses); err != nil {
		return "", err
	}
	running, ok := s.listening(webUIPort)
	same := len(running) == len(wanted)
	for a := range running {
		same = same && wanted[a]
	}
	if !ok || len(running) == 0 || same {
		return "webUI listens on " + strings.Join(sorted, ", "), nil
	}
	_, err := s.Run(Cmd{Argv: []string{"systemd-run", "--quiet", "--on-active=3", "--unit=" + webUIRebindUnit,
		"systemctl", "try-restart", WebUIUnit}, Timeout: 30 * time.Second})
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrTimeout) {
		return "webUI listen addresses changed; restart fr-webui to apply them", nil
	}
	if err != nil {
		return "", err
	}
	return "webUI restarting to listen on " + strings.Join(sorted, ", "), nil
}

// MovesManagement is why an apply of c must not happen: it would move
// the webUI and SSH (listen elsewhere than with previous, the config
// applied now) without the admin having changed the management settings
// (ROADMAP SEC-27). "" when it may.
func (s *System) MovesManagement(c, previous *config.Config) string {
	if previous == nil || !managementEqual(c.Management, previous.Management) {
		return ""
	}
	// IPv4 only: the ULA addresses follow the LAN zones' IPv6, and IPv4
	// still reaches the router wherever they come and go.
	v4 := func(list []string) []string {
		var out []string
		for _, a := range list {
			if !strings.Contains(a, ":") {
				out = append(out, a)
			}
		}
		return out
	}
	before, after := v4(s.ListenAddresses(previous)), v4(s.ListenAddresses(c))
	if setEqual(before, after) {
		return ""
	}
	return "it would move the webUI and SSH from " + strings.Join(before, ", ") + " to " + strings.Join(after, ", ") +
		". Only the webUI address setting moves them (System -> webUI address)"
}

func managementEqual(a, b config.ManagementConfig) bool {
	return slices.Equal(a.Zones, b.Zones) && a.AllowWan == b.AllowWan &&
		a.ConfirmApplySeconds == b.ConfirmApplySeconds && slices.Equal(a.Addresses, b.Addresses) && a.IPv6 == b.IPv6
}

func setEqual(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	for _, x := range b {
		if !slices.Contains(a, x) {
			return false
		}
	}
	return true
}

// --- scheduled rules (frfw.schedule_refresh) ----------------------------------------

func hasSchedules(c *config.Config) bool {
	for _, r := range c.Rules {
		if r.Schedule != nil {
			return true
		}
	}
	return false
}

// ConfigFingerprint identifies a parsed config: the hourly schedule
// check re-applies only the config that was applied, never an edit
// saved since. 1.x hashes Python's repr of its Config; FR_OS 2 hashes
// the JSON of its own (testdata/reference/decisions.md, "The schedule
// record's fingerprint"), so formatting-only edits still don't count.
func ConfigFingerprint(c *config.Config) (string, error) {
	data, err := json.Marshal(c, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// DescribeClock is ScheduleClock.describe(): "UTC+02:00".
func DescribeClock(c nft.Clock) string {
	sign, m := "+", c.UTCOffsetMinutes
	if m < 0 {
		sign, m = "-", -m
	}
	return "UTC" + sign + pad2(m/60) + ":" + pad2(m%60)
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func (s *System) recordSchedule(c *config.Config, clock nft.Clock) error {
	fp, err := ConfigFingerprint(c)
	if err != nil {
		return err
	}
	cl := config.NewMap()
	cl.Set("utc_offset_minutes", bigInt(clock.UTCOffsetMinutes))
	cl.Set("kernel_minuteswest", bigInt(clock.KernelMinutesWest))
	m := config.NewMap()
	m.Set("clock", cl)
	if c.Timezone == "" {
		m.Set("timezone", nil)
	} else {
		m.Set("timezone", c.Timezone)
	}
	m.Set("config_fingerprint", fp)
	text, err := config.PyJSON(m, -1, false)
	if err != nil {
		return err
	}
	path := s.Paths.ScheduleState
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + ".tmp"
	return pyOSError(replaceFile(path, name, text, 0))
}
