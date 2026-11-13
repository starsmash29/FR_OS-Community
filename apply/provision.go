package apply

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// ApplyAll makes the system match a config, as one transaction
// (frfw.provision.apply_all, ROADMAP SEC-5, review v0.2.0 R6):
//
//   - Checked before anything changes (Preflight): the ruleset with
//     `nft -c`, the Kea config with `kea-dhcp4 -t`, the resolver's with
//     `dnsmasq --test`, the network devices the steps will touch. A
//     config that fails here changes nothing at all.
//   - Journalled, then rolled back on failure. Each step records how to
//     undo itself before it changes anything; when one fails, the steps
//     done so far are undone in reverse order -- the firewall last, so
//     the box is filtered throughout. The error names the step, what was
//     rolled back and anything that couldn't be.
//   - Recorded on success. The text of a config applied in full is kept
//     root-only (Paths.AppliedConfig): what the steps that reconcile the
//     system with a config are rolled back to, and what the router boots
//     into when config.yaml fails at boot.
//
// The steps, in order: the ruleset first, so the box is filtered before
// anything else comes up (carrying the brute-force jail, the AI IDS
// quarantine, ZTNA sessions and isolated IoT devices over the reload in
// the same nft transaction); IPv4 forwarding and the WireGuard tunnel,
// only behind it; the interface addresses; IPv6; Kea; the ad-block
// resolver; the XDP SNI filter; the PQC key exchange of the webUI and
// sshd; and last where sshd and the webUI listen.
func (s *System) ApplyAll(c *config.Config, o Options) ([]string, error) {
	if o.DryRun {
		r := &run{sys: s, c: c, dryRun: true}
		return r.run()
	}
	if !o.LastResort {
		if err := s.Preflight(c); err != nil {
			return nil, err
		}
	}
	r := &run{sys: s, c: c, previous: s.LoadAppliedConfig()}
	if !o.LastResort {
		r.journal = &Transaction{}
	}
	messages, err := r.run()
	if err != nil {
		return nil, err
	}
	if o.SourceText != nil {
		if err := WritePrivate(s.Paths.AppliedConfig, *o.SourceText); err != nil {
			return nil, pyOSError(err)
		}
	}
	return messages, nil
}

// Options are how ApplyAll applies.
type Options struct {
	// DryRun changes nothing and returns whatever its checks raise.
	DryRun bool
	// SourceText is the YAML the config was parsed from: once the apply
	// succeeds it becomes the record of the applied config. Nil leaves
	// the record as it is.
	SourceText *string
	// LastResort is the boot's last resort only (neither config.yaml nor
	// the last applied config could be applied): no preflight and no
	// rollback, so the ruleset loads even when a later step can't
	// succeed on this hardware.
	LastResort bool
}

// AppliedConfigText is the text of the config last applied in full, ok
// false when none was recorded.
func (s *System) AppliedConfigText() (string, bool) { return readText(s.Paths.AppliedConfig) }

// LoadAppliedConfig is the config last applied in full, or nil: never
// recorded (first boot, or the first apply after an update to this
// version), or no longer a valid config (an update changed the schema).
func (s *System) LoadAppliedConfig() *config.Config {
	text, ok := s.AppliedConfigText()
	if !ok {
		return nil
	}
	return parseText(text)
}

func parseText(text string) *config.Config {
	raw, err := config.LoadYAML(text)
	if err != nil {
		return nil
	}
	c, err := config.Parse(raw)
	if err != nil {
		return nil
	}
	return c
}

// --- preflight -----------------------------------------------------------------

// Preflight is everything that can be checked without changing anything,
// before anything changes. Its error says nothing was changed.
func (s *System) Preflight(c *config.Config) error {
	type check struct {
		step string
		run  func() error
	}
	checks := []check{
		{"the firewall ruleset", func() error {
			ruleset, err := s.buildRuleset(c, &nft.RuntimeSets{})
			if err != nil {
				return err
			}
			return CheckSyntax(s.Run, ruleset)
		}},
		{"network devices", func() error { return s.checkDevices(c) }},
	}
	if c.Dhcp.Zones.Len() > 0 {
		checks = append(checks, check{"DHCP (Kea)", func() error { return s.preflightKea(c) }})
	}
	if c.Adblocker.Enabled {
		checks = append(checks, check{"the ad-block DNS resolver", func() error { return s.preflightDnsmasq(c) }})
	}
	if c.XdpSniFilter.Enabled {
		checks = append(checks, check{"the XDP SNI filter", func() error { return s.checkXDP(c) }})
	}
	if c.IPv6.Enabled {
		checks = append(checks, check{"IPv6", func() error { return s.checkIPv6(c) }})
	}
	for _, ch := range checks {
		if err := ch.run(); err != nil {
			return &Error{Step: ch.step, Cause: err}
		}
	}
	return nil
}

// MissingDevices are the devices a step will act on that this machine
// doesn't have (a VLAN device is created from its parent, so the parent
// must be there). Devices only named in rules are not required: nft
// matches interfaces by name.
func (s *System) MissingDevices(c *config.Config) ([]string, error) {
	wanted := map[string]bool{}
	vlans := map[string]bool{}
	for _, i := range c.Interfaces.Values() {
		switch {
		case i.VlanParent != "":
			wanted[i.VlanParent] = true
			vlans[i.Device] = true
		case i.Address != "":
			wanted[i.Device] = true
		}
	}
	if c.XdpSniFilter.Enabled {
		for _, name := range c.XdpSniFilter.Interfaces {
			if i, ok := c.Interfaces.Get(name); ok && !vlans[i.Device] {
				wanted[i.Device] = true
			}
		}
	}
	var missing []string
	for _, d := range sortedKeys(wanted) {
		ok, err := s.DeviceExists(d)
		if err != nil {
			return nil, err
		}
		if !ok {
			missing = append(missing, d)
		}
	}
	return missing, nil
}

func (s *System) checkDevices(c *config.Config) error {
	missing, err := s.MissingDevices(c)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return stepErr("no such network device on this machine: %s", strings.Join(missing, ", "))
	}
	return nil
}

// --- the steps -----------------------------------------------------------------

// run is one pass of the steps, journalled unless it is a dry run or the
// boot's last resort.
type run struct {
	sys      *System
	c        *config.Config
	previous *config.Config
	dryRun   bool
	journal  *Transaction
	step     string
	changed  bool
}

func (r *run) begin(step string, undo func() error, whyNot string) {
	r.step = step
	if r.journal != nil && !r.dryRun {
		r.changed = true
		r.journal.Begin(step, undo, whyNot)
	}
}

func (r *run) run() (messages []string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = r.failed(fmt.Errorf("%v", p))
		}
	}()
	messages, err = r.steps()
	if err != nil {
		err = r.failed(err)
	}
	return messages, err
}

func (r *run) failed(err error) error {
	var ae *Error
	if errors.As(err, &ae) || r.dryRun {
		return err
	}
	if r.journal == nil {
		return &Error{Step: r.step, Cause: err, Changed: true,
			NotRolledBack: []string{"everything before it (boot's last-resort apply, no rollback)"}}
	}
	done, failed := r.journal.RollBack()
	return &Error{Step: r.step, Cause: err, Changed: r.changed, RolledBack: done, NotRolledBack: failed}
}

func (r *run) steps() ([]string, error) {
	s, c, dry := r.sys, r.c, r.dryRun
	var messages []string
	add := func(m string, err error) error {
		if err == nil {
			messages = append(messages, m)
		}
		return err
	}

	// The reload (`nft -f`) flushes the whole ruleset, the brute-force
	// jail, the AI IDS quarantine, ZTNA sessions and isolated IoT devices
	// with it. Their live members are read here and written into the new
	// ruleset itself, so they come back in the same nft transaction as
	// the flush: an unrelated config change never un-bans an attacker,
	// releases a quarantined host or logs a ZTNA session out, not even
	// for a moment (review FR-002). A read that fails stops the apply
	// before anything is reloaded -- the running ruleset keeps enforcing.
	// A dry run reloads nothing, so it reads nothing either.
	r.step = "reading the firewall's live sets"
	runtime := &nft.RuntimeSets{}
	if !dry {
		var err error
		if runtime, err = s.ReadRuntime(c); err != nil {
			return nil, &Error{Step: r.step, Cause: err}
		}
	}

	if !dry {
		undo, whyNot, err := r.firewallUndo()
		if err != nil {
			return nil, err
		}
		r.begin("the firewall", undo, whyNot)
	}
	fw, err := s.firewall(c, runtime, dry)
	if err != nil {
		return nil, err
	}
	messages = append(messages, fw...)
	countLeft := func(ts []nft.Timed) int {
		n := 0
		for _, t := range ts {
			if t.Left > 0 {
				n++
			}
		}
		return n
	}
	jailed := countLeft(runtime.BruteforceJail)
	quarantined := countLeft(runtime.IDSQuarantine)
	sessions := 0
	if c.Ztna.Enabled {
		for _, z := range runtime.Ztna {
			if z.Left > 0 {
				sessions++
			}
		}
	}
	isolated := 0
	if c.Iot.Enabled {
		isolated = len(runtime.IotIsolated)
	}

	// Routing only once the forward chain is loaded.
	if !dry {
		path := s.Paths.IPForward
		was, had := readText(path)
		r.begin("IPv4 forwarding", func() error {
			if now, _ := readText(path); had && now != was {
				return pyOSError(writeText(path, was))
			}
			return nil
		}, "")
	}
	if err := add(s.enableForwarding(dry)); err != nil {
		return nil, err
	}

	// The VPN tunnel (security-lessons G8), also only behind the ruleset.
	if !dry {
		undo, whyNot, err := r.wireguardUndo()
		if err != nil {
			return nil, err
		}
		r.begin("WireGuard", undo, whyNot)
	}
	if err := add(s.syncWireguard(c, dry)); err != nil {
		return nil, err
	}

	// Addresses only after the ruleset is in: no address is brought up
	// before the rules that filter it.
	if !dry {
		var links []LinkState
		for _, d := range addressDevices(c, r.previous) {
			l, err := CaptureLink(s.Run, d)
			if err != nil {
				return nil, err
			}
			links = append(links, l)
		}
		r.begin("interface addresses", func() error {
			for i := len(links) - 1; i >= 0; i-- {
				if err := links[i].Restore(s.Run); err != nil {
					return err
				}
			}
			return nil
		}, "")
	}
	if err := add(s.syncAddresses(c, r.previous, dry)); err != nil {
		return nil, err
	}

	// IPv6, after the addresses step, which creates the VLAN devices whose
	// settings it writes. With IPv6 off now and before, nothing to undo.
	if !dry && s.ipv6Touched(c, r.previous) {
		undo, err := r.ipv6Undo()
		if err != nil {
			return nil, err
		}
		r.begin("IPv6", undo, "")
	}
	if err := add(s.syncIPv6(c, dry)); err != nil {
		return nil, err
	}

	if !dry && c.Dhcp.Zones.Len() > 0 {
		undo, err := r.serviceUndo(s.Paths.KeaConfig, KeaService)
		if err != nil {
			return nil, err
		}
		r.begin("DHCP (Kea)", undo, "")
	}
	if err := add(s.syncKea(c, dry)); err != nil {
		return nil, err
	}

	if !dry {
		undo, err := r.serviceUndo(s.Paths.AdblockDnsmasqConf, AdblockDNSService)
		if err != nil {
			return nil, err
		}
		r.begin("the ad-block DNS resolver", undo, "")
	}
	if err := add(s.syncResolver(c, dry)); err != nil {
		return nil, err
	}

	blocklist, tooLong, err := s.xdpBlocklist(c)
	if err != nil {
		return nil, err
	}
	if len(tooLong) > 0 {
		// The names are shown in full: they come from this router's own
		// app catalog and its own list, and a name not named is a name the
		// operator believes is blocked and is not (ROADMAP SEC-17).
		messages = append(messages, fmt.Sprintf("XDP blocklist: %d name(s) are %d bytes or longer and are NOT "+
			"blocked in XDP (the kernel filter's MAX_SNI_LEN limit): %s. They are still blocked at the app-level "+
			"DNS layer, which is a later and coarser one.", len(tooLong), MaxSNILen, sampleNames(tooLong)))
	}
	if !dry {
		undo, whyNot, err := r.xdpUndo()
		if err != nil {
			return nil, err
		}
		r.begin("the XDP SNI filter", undo, whyNot)
	}
	if err := add(s.syncXDP(c, blocklist, dry)); err != nil {
		return nil, err
	}
	if c.TlsFingerprint.Enabled && !dry {
		// The daemon can't reopen a replaced ring buffer once it has
		// dropped its privileges: restarted to pick up the current one.
		// Best effort.
		if _, err := Systemctl(s.Run, "try-restart", TLSFPService, 30*time.Second); err != nil && !noSystemd(err) {
			return nil, err
		}
	}

	switch {
	case dry:
		messages = append(messages, "Brute-force jail: would preserve active bans across reload (dry-run)",
			"AI IDS quarantine: would preserve active quarantines across reload (dry-run)")
	default:
		messages = append(messages,
			"Brute-force jail: "+strconv.Itoa(jailed)+" active ban(s) preserved across reload",
			"AI IDS quarantine: "+strconv.Itoa(quarantined)+" active quarantine(s) preserved across reload")
	}
	switch {
	case !c.Ztna.Enabled:
		messages = append(messages, "ZTNA gate disabled")
	case dry:
		messages = append(messages, "ZTNA gate: would preserve active sessions across reload (dry-run)")
	default:
		messages = append(messages, "ZTNA gate: "+strconv.Itoa(sessions)+" active session(s) preserved across reload")
	}
	switch {
	case !c.Iot.Enabled:
		messages = append(messages, "IoT isolation disabled")
	case dry:
		messages = append(messages, "IoT isolation: would preserve isolated devices across reload (dry-run)")
	default:
		messages = append(messages, "IoT isolation: "+strconv.Itoa(isolated)+" isolated device(s) preserved across reload")
	}

	if !dry {
		tls, err := CaptureFile(s.Paths.PqcOpenSSLConf)
		if err != nil {
			return nil, err
		}
		r.begin("the webUI's TLS key exchange", tls.Restore, "")
	}
	if err := add(s.syncTLSPQC(c, dry)); err != nil {
		return nil, err
	}

	if !dry {
		kex, err := CaptureFile(s.Paths.SSHKexDropin)
		if err != nil {
			return nil, err
		}
		r.begin("SSH key exchange", func() error {
			if differs, err := kex.Differs(); err != nil || !differs {
				return err
			}
			if err := kex.Restore(); err != nil {
				return err
			}
			if s.Which(sshdBinary) != "" {
				unit, err := CaptureService(s.Run, sshUnits[0])
				if err != nil {
					return err
				}
				return unit.Restore(s.Run, true, "reload-or-restart")
			}
			return nil
		}, "")
	}
	if err := add(s.syncSSHKex(c, dry)); err != nil {
		return nil, err
	}

	// Security-lessons F2/G4: the webUI and sshd listen on the management
	// zones' addresses only.
	if !dry {
		undo, err := r.sshdUndo()
		if err != nil {
			return nil, err
		}
		r.begin("SSH listen addresses", undo, "")
	}
	if err := add(s.syncSSHD(c, dry)); err != nil {
		return nil, err
	}
	// Last: it only schedules a webUI restart, so it runs only once
	// everything before it succeeded, and has nothing to undo.
	r.step = "the webUI's listen addresses"
	if err := add(s.syncWebUI(c, dry)); err != nil {
		return nil, err
	}
	if c.Management.AllowWan {
		messages = append(messages, "WARNING: "+WANWarning)
	}
	return messages, nil
}

// --- how each step is undone -----------------------------------------------------

func (r *run) firewallUndo() (func() error, string, error) {
	s := r.sys
	schedule, err := CaptureFile(s.Paths.ScheduleState)
	if err != nil {
		return nil, "", err
	}
	if r.previous != nil {
		previous := r.previous
		// The last applied config, with the live sets read again now: a
		// ban or session added since the apply began is kept.
		return func() error {
			runtime, err := s.ReadRuntime(previous)
			if err != nil {
				return err
			}
			_, err = s.firewall(previous, runtime, false)
			return err
		}, "", nil
	}
	before, err := CaptureRuleset(s.Run)
	if err != nil {
		return nil, "", err
	}
	if config.PyStrip(before) != "" {
		return func() error {
			if err := LoadCaptured(s.Run, before); err != nil {
				return err
			}
			return schedule.Restore()
		}, "", nil
	}
	return nil, "nothing was loaded before it, so the new ruleset stays: the router is never left unfiltered", nil
}

func (r *run) wireguardUndo() (func() error, string, error) {
	s := r.sys
	if r.previous != nil {
		previous := r.previous
		return func() error { _, err := s.syncWireguard(previous, false); return err }, "", nil
	}
	there, err := s.wgLinkExists()
	if err != nil {
		return nil, "", err
	}
	if !there {
		off := wireguardOff(r.c)
		return func() error { _, err := s.syncWireguard(off, false); return err }, "", nil
	}
	return nil, "no config was recorded as applied before, so the tunnel as it was is unknown", nil
}

func (r *run) ipv6Undo() (func() error, error) {
	s := r.sys
	keys := map[string]bool{}
	for _, kv := range sysctlsOf(r.c) {
		keys[kv.Key] = true
	}
	if r.previous != nil {
		for _, kv := range sysctlsOf(r.previous) {
			keys[kv.Key] = true
		}
	}
	sysctls := s.readSysctls(sortedKeys(keys))
	dhcpcd, err := r.capture(s.Paths.IPv6DhcpcdConf, IPv6Service)
	if err != nil {
		return nil, err
	}
	ra, err := r.capture(s.Paths.IPv6RAConf, IPv6RAService)
	if err != nil {
		return nil, err
	}
	ula := s.captureULA()
	// The RA instance goes back first: it advertises what dhcpcd and the
	// ULA addresses set.
	return func() error {
		if err := s.writeSysctls(sysctls); err != nil {
			return err
		}
		if err := ra.restore(s.Run); err != nil {
			return err
		}
		if err := s.restoreULA(ula); err != nil {
			return err
		}
		return dhcpcd.restore(s.Run)
	}, nil
}

// fileService is a config file and the unit that reads it, as they
// were.
type fileService struct {
	file FileState
	unit ServiceState
}

func (r *run) capture(path, unit string) (fileService, error) {
	f, err := CaptureFile(path)
	if err != nil {
		return fileService{}, err
	}
	u, err := CaptureService(r.sys.Run, unit)
	if err != nil {
		return fileService{}, err
	}
	return fileService{f, u}, nil
}

// restore puts the file back, then the unit, restarted if its file
// changed.
func (fs fileService) restore(run Runner) error {
	changed, err := fs.file.Differs()
	if err != nil {
		return err
	}
	if err := fs.file.Restore(); err != nil {
		return err
	}
	return fs.unit.Restore(run, changed, "restart")
}

func (r *run) serviceUndo(path, unit string) (func() error, error) {
	fs, err := r.capture(path, unit)
	if err != nil {
		return nil, err
	}
	return func() error { return fs.restore(r.sys.Run) }, nil
}

func (r *run) sshdUndo() (func() error, error) {
	s := r.sys
	dropin, err := CaptureFile(s.Paths.SSHManagementDropin)
	if err != nil {
		return nil, err
	}
	if s.Which(sshdBinary) == "" {
		return dropin.Restore, nil // syncSSHD is a no-op without sshd
	}
	unit, err := CaptureService(s.Run, sshUnits[0])
	if err != nil {
		return nil, err
	}
	enabled, known, err := Enabled(s.Run, sshUnits[0])
	if err != nil {
		return nil, err
	}
	return func() error {
		changed, err := dropin.Differs()
		if err != nil {
			return err
		}
		if err := dropin.Restore(); err != nil {
			return err
		}
		if err := SetEnabled(s.Run, sshUnits[0], enabled, known); err != nil {
			return err
		}
		return unit.Restore(s.Run, changed, "reload-or-restart")
	}, nil
}

// --- the firewall --------------------------------------------------------------

func (s *System) scheduleClock(c *config.Config) (*nft.Clock, error) {
	if !hasSchedules(c) {
		return nil, nil
	}
	clock, err := nft.CurrentClock(c.Timezone, s.Now())
	if err != nil {
		return nil, err
	}
	return &clock, nil
}

func (s *System) buildRuleset(c *config.Config, runtime *nft.RuntimeSets) (string, error) {
	clock, err := s.scheduleClock(c)
	if err != nil {
		return "", err
	}
	return nft.Build(c, nft.Options{Clock: clock, Now: s.Now(), Runtime: runtime})
}

// firewall loads c's ruleset (backing up the running one) with the
// scheduled rules rendered for the offset in effect now, and records
// that offset for the hourly DST check.
func (s *System) firewall(c *config.Config, runtime *nft.RuntimeSets, dry bool) ([]string, error) {
	clock, err := s.scheduleClock(c)
	if err != nil {
		return nil, err
	}
	ruleset, err := nft.Build(c, nft.Options{Clock: clock, Now: s.Now(), Runtime: runtime})
	if err != nil {
		return nil, err
	}
	message, _, err := ApplyRuleset(s.Run, ruleset, dry, s.Paths.BackupDir, BackupRetention, s.Now())
	if err != nil {
		return nil, err
	}
	messages := []string{message}
	if clock != nil {
		scheduled := 0
		for _, rule := range c.Rules {
			if rule.Schedule != nil {
				scheduled++
			}
		}
		zone := c.Timezone
		if zone == "" {
			zone = "system local time"
		}
		messages = append(messages, fmt.Sprintf("Scheduled rules: %d, rendered for %s (%s)", scheduled, DescribeClock(*clock), zone))
		if !dry {
			if err := s.recordSchedule(c, *clock); err != nil {
				return nil, err
			}
		}
	} else if !dry {
		if err := unlinkMissingOK(s.Paths.ScheduleState); err != nil {
			return nil, pyOSError(err)
		}
	}
	return messages, nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func bigInt(n int) *big.Int { return big.NewInt(int64(n)) }
