package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
	"github.com/starsmash29/fr_os-community/render"
)

// firewall-cli: the commands the router's units run as root (1.x's
// frfw.cli): the boot's apply in fail-closed mode (fr-firewall.service),
// an apply from the console, validate and render, the hourly schedule
// check (fr-schedule-check.timer), the DNS query log trim
// (fr-dns-log-trim.timer), the ad-block refresh
// (fr-adblock-refresh.timer), ensure-accounts (fr-accounts.service), and
// first boot's (firstboot.go). Each prints what 1.x prints and exits as
// it does.

// cliUsage is what a command line firewall-cli can't read gets, with
// exit status 2 (argparse's). It is 2.x's own: 1.x lists the commands
// it has (decisions.md, "phase 4f-1").
const cliUsage = `usage: firewall-cli COMMAND ...

  validate [CONFIG]                 check a config file
  render [CONFIG]                   print the nftables ruleset it builds
  apply [CONFIG] [--dry-run] [--fail-closed] [--confirm-within SECONDS]
                                    apply it (fr-firewall.service: --fail-closed)
  schedule-check [CONFIG]           re-apply scheduled rules after a time offset change
  dns-log-trim                      empty the resolver's query log past 16 MiB
  adblock-refresh [CONFIG] [--scheduled]
                                    fetch the ad-block lists
  ensure-accounts                   create FR_OS's accounts and state directories
  detect-interfaces [--include-virtual]
                                    list the network ports
  detect-wan-lan                    pick the WAN and LAN ports (first boot; root)
  assign-interfaces --wan DEVICE --lan DEVICE [--opt ZONE:DEVICE]... [--hostname NAME]
                    [--lan-address ADDRESS/PREFIX] [--out FILE] [--force]
                                    write a minimal config for the ports
  set-admin-password [--username NAME] [--generate [--show-on-console]]
                                    create or reset a webUI admin account
  mfa-reset USERNAME                remove a webUI account's second factors
  initial-password                  take the generated password off the console once changed
  console-ports [--print] [--watch] show the ports on the console's login screen
  persistence status | auto [--reboot] | create DISK [--wipe] [--yes]
                                    keep a live-booted router's state across reboots

CONFIG defaults to /etc/fr_os/config.yaml.
`

// cliCommand is one command's options, as argparse reads them.
type cliCommand struct {
	name    string
	config  bool     // takes the optional CONFIG
	flags   []string // its switches
	numbers []string // its options taking an integer
	values  []string // its options taking a value
	appends []string // its options taking a value, repeatable
	// required are the options it must have; positional the values it
	// takes in order, all required.
	required, positional []string
	defaults             map[string]string
}

var cliCommands = []cliCommand{
	{name: "validate", config: true},
	{name: "render", config: true},
	{name: "apply", config: true, flags: []string{"--dry-run", "--fail-closed"}, numbers: []string{"--confirm-within"}},
	{name: "schedule-check", config: true},
	{name: "dns-log-trim"},
	{name: "adblock-refresh", config: true, flags: []string{"--scheduled"}},
	{name: "ensure-accounts"},
	{name: "detect-interfaces", flags: []string{"--include-virtual"}},
	{name: "detect-wan-lan"},
	{name: "assign-interfaces", flags: []string{"--force"},
		values: []string{"--wan", "--lan", "--hostname", "--lan-address", "--out"}, appends: []string{"--opt"},
		required: []string{"--wan", "--lan"},
		defaults: map[string]string{"--hostname": "fr-router", "--lan-address": apply.DefaultLANAddress}},
	{name: "set-admin-password", flags: []string{"--generate", "--show-on-console"}, values: []string{"--username"},
		defaults: map[string]string{"--username": "admin"}},
	{name: "mfa-reset", positional: []string{"username"}},
	{name: "initial-password"},
	{name: "console-ports", flags: []string{"--print", "--watch"}},
	{name: "persistence status"},
	{name: "persistence auto", flags: []string{"--reboot"}},
	{name: "persistence create", flags: []string{"--wipe", "--yes"}, positional: []string{"disk"}},
}

type cliArgs struct {
	command string
	config  string
	flags   map[string]bool
	numbers map[string]*int64
	values  map[string]string
	appends map[string][]string
	// positional are the command's values by name.
	positional map[string]string
}

type usageError string

func (e usageError) Error() string { return string(e) }

// option is the one option name arg stands for (argparse takes any
// unambiguous prefix).
func option(arg string, names []string) (string, error) {
	var found []string
	for _, n := range names {
		if n == arg {
			return n, nil
		}
		if strings.HasPrefix(n, arg) {
			found = append(found, n)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", usageError("unrecognized arguments: " + arg)
	}
	return "", usageError("ambiguous option: " + arg)
}

// negativeNumber is what argparse takes as a value although it starts
// with "-" (no option of firewall-cli looks like one).
var negativeNumber = regexp.MustCompile(`\A-\d+\z|\A-\d*\.\d+\z`)

func parseCLI(args []string, defaultConfig string) (*cliArgs, error) {
	if len(args) == 0 {
		return nil, usageError("the following arguments are required: command")
	}
	name := args[0]
	rest := args[1:]
	if name == "persistence" {
		if len(rest) == 0 {
			return nil, usageError("the following arguments are required: persistence_command")
		}
		name, rest = name+" "+rest[0], rest[1:]
	}
	var cmd *cliCommand
	for i := range cliCommands {
		if cliCommands[i].name == name {
			cmd = &cliCommands[i]
		}
	}
	if cmd == nil {
		return nil, usageError("invalid choice: " + strconv.Quote(args[0]))
	}
	a := &cliArgs{command: cmd.name, config: defaultConfig, flags: map[string]bool{}, numbers: map[string]*int64{},
		values: map[string]string{}, appends: map[string][]string{}, positional: map[string]string{}}
	for k, v := range cmd.defaults {
		a.values[k] = v
	}
	names := slices.Concat(cmd.flags, cmd.numbers, cmd.values, cmd.appends)
	seen := map[string]bool{}
	configs := 0
	onlyPositional := false
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if !onlyPositional && arg == "--" {
			onlyPositional = true
			continue
		}
		if !onlyPositional && strings.HasPrefix(arg, "-") && arg != "-" && !negativeNumber.MatchString(arg) {
			opt, value, hasValue := strings.Cut(arg, "=")
			opt, err := option(opt, names)
			if err != nil {
				return nil, err
			}
			seen[opt] = true
			if slices.Contains(cmd.flags, opt) {
				if hasValue {
					return nil, usageError("argument " + opt + ": ignored explicit argument " + strconv.Quote(value))
				}
				a.flags[opt] = true
				continue
			}
			if !hasValue {
				next := ""
				if i+1 < len(rest) {
					next = rest[i+1]
				}
				if i+1 >= len(rest) || (strings.HasPrefix(next, "-") && next != "-" && !negativeNumber.MatchString(next)) {
					return nil, usageError("argument " + opt + ": expected one argument")
				}
				i++
				value = next
			}
			switch {
			case slices.Contains(cmd.numbers, opt):
				n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
				if err != nil {
					return nil, usageError("argument " + opt + ": invalid int value: " + strconv.Quote(value))
				}
				a.numbers[opt] = &n
			case slices.Contains(cmd.appends, opt):
				a.appends[opt] = append(a.appends[opt], value)
			default:
				a.values[opt] = value
			}
			continue
		}
		switch {
		case len(a.positional) < len(cmd.positional):
			a.positional[cmd.positional[len(a.positional)]] = arg
		case cmd.config && configs == 0:
			a.config = arg
			configs++
		default:
			return nil, usageError("unrecognized arguments: " + arg)
		}
	}
	for _, r := range cmd.required {
		if !seen[r] {
			return nil, usageError("the following arguments are required: " + r)
		}
	}
	if len(a.positional) < len(cmd.positional) {
		return nil, usageError("the following arguments are required: " + cmd.positional[len(a.positional)])
	}
	return a, nil
}

// CLI runs firewall-cli with args (without the program's name), printing
// to stdout and stderr, and returns its exit status.
func (s *Server) CLI(args []string, stdout, stderr io.Writer) int {
	a, err := parseCLI(args, s.sys().Paths.Config)
	if err != nil {
		fmt.Fprint(stderr, cliUsage)
		fmt.Fprintf(stderr, "firewall-cli: error: %v\n", err)
		return 2
	}
	c := &cli{s: s, out: stdout, err: stderr}
	code, err := c.run(a)
	if err != nil {
		fmt.Fprintln(stderr, errorLine(err))
		return 1
	}
	return code
}

// errorLine is the line 1.x's main prints for an exception it catches
// ("error: " for the rest: the config file not found, the steps'
// refusals; and, for one 1.x lets through, its name and text where 1.x
// prints a traceback).
func errorLine(err error) string {
	var (
		ce *config.Error
		pe *PendingError
		ne *apply.NftError
		ae *apply.Error
		na *apply.NoAccountError
	)
	switch {
	case errors.As(err, &ae): // first: it wraps the step's own error
		return "apply error: " + err.Error()
	case errors.As(err, &ce):
		return "config error: " + err.Error()
	case errors.As(err, &pe):
		return "error: " + err.Error()
	case errors.As(err, &ne):
		return "nft error: " + err.Error()
	case errors.As(err, &na):
		return "KeyError: " + err.Error()
	}
	return "error: " + err.Error()
}

type cli struct {
	s        *Server
	out, err io.Writer
}

func (c *cli) println(a ...any)  { fmt.Fprintln(c.out, a...) }
func (c *cli) eprintln(a ...any) { fmt.Fprintln(c.err, a...) }

func (c *cli) run(a *cliArgs) (int, error) {
	// The command's config is the one every step of it reads and writes
	// (an apply's revert puts the earlier config back there).
	oldEnv, oldPath := c.s.Env.ConfigPath, c.s.sys().Paths.Config
	defer func() { c.s.Env.ConfigPath, c.s.sys().Paths.Config = oldEnv, oldPath }()
	c.s.Env.ConfigPath = a.config
	sys := c.s.sys()
	switch a.command {
	case "validate":
		cfg, _, err := apply.ReadConfig(a.config)
		if err != nil {
			return 0, err
		}
		c.println("OK: " + a.config + " is valid (" + strconv.Itoa(len(cfg.Rules)) + " rule(s))")
		return 0, nil
	case "render":
		cfg, _, err := apply.ReadConfig(a.config)
		if err != nil {
			return 0, err
		}
		script, err := nft.Build(cfg, nft.Options{Now: sys.Now()})
		if err != nil {
			return 0, err
		}
		fmt.Fprint(c.out, script)
		return 0, nil
	case "apply":
		return c.apply(a.config, a.flags["--dry-run"], a.flags["--fail-closed"], a.numbers["--confirm-within"])
	case "schedule-check":
		return c.scheduleCheck(a.config)
	case "dns-log-trim":
		trimmed, err := sys.TrimQueryLog()
		if err != nil {
			return 0, err
		}
		if trimmed {
			c.println(fmt.Sprintf("emptied %s (it was over %d bytes)", sys.Paths.DNSQueryLog, apply.QueryLogMaxBytes))
		}
		return 0, nil
	case "adblock-refresh":
		return c.adblockRefresh(a.config, a.flags["--scheduled"])
	case "ensure-accounts":
		done, err := sys.EnsureAccounts()
		var ae *apply.AccountsError
		var se *apply.StepError
		if errors.As(err, &ae) || errors.As(err, &se) {
			c.eprintln("error: " + err.Error())
			return 1, nil
		}
		if err != nil {
			return 0, err
		}
		for _, line := range done {
			c.println("fr-accounts: " + line)
		}
		c.println("fr-accounts: accounts and state directories in place")
		return 0, nil
	}
	if code, ok, err := c.firstBoot(a); ok {
		return code, err
	}
	return 2, nil
}

const baselineLoaded = "apply failed with no FR_OS ruleset loaded: fail-closed baseline loaded"

// failSafe is the boot's last line (security-lessons A3): never leave
// the box unfiltered because of a bad config or a missing NIC, but
// never replace a working ruleset either (nft -f is atomic, so a failed
// reload keeps the previous one). It returns the error to report.
func (c *cli) failSafe(err error) error {
	run := c.s.sys().Run
	if apply.TableLoaded(run) {
		return err
	}
	if lerr := apply.LoadBaseline(run); lerr != nil {
		return lerr
	}
	c.eprintln(baselineLoaded)
	return err
}

func (c *cli) apply(path string, dryRun, failClosed bool, within *int64) (int, error) {
	sys := c.s.sys()
	failClosed = failClosed && !dryRun
	if failClosed && !isRegular(path) {
		// Expected on a live image before first boot writes the config.
		if err := apply.LoadBaseline(sys.Run); err != nil {
			return 0, err
		}
		c.println("No config at " + path + ": fail-closed baseline loaded (only loopback and replies to the " +
			"router's own connections get in; nothing is forwarded)")
		return 0, nil
	}
	if failClosed {
		// ROADMAP SEC-26: the router restarted while an apply waited for
		// confirmation. A reboot is no confirmation: an admin cut off by
		// the apply may have power-cycled it to get it back.
		held, err := c.s.readHeld()
		if err == nil && held != nil {
			done, messages, err := c.bootRevert()
			if err != nil {
				return 0, c.failSafe(err)
			}
			if done {
				for _, m := range messages {
					c.println(m)
				}
				return 0, nil
			}
		}
	}
	if within != nil && (*within < config.ConfirmApplyMin || *within > config.ConfirmApplyMax) {
		c.eprintln(fmt.Sprintf("error: --confirm-within takes %d-%d seconds", config.ConfirmApplyMin,
			config.ConfirmApplyMax))
		return 1, nil
	}
	if dryRun || failClosed {
		return c.applyNow(path, dryRun, failClosed)
	}
	unlock, err := lockApply(c.s.lockPath())
	if err != nil {
		return 0, err
	}
	defer unlock()
	held, err := c.s.readHeld()
	if err != nil {
		return 0, err
	}
	if held != nil {
		c.eprintln("error: the last apply is waiting for confirmation (" +
			held.remaining(apply.NowSeconds(sys.Now())).String() + " s left): firewall-cli apply-confirm or " +
			"apply-revert first")
		return 1, nil
	}
	// ROADMAP SEC-27: only `firewall-cli management-addresses` (or the
	// webUI's) moves the webUI and SSH.
	cfg, _, err := apply.ReadConfig(path)
	if err != nil {
		return 0, err
	}
	if moved := sys.MovesManagement(cfg, sys.LoadAppliedConfig()); moved != "" {
		c.eprintln("error: nothing was applied -- " + moved + ", or here: firewall-cli management-addresses")
		return 1, nil
	}
	previous, hadPrevious := sys.AppliedConfigText()
	status, err := c.applyNow(path, false, false)
	if err != nil || status != 0 || within == nil {
		return status, err
	}
	cfg, text, err := apply.ReadConfig(path)
	if err != nil {
		return 0, err
	}
	if !hadPrevious || previous == text {
		c.println("Nothing to go back to (no earlier config applied, or the same one): not held for confirmation")
		return 0, nil
	}
	var reachable []string
	for _, a := range sys.ListenAddresses(cfg) {
		if a != render.Loopback {
			reachable = append(reachable, a)
		}
	}
	kept, err := c.s.beginHeld(previous, *within, "console", reachable)
	if err != nil {
		return 0, err
	}
	c.println("Confirm with `firewall-cli apply-confirm` within " + kept.Seconds.String() + " s, or the router " +
		"goes back to the config applied before this one")
	return 0, nil
}

// bootRevert reverts the apply left waiting when the router went down,
// under the lock; done false when it was confirmed or reverted meanwhile.
func (c *cli) bootRevert() (bool, []string, error) {
	unlock, err := lockApply(c.s.lockPath())
	if err != nil {
		return false, nil, err
	}
	defer unlock()
	held, err := c.s.readHeld()
	if err != nil || held == nil {
		return false, nil, err
	}
	messages, err := c.s.revert("the router restarted before it was confirmed", c.bootApply)
	return true, messages, err
}

// bootApply is the boot's revert of an unconfirmed apply: the config
// applied before it, as one transaction, and when that fails, as far as
// it goes, the ruleset first, like any config at boot.
func (c *cli) bootApply(cfg *config.Config, text string) ([]string, error) {
	sys := c.s.sys()
	messages, err := sys.ApplyAll(cfg, apply.Options{SourceText: &text})
	var ae *apply.Error
	if !errors.As(err, &ae) {
		return messages, err
	}
	c.eprintln("the config applied before the unconfirmed one failed at boot: " + err.Error())
	return sys.ApplyAll(cfg, apply.Options{LastResort: true})
}

func (c *cli) applyNow(path string, dryRun, failClosed bool) (int, error) {
	sys := c.s.sys()
	messages, err := func() ([]string, error) {
		cfg, text, err := apply.ReadConfig(path)
		if err != nil {
			return nil, err
		}
		messages, err := sys.ApplyAll(cfg, apply.Options{DryRun: dryRun, SourceText: &text})
		var ae *apply.Error
		if errors.As(err, &ae) && failClosed {
			messages, err = c.bootWithout(cfg, ae)
		}
		if err != nil {
			return nil, err
		}
		if !dryRun {
			// ROADMAP SEC-11: the parser daemons' copy without secrets,
			// also at boot.
			if problem := sys.RefreshSensorCopy(path); problem != "" {
				messages = append(messages, problem)
			}
		}
		return messages, nil
	}()
	if err != nil {
		if failClosed {
			return 0, c.failSafe(err)
		}
		return 0, err
	}
	for _, m := range messages {
		c.println(m)
	}
	return 0, nil
}

// bootWithout: config.yaml failed at boot and was rolled back (ROADMAP
// SEC-5). The router boots into the last config applied in full, if
// there is one and it is another config; and when that fails too, or
// there is none, config.yaml is applied as far as it goes, without a
// preflight or rollback, the ruleset first, so the router is filtered
// whatever fails after it. Either way it is a security alert.
func (c *cli) bootWithout(cfg *config.Config, failure *apply.Error) ([]string, error) {
	sys := c.s.sys()
	c.eprintln("config.yaml could not be applied: " + failure.Error())
	if last := sys.LoadAppliedConfig(); last != nil && !sameConfig(last, cfg) {
		messages, err := sys.ApplyAll(last, apply.Options{})
		var again *apply.Error
		switch {
		case errors.As(err, &again):
			c.eprintln("the last applied config could not be applied either: " + err.Error())
		case err != nil:
			return nil, err
		default:
			warning := "config.yaml could not be applied at boot, so the router runs the last config that was " +
				"applied in full: " + failure.Error()
			sys.Alert(warning, "boot", "boot")
			return append([]string{"WARNING: " + warning}, messages...), nil
		}
	}
	sys.Alert("config.yaml could not be applied at boot; applied as far as it goes: "+failure.Error(), "boot", "boot")
	return sys.ApplyAll(cfg, apply.Options{LastResort: true})
}

// sameConfig is 1.x's dataclass equality of two configs.
func sameConfig(a, b *config.Config) bool {
	fa, err1 := apply.ConfigFingerprint(a)
	fb, err2 := apply.ConfigFingerprint(b)
	return err1 == nil && err2 == nil && fa == fb
}

func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func (c *cli) scheduleCheck(path string) (int, error) {
	sys := c.s.sys()
	cfg, _, err := apply.ReadConfig(path)
	if err != nil {
		return 0, err
	}
	// Security-lessons K2: the same hourly run keeps the per-rule hit
	// record the rule check uses for "unused for 90 days".
	counters, err := sys.ReadCounters()
	if err == nil {
		names := make([]string, len(cfg.Rules))
		for i, r := range cfg.Rules {
			names[i] = r.Name
		}
		err = sys.RecordRuleHits(counters, names)
	}
	if err != nil {
		c.eprintln("rule hit counters not recorded: " + err.Error())
	}
	status, message, err := sys.CheckSchedule(cfg)
	if err != nil {
		return 0, err
	}
	c.println(message)
	switch status {
	case apply.ScheduleConfigChanged:
		return 1, nil
	case apply.ScheduleRefresh:
	default:
		return 0, nil
	}
	// ROADMAP SEC-26: never in the middle of an apply's revert, and with
	// config.yaml as it is after one.
	unlock, err := lockApply(c.s.lockPath())
	if err != nil {
		return 0, err
	}
	defer unlock()
	cfg, text, err := apply.ReadConfig(path)
	if err != nil {
		return 0, err
	}
	messages, err := sys.ApplyAll(cfg, apply.Options{SourceText: &text})
	if err != nil {
		return 0, err
	}
	for _, m := range messages {
		c.println(m)
	}
	return 0, nil
}

func (c *cli) adblockRefresh(path string, scheduled bool) (int, error) {
	sys := c.s.sys()
	cfg, _, err := apply.ReadConfig(path)
	if err != nil {
		return 0, err
	}
	// ROADMAP SEC-21, G11: the daily run fetches nothing the admin didn't
	// turn on; an admin's own run still fetches whenever lists are set.
	if scheduled && !cfg.Adblocker.Enabled {
		c.println("ad-blocking is off: nothing fetched")
		return 0, nil
	}
	r, err := sys.RefreshAdblock(cfg)
	var se *apply.StepError
	if errors.As(err, &se) {
		c.eprintln("error: " + err.Error())
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	c.println(r.Message)
	if len(r.FailedURLs) > 0 {
		list := make([]config.Value, len(r.FailedURLs))
		for i, u := range r.FailedURLs {
			list[i] = u
		}
		c.eprintln(fmt.Sprintf("warning: %d source(s) failed: %s", len(r.FailedURLs), config.Repr(list)))
	}
	return 0, nil
}
