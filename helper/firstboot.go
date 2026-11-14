package helper

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/webui"
)

// The commands first boot and its units run (fr-first-boot.sh,
// fr-initial-password, fr-console-ports, fr-persistence-setup), and the
// console's recovery paths for the webUI's accounts: each prints what
// 1.x's frfw.cli prints and exits as it does.

// firstBoot runs one of them; ok false when a.command is none of them.
func (c *cli) firstBoot(a *cliArgs) (code int, ok bool, err error) {
	sys := c.s.sys()
	switch a.command {
	case "detect-interfaces":
		return c.detectInterfaces(a.flags["--include-virtual"]), true, nil
	case "detect-wan-lan":
		code, err := c.detectWanLan()
		return code, true, err
	case "assign-interfaces":
		code, err := c.assignInterfaces(a)
		return code, true, err
	case "set-admin-password":
		code, err := c.setAdminPassword(a.values["--username"], a.flags["--generate"], a.flags["--show-on-console"])
		return code, true, err
	case "mfa-reset":
		code, err := c.mfaReset(a.positional["username"])
		return code, true, err
	case "initial-password":
		return 0, true, c.initialPassword()
	case "console-ports":
		switch {
		case a.flags["--print"]:
			fmt.Fprint(c.out, sys.ConsolePorts())
		case a.flags["--watch"]:
			return 0, true, sys.WatchConsolePorts()
		default:
			if _, err := sys.RefreshConsolePorts(); err != nil {
				return 0, true, err
			}
			c.println("fr-console-ports: wrote " + sys.Paths.PortsIssue)
		}
		return 0, true, nil
	case "persistence status":
		st := sys.Persistence()
		c.println("Persistence: " + st.Summary())
		if st.Live {
			boot := st.BootDevice
			if boot == "" {
				boot = "-"
			}
			c.println("  boot medium: " + boot)
			c.println("  'persistence' boot option: " + yesNo(st.Requested))
		}
		return 0, true, nil
	case "persistence auto":
		outcome, device, err := sys.PersistenceAuto()
		if err != nil {
			return 0, true, err
		}
		if device != "" {
			outcome += " (" + device + ")"
		}
		c.println("fr-persistence: " + outcome)
		if strings.HasPrefix(outcome, "created") {
			c.println("fr-persistence: rebooting once to start using it -- nothing has been configured yet, so nothing is lost")
			if a.flags["--reboot"] {
				sys.Run(apply.Cmd{Argv: []string{"systemctl", "reboot"}})
			}
		}
		return 0, true, nil
	case "persistence create":
		disk := a.positional["disk"]
		if !a.flags["--yes"] {
			c.eprintln("error: this erases " + disk + "; add --yes to confirm")
			return 1, true, nil
		}
		partition, err := sys.CreatePersistenceOnDisk(disk, a.flags["--wipe"])
		var pe *apply.PersistenceError
		if errors.As(err, &pe) {
			c.eprintln("error: " + err.Error())
			return 1, true, nil
		}
		if err != nil {
			return 0, true, err
		}
		c.println("Created the persistence filesystem on " + partition + ".")
		c.println("Reboot: FR_OS will keep its state there from the next boot on.")
		c.println("Note: what was changed during this boot is not copied over.")
		return 0, true, nil
	}
	return 0, false, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orQuestion(s *string) string {
	if s == nil || *s == "" {
		return "?"
	}
	return *s
}

func (c *cli) detectInterfaces(includeVirtual bool) int {
	ifaces := apply.ListInterfaces(c.s.sys().Paths.NetClass, includeVirtual)
	if len(ifaces) == 0 {
		c.println("No network interfaces detected")
		return 0
	}
	c.println(fmt.Sprintf("%-10s %-16s %-18s %-6s SPEED", "NAME", "DRIVER", "MAC", "LINK"))
	for _, i := range ifaces {
		link := "?"
		if i.Link != nil {
			link = "down"
			if *i.Link {
				link = "up"
			}
		}
		speed := "-"
		if i.SpeedMbps > 0 {
			speed = fmt.Sprintf("%dMb/s", i.SpeedMbps)
		}
		c.println(fmt.Sprintf("%-10s %-16s %-18s %-6s %s", i.Name, orQuestion(i.Driver), orQuestion(i.MAC), link, speed))
	}
	return 0
}

// detectWanLan is for fr-first-boot.sh: line 1 is "WAN LAN LAN-ADDRESS"
// (empty when there is no safe choice), line 2 says why (ROADMAP SEC-8).
// The LAN's address is outside the network the WAN's DHCP server offered
// (ROADMAP NET-12). Exit 1 without a choice.
func (c *cli) detectWanLan() (int, error) {
	sys := c.s.sys()
	net := sys.Paths.NetClass
	choice := apply.ChooseWanLan(apply.ListInterfaces(net, false), sys.DHCPOffer,
		func(device string) bool { return apply.HasLink(net, device) })
	if choice.Wan == "" || choice.Lan == "" {
		c.println("")
		c.println(choice.Basis)
		return 1, nil
	}
	var upstream []string
	if choice.WanNetwork != "" {
		upstream = append(upstream, choice.WanNetwork)
	}
	lanAddress, err := apply.LANAddressAvoiding(upstream)
	if err != nil {
		return 0, err
	}
	basis := choice.Basis
	if choice.WanNetwork != "" {
		basis += " (offering " + choice.WanNetwork + ")"
		if lanAddress != apply.DefaultLANAddress {
			basis += "; the LAN moved to " + lanAddress + ", out of its way"
		}
	}
	c.println(choice.Wan + " " + choice.Lan + " " + lanAddress)
	c.println(basis)
	return 0, nil
}

func (c *cli) assignInterfaces(a *cliArgs) (int, error) {
	var opts []apply.OptDevice
	for _, entry := range a.appends["--opt"] {
		zone, device, found := strings.Cut(entry, ":")
		if !found {
			c.eprintln("error: --opt expects ZONE:DEVICE, got " + config.Repr(entry))
			return 1, nil
		}
		replaced := false
		for i := range opts { // a dict: a zone named twice keeps its place, the last device
			if opts[i].Zone == zone {
				opts[i].Device, replaced = device, true
			}
		}
		if !replaced {
			opts = append(opts, apply.OptDevice{Zone: zone, Device: device})
		}
	}
	out, ok := a.values["--out"]
	if !ok {
		out = c.s.sys().Paths.Config
	}
	if _, err := os.Stat(out); err == nil && !a.flags["--force"] {
		c.eprintln("error: " + out + " already exists (use --force to overwrite)")
		return 1, nil
	}
	lanAddress, err := apply.IPv4Interface(a.values["--lan-address"])
	if err != nil {
		c.eprintln("error: --lan-address: " + err.Error())
		return 1, nil
	}
	text, err := apply.BuildSkeleton(a.values["--wan"], a.values["--lan"], opts, a.values["--hostname"], lanAddress)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o777); err != nil {
		return 0, err
	}
	if err := os.WriteFile(out, []byte(text), 0o666); err != nil {
		return 0, err
	}
	c.println("Wrote " + out)
	return 0, nil
}

func (c *cli) accounts() *webui.ConsoleAccounts {
	sys := c.s.sys()
	return webui.NewConsoleAccounts(sys.Paths.WebUIState, randReader(sys.Random), func() float64 {
		return float64(sys.Now().UnixNano()) / 1e9
	})
}

// randReader is the system's randomness as an io.Reader.
type randReader func([]byte) error

func (r randReader) Read(b []byte) (int, error) {
	if err := r(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *cli) setAdminPassword(username string, generate, show bool) (int, error) {
	sys := c.s.sys()
	accounts := c.accounts()
	if generate {
		// For fr-first-boot.sh: no prompts, and the only thing printed
		// is the password itself, so a caller can capture it -- or with
		// show, nothing secret at all.
		password := accounts.GeneratePassword()
		// The first sign-in then asks for the admin's own username and
		// password (security-lessons G1).
		if err := accounts.SetAdmin(username, password, true); err != nil {
			return 0, err
		}
		if !show {
			c.println(password)
			return 0, nil
		}
		if err := sys.WriteInitialPassword(username, password); err != nil {
			return 0, err
		}
		c.println("Generated a password for " + config.Repr(username) + "; it is shown on the console (" +
			sys.Paths.InitialIssue + ", root-only) until it is changed")
		return 0, nil
	}
	if show {
		c.eprintln("error: --show-on-console only goes with --generate")
		return 1, nil
	}
	ask := sys.Getpass
	password, err := ask("New password: ")
	if err != nil {
		return 0, err
	}
	confirm, err := ask("Confirm password: ")
	if err != nil {
		return 0, err
	}
	if password != confirm {
		c.eprintln("error: passwords do not match")
		return 1, nil
	}
	if weak := webui.PasswordProblem(password, username); weak != "" { // security-lessons G6
		c.eprintln("error: " + weak)
		return 1, nil
	}
	if err := accounts.SetAdmin(username, password, false); err != nil {
		return 0, err
	}
	// Security-lessons G9: what is done on the console shows up in the
	// webUI's security alerts like what is done in the webUI.
	sys.Alert("admin account "+config.Repr(username)+" set from the console (firewall-cli set-admin-password)",
		"console", "console")
	c.println("Admin account " + config.Repr(username) + " set")
	return 0, nil
}

func (c *cli) mfaReset(username string) (int, error) {
	err := c.accounts().ResetMFA(username)
	if webui.IsAccountError(err) {
		c.eprintln("error: " + err.Error())
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	c.s.sys().Alert("second factors of "+config.Repr(username)+" removed from the console (firewall-cli mfa-reset)",
		"console", "console")
	c.println("Second factors of " + config.Repr(username) + " removed; they sign in with the password alone until they add one")
	return 0, nil
}

// initialPassword is fr-initial-password.service: the generated password
// leaves the console as soon as it no longer signs in (changed in the
// webUI or with set-admin-password); a v0.1.0-style line in the
// world-readable /etc/issue moves to the root-only file first.
func (c *cli) initialPassword() error {
	sys := c.s.sys()
	moved, err := sys.MigrateLegacyInitialPassword()
	if err != nil {
		return err
	}
	if moved {
		c.println("fr-initial-password: moved the password line out of " + sys.Paths.Issue)
	}
	username, password, shown := sys.InitialLogin()
	if !shown {
		return nil
	}
	works, err := c.accounts().SignsIn(username, password)
	if err != nil {
		return err
	}
	if works {
		return nil
	}
	if err := sys.RemoveInitialLogin(); err != nil {
		return err
	}
	c.println("fr-initial-password: the initial password was changed; removed it from the console")
	return nil
}
