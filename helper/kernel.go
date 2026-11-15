package helper

import (
	"fmt"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/apply"
)

// The kernel commands (ROADMAP SEC-14): a kernel staged on the
// persistence partition, tried once at the next reboot and kept only if
// the router comes up on it (1.x's frfw.cli _cmd_kernel_*, held to its
// recorded runs in apply.jsonl, "cli/kernel/...").

const noKernelBootDir = "error: no persistence partition in use -- a kernel can only be staged on a live router " +
	"with persistence (firewall-cli persistence status)"

func (c *cli) kernel(a *cliArgs) (int, bool, error) {
	sys := c.s.sys()
	switch a.command {
	case "kernel status":
		st := sys.KernelStatus(true)
		c.println("Kernel: " + st.Summary())
		if dir, ok := sys.KernelBootDir(); ok && st.State != "" {
			files := apply.StagedFiles(dir)
			names := make([]string, 0, len(files))
			for n := range files {
				names = append(names, n)
			}
			slices.Sort(names)
			for _, n := range names {
				c.println("  " + n + ": sha256 " + files[n])
			}
		}
		return 0, true, nil
	case "kernel stage":
		dir, ok := sys.KernelBootDir()
		if !ok {
			c.eprintln(noKernelBootDir)
			return 1, true, nil
		}
		version := a.values["--version"]
		// ROADMAP SEC-23: what works now must work again on its trial boot.
		expect := sys.CurrentExpectations()
		if err := sys.StageKernel(a.positional["kernel"], a.positional["initrd"], version, dir, expect); err != nil {
			c.eprintln("error: " + err.Error())
			return 1, true, nil
		}
		// Security-lessons G9: what boots the router is the most
		// valuable thing to change.
		sys.Alert("kernel "+version+" staged: the next reboot tries it once (firewall-cli kernel stage)",
			"console", "console")
		c.println("Kernel " + version + " staged. The router does not reboot by itself: the next reboot tries it once,")
		c.println("and keeps it only if the router comes up on it; otherwise the image's own kernel boots again.")
		return 0, true, nil
	case "kernel unstage":
		dir, ok := sys.KernelBootDir()
		if !ok {
			c.eprintln(noKernelBootDir)
			return 1, true, nil
		}
		removed, err := apply.UnstageKernel(dir)
		if err != nil {
			return 0, true, err
		}
		if !removed {
			c.println("Nothing was staged.")
			return 0, true, nil
		}
		sys.Alert("staged kernel removed: the image's own kernel boots from the next reboot (firewall-cli kernel "+
			"unstage)", "console", "console")
		c.println("Staged kernel removed: the image's own kernel boots from the next reboot.")
		return 0, true, nil
	case "kernel confirm-boot":
		// Never fails the unit and never reboots, but for the one case
		// the design asks for: a trial boot the router didn't come up on.
		dir, ok := sys.KernelBootDir()
		if !ok {
			c.println("fr-kernel: no persistence partition in use; nothing to confirm")
			return 0, true, nil
		}
		outcome, err := sys.ConfirmBoot(dir)
		if err != nil {
			c.println(fmt.Sprintf("fr-kernel: could not check this boot: %v", err))
			return 0, true, nil
		}
		c.println("fr-kernel: " + outcome.Message)
		if outcome.Alert != "" {
			sys.Alert(outcome.Alert, "fr-kernel-confirm", "boot")
		}
		if outcome.Reboot {
			_, _ = sys.Run(apply.Cmd{Argv: []string{"systemctl", "reboot"}})
		}
		return 0, true, nil
	case "kernel prepare":
		return c.kernelPrepare(a)
	case "kernel try":
		dir, ok := sys.KernelBootDir()
		if !ok {
			c.eprintln(noKernelBootDir)
			return 1, true, nil
		}
		version, err := sys.TryPreparedKernel(dir)
		if err != nil {
			if !apply.KernelCaught(err) {
				return 0, true, err
			}
			c.eprintln("error: " + apply.KernelErrorText(err))
			return 1, true, nil
		}
		sys.Alert("kernel "+version+" staged for its trial boot (firewall-cli kernel try)", "console", "console")
		if a.flags["--no-reboot"] {
			c.println("Kernel " + version + " staged: the next reboot tries it once.")
			return 0, true, nil
		}
		c.println("Kernel " + version + " staged: rebooting into its trial.")
		_, _ = sys.Run(apply.Cmd{Argv: []string{"systemctl", "reboot"}})
		return 0, true, nil
	}
	return 0, strings.HasPrefix(a.command, "kernel "), nil
}

// kernelPrepare is fr-kernel-prepare.service: Debian's newer kernel
// installed and its initrd made, ready for the admin to try (ROADMAP
// SEC-14, step 3). It never stages and never reboots.
func (c *cli) kernelPrepare(a *cliArgs) (int, bool, error) {
	sys := c.s.sys()
	dir, ok := sys.KernelBootDir()
	if !ok {
		c.println("fr-kernel: no persistence partition in use; nothing to prepare")
		return 0, true, nil
	}
	path, given := a.values["--config"]
	if !given {
		path = sys.Paths.Config
	}
	enabled := true // no or a broken config: the default
	if cfg, _, err := apply.ReadConfig(path); err == nil {
		enabled = cfg.Update.KernelUpdates
	}
	version, given := a.values["--version"]
	outcome, err := sys.PrepareKernel(version, given, enabled, dir)
	if err != nil {
		if !apply.KernelCaught(err) {
			return 0, true, err
		}
		text := apply.KernelErrorText(err)
		_ = sys.RecordKernelCheck(text, true)
		c.println("fr-kernel: could not prepare a kernel: " + text)
		return 1, true, nil
	}
	if err := sys.RecordKernelCheck(outcome.Message, false); err != nil {
		return 0, true, err
	}
	c.println("fr-kernel: " + outcome.Message)
	if outcome.Alert != "" {
		sys.Alert(outcome.Alert, "fr-kernel-prepare", "timer")
	}
	return 0, true, nil
}
