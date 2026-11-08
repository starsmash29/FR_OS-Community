package apply

import (
	"errors"
	"strings"
	"time"
)

// bootingStates are `systemctl is-system-running`'s answers while systemd
// still works through the boot transaction.
var bootingStates = map[string]bool{"initializing": true, "starting": true}

// SystemIsBooting reports whether the boot is still running.
func SystemIsBooting(run Runner) bool {
	res, err := run(Cmd{Argv: []string{"systemctl", "is-system-running"}, Timeout: 10 * time.Second})
	return err == nil && bootingStates[strings.TrimSpace(res.Stdout)]
}

// Systemctl is `systemctl ACTION -- UNIT` (frfw.svc.systemctl). While the
// system boots the job is only queued (--no-block): fr-firewall applies
// the config early in the boot, and waiting there for a unit systemd
// ordered after it hangs the boot forever (found booting the image in
// QEMU). Its config was already checked (kea-dhcp4 -t, sshd -t, dnsmasq
// --test). Once the system is up the call waits, so a service that
// doesn't come back is reported. ErrNotFound: no systemctl.
func Systemctl(run Runner, action, unit string, timeout time.Duration) (Result, error) {
	a, err := SystemctlAction(action)
	if err != nil {
		return Result{}, err
	}
	u, err := SystemdUnit(unit)
	if err != nil {
		return Result{}, err
	}
	argv := []string{"systemctl", a, "--", u}
	if SystemIsBooting(run) {
		argv = []string{"systemctl", "--no-block", a, "--", u}
	}
	return run(Cmd{Argv: argv, Timeout: timeout})
}

// noSystemd: the call couldn't tell (no systemctl, or it timed out).
func noSystemd(err error) bool { return errors.Is(err, ErrNotFound) || errors.Is(err, ErrTimeout) }
