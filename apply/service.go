package apply

import (
	"errors"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// ServiceState is whether a unit was running (frfw.transaction.
// ServiceState). Known is false when that couldn't be told (no systemd);
// then nothing is done to it on undo.
type ServiceState struct {
	Unit          string
	Known, Active bool
}

// CaptureService asks systemd.
func CaptureService(run Runner, unit string) (ServiceState, error) {
	res, err := Systemctl(run, "is-active", unit, 30*time.Second)
	if noSystemd(err) {
		return ServiceState{Unit: unit}, nil
	}
	if err != nil {
		return ServiceState{}, err
	}
	switch strings.TrimSpace(res.Stdout) {
	case "active", "activating", "reloading":
		return ServiceState{unit, true, true}, nil
	}
	return ServiceState{unit, true, false}, nil
}

// Restore puts the unit back: running (re-reading its restored config
// with how, "restart" or "reload-or-restart", when configChanged) or
// stopped.
func (s ServiceState) Restore(run Runner, configChanged bool, how string) error {
	if !s.Known {
		return nil
	}
	action := "start"
	if s.Active {
		if configChanged {
			action = how
		}
	} else {
		now, err := CaptureService(run, s.Unit)
		if err != nil {
			return err
		}
		if now.Known && !now.Active {
			return nil
		}
		action = "stop"
	}
	return systemctlOK(run, action, s.Unit)
}

func systemctlOK(run Runner, action, unit string) error {
	res, err := Systemctl(run, action, unit, 60*time.Second)
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return errors.New(msg)
		}
		return errors.New("systemctl " + action + " " + unit + " failed")
	}
	return nil
}

// Enabled is whether unit starts at boot; known is false when that can't
// be told.
func Enabled(run Runner, unit string) (enabled, known bool, err error) {
	res, err := Systemctl(run, "is-enabled", unit, 30*time.Second)
	if noSystemd(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	switch strings.TrimSpace(res.Stdout) {
	case "enabled", "enabled-runtime":
		return true, true, nil
	case "disabled", "masked":
		return false, true, nil
	}
	return false, false, nil
}

// SetEnabled enables or disables unit, unless it already is so or known
// is false.
func SetEnabled(run Runner, unit string, enabled, known bool) error {
	if !known {
		return nil
	}
	now, nowKnown, err := Enabled(run, unit)
	if err != nil {
		return err
	}
	if nowKnown && now == enabled {
		return nil
	}
	action := "disable"
	if enabled {
		action = "enable"
	}
	return systemctlOK(run, action, unit)
}
