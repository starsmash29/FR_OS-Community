package helper

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The commands that change the system: apply, its confirmation and
// revert (ROADMAP SEC-26, frfw.apply_confirm), rollback and save_config.

// PendingError is an apply that can't be held, confirmed or reverted.
type PendingError struct{ Msg string }

func (e *PendingError) Error() string { return e.Msg }

// sys is the system the commands act on: Env.Sys, its paths those the
// helper was started with, its live-set reader the helper's own.
func (s *Server) sys() *apply.System {
	sys := s.Env.Sys
	if sys == nil {
		sys = apply.DefaultSystem()
		s.Env.Sys = sys
	}
	p := &sys.Paths
	if s.Env.ConfigPath != "" {
		p.Config = s.Env.ConfigPath
	}
	if s.Env.BackupDir != "" {
		p.BackupDir = s.Env.BackupDir
	}
	if s.Env.KeaConfigPath != "" {
		p.KeaConfig = s.Env.KeaConfigPath
	}
	if s.Env.ApplyPendingPath != "" {
		p.ApplyPending = s.Env.ApplyPendingPath
	}
	if s.Env.RejectedConfigPath != "" {
		p.RejectedConfig = s.Env.RejectedConfigPath
	}
	if sys.ReadRuntime == nil {
		sys.ReadRuntime = s.ReadRuntime
	}
	return sys
}

// lockApply takes the one lock an apply, its confirmation and its revert
// share (flock), across the helper, the revert unit and the boot: a
// confirmation can't land halfway through a revert.
func lockApply(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// heldApply is the pending record with what only root sees: the text of
// the config applied before it.
type heldApply struct {
	*pending
	deadline float64
	previous string
}

func (s *Server) readHeld() (*heldApply, error) {
	p, deadline, previous, err := readPendingFull(s.sys().Paths.ApplyPending)
	if err != nil || p == nil {
		return nil, err
	}
	return &heldApply{p, deadline, previous}, nil
}

// remaining is max(0, int(deadline - now + 0.999)).
func (h *heldApply) remaining(now float64) *big.Int {
	left, err := truncFloat(h.deadline - now + 0.999)
	if err != nil || left.Sign() < 0 {
		return big.NewInt(0)
	}
	return left
}

// public is what the webUI may see: never the previous config.
func (h *heldApply) public(now float64) *pending {
	p := *h.pending
	p.Remaining = h.remaining(now)
	return &p
}

// beginHeld records a pending apply and starts the unit that waits for
// its deadline. The caller holds the lock and has just applied.
func (s *Server) beginHeld(previous string, seconds int64, by string, addresses []string) (*heldApply, error) {
	sys := s.sys()
	id := make([]byte, 8)
	if err := sys.Random(id); err != nil {
		return nil, err
	}
	deadline := apply.NowSeconds(sys.Now()) + float64(seconds)
	list := make([]config.Value, len(addresses))
	for i, a := range addresses {
		list[i] = a
	}
	m := config.NewMap()
	m.Set("id", hex.EncodeToString(id))
	m.Set("deadline", deadline)
	m.Set("seconds", big.NewInt(seconds))
	m.Set("by", by)
	m.Set("addresses", list)
	m.Set("previous", previous)
	text, err := config.PyJSON(m, -1, false)
	if err != nil {
		return nil, err
	}
	record := sys.Paths.ApplyPending
	if err := apply.WritePrivate(record, text); err != nil {
		return nil, err
	}
	if err := s.startWaiting(); err != nil {
		// Nothing would ever revert it: an apply that can't be held isn't.
		os.Remove(record)
		return nil, err
	}
	return &heldApply{&pending{ID: hex.EncodeToString(id), Seconds: big.NewInt(seconds), By: by,
		Addresses: append([]string{}, addresses...)}, deadline, previous}, nil
}

// startWaiting restarts, not starts, the revert unit: one still waiting
// on a confirmed apply would otherwise make the start a no-op, then exit.
func (s *Server) startWaiting() error {
	res, err := apply.Systemctl(s.sys().Run, "restart", apply.RevertUnit, 30*time.Second)
	if errors.Is(err, apply.ErrNotFound) {
		return &PendingError{"could not start " + apply.RevertUnit + ": [Errno 2] No such file or directory: 'systemctl'"}
	}
	if err != nil {
		return &PendingError{"could not start " + apply.RevertUnit + ": " + err.Error()}
	}
	if res.Code != 0 {
		return &PendingError{"could not start " + apply.RevertUnit + ": " + config.PyStrip(res.Stderr)}
	}
	return nil
}

// confirmHeld keeps the pending apply. Only its own id confirms it, so a
// stale page can't confirm a later apply.
func (s *Server) confirmHeld(id string) error {
	held, err := s.readHeld()
	if err != nil {
		return err
	}
	if held == nil {
		return &PendingError{"No apply is waiting for confirmation (it may have been reverted already)"}
	}
	if subtle.ConstantTimeCompare([]byte(id), []byte(held.ID)) != 1 {
		return &PendingError{"That is not the apply waiting for confirmation -- reload the page"}
	}
	return removeMissingOK(s.sys().Paths.ApplyPending)
}

// Revert goes back to the config applied before the pending apply: it is
// applied again (a transaction, so a failure there is rolled back too),
// config.yaml goes back to it, so neither the next Apply nor a boot
// brings the unconfirmed config back, and the unconfirmed one is kept
// for the admin to fix. Every revert is a security alert. The caller
// holds the lock.
func (s *Server) Revert(why string) ([]string, error) {
	return s.revert(why, func(c *config.Config, text string) ([]string, error) {
		return s.sys().ApplyAll(c, apply.Options{SourceText: &text})
	})
}

// revert is Revert, the previous config applied by applyPrevious (the
// boot's own, firewall-cli apply --fail-closed, falls back to applying
// it as far as it goes).
func (s *Server) revert(why string, applyPrevious func(c *config.Config, text string) ([]string, error)) ([]string, error) {
	sys := s.sys()
	p := sys.Paths
	held, err := s.readHeld()
	if err != nil {
		return nil, err
	}
	if held == nil {
		return nil, &PendingError{"No apply is waiting for confirmation"}
	}
	previous, perr := parsePrevious(held.previous)
	if perr != nil {
		// Nothing to go back to: the router keeps the applied config, and
		// nothing is left pending that no one could ever resolve.
		removeMissingOK(p.ApplyPending)
		warning := "The apply was not confirmed (" + why + "), but the config applied before it is no longer valid (" +
			perr.Error() + "): the router keeps the one applied"
		sys.Alert(warning, "system", "apply-confirm")
		return []string{warning}, nil
	}
	var messages []string
	failure := ""
	result, err := applyPrevious(previous, held.previous)
	var ae *apply.Error
	switch {
	case errors.As(err, &ae):
		failure = ae.Error()
	case err != nil:
		return nil, err
	default:
		messages = result
	}
	if unconfirmed, err := os.ReadFile(p.Config); err == nil && string(unconfirmed) != held.previous {
		if err := writeLike(sys, p.RejectedConfig, string(unconfirmed), p.Config); err != nil {
			return nil, err
		}
	}
	if err := apply.WriteKeepingOwner(p.Config, held.previous); err != nil {
		return nil, err
	}
	sys.RefreshSensorCopy(p.Config)
	removeMissingOK(p.ApplyPending)
	who := ""
	if held.By != "" {
		who = " by " + held.By
	}
	var warning string
	if failure == "" {
		warning = "The apply" + who + " was not confirmed (" + why + "): the router went back to the config applied " +
			"before it. The unconfirmed config is kept -- load it from the dashboard to fix it."
	} else {
		warning = "The apply" + who + " was not confirmed (" + why + "), and going back to the config applied before it " +
			"failed: " + failure + ". config.yaml is that config again, so a reboot applies it."
	}
	sys.Alert(warning, "system", "apply-confirm")
	return append([]string{warning}, messages...), nil
}

func parsePrevious(text string) (*config.Config, error) {
	raw, err := config.LoadYAML(text)
	if err != nil {
		return nil, err
	}
	return config.Parse(raw)
}

// writeLike writes path with like's owner and mode: it holds what
// config.yaml holds.
func writeLike(sys *apply.System, path, text, like string) error {
	if err := apply.WriteKeepingOwner(path, text); err != nil {
		return err
	}
	st, err := os.Stat(like)
	if err != nil {
		return nil
	}
	if sys.Euid() == 0 {
		owner := st.Sys().(*syscall.Stat_t)
		if err := sys.Chown(path, int(owner.Uid), int(owner.Gid)); err != nil {
			return err
		}
	}
	return os.Chmod(path, st.Mode().Perm())
}

// Wait is fr-apply-revert.service: wait for the pending apply's deadline
// and revert it, unless it is confirmed (or reverted) first. The record
// is read again every second, so a confirmation ends the wait within
// one.
func (s *Server) Wait() ([]string, error) {
	sys := s.sys()
	for {
		unlock, err := lockApply(s.lockPath())
		if err != nil {
			return nil, err
		}
		held, err := s.readHeld()
		if err != nil || held == nil {
			unlock()
			if err != nil {
				return nil, err
			}
			return []string{"Nothing waiting for confirmation"}, nil
		}
		left := held.deadline - apply.NowSeconds(sys.Now())
		if left <= 0 {
			messages, err := s.Revert("no confirmation within " + held.Seconds.String() + " s")
			unlock()
			return messages, err
		}
		unlock()
		wait := time.Duration(left * float64(time.Second))
		if poll := sys.ConfirmPoll; poll > 0 && wait > poll {
			wait = poll
		}
		sys.Sleep(wait)
	}
}

// restoreRejected loads the unconfirmed config back into config.yaml,
// for the admin to fix and apply again.
func (s *Server) restoreRejected() (string, error) {
	sys := s.sys()
	p := sys.Paths
	held, err := s.readHeld()
	if err != nil {
		return "", err
	}
	if held != nil {
		return "", &PendingError{"Confirm or revert the pending apply first"}
	}
	data, err := os.ReadFile(p.RejectedConfig)
	if errors.Is(err, os.ErrNotExist) {
		return "", &PendingError{"There is no unconfirmed config to load"}
	}
	if err != nil {
		return "", err
	}
	text := string(data)
	if _, err := parsePrevious(text); err != nil { // still a valid config for this version
		return "", err
	}
	if err := apply.WriteKeepingOwner(p.Config, text); err != nil {
		return "", err
	}
	sys.RefreshSensorCopy(p.Config)
	removeMissingOK(p.RejectedConfig)
	return "The unconfirmed config is in " + p.Config + " again: fix it, then Apply", nil
}

func (s *Server) lockPath() string {
	if s.Env.ApplyLockPath != "" {
		return s.Env.ApplyLockPath
	}
	return s.sys().Paths.ApplyLock
}

func removeMissingOK(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// --- the commands ------------------------------------------------------------------

// applyReply is {"ok", "message"} and, for an apply held for
// confirmation, "pending".
type applyReply struct {
	OK      bool     `json:"ok"`
	Message string   `json:"message"`
	Pending *pending `json:"pending,omitempty"`
}

// commandError is 1.x's answer to an error its request handler catches:
// the error's text.
func commandError(err error) (any, error) {
	var bad invalidRequest
	if errors.As(err, &bad) || errors.Is(err, errNoReply) {
		return nil, err
	}
	return message(false, err.Error()), nil
}

// userOf is str(request.get("user") or "")[:64].
func userOf(request *config.Map) string {
	u, _ := request.Get("user")
	if !config.Truthy(u) {
		return ""
	}
	r := []rune(config.Str(u))
	if len(r) > 64 {
		r = r[:64]
	}
	return string(r)
}

// cmdApply applies config.yaml. Asked with `confirm` (the webUI's Apply),
// a successful apply is held until the admin confirms it, and the router
// goes back by itself otherwise (ROADMAP SEC-26).
func (s *Server) cmdApply(request *config.Map) (any, error) {
	sys := s.sys()
	c, text, err := apply.ReadConfig(sys.Paths.Config)
	if err != nil {
		return commandError(err)
	}
	if dry, _ := request.Get("dry_run"); config.Truthy(dry) {
		if err := s.refuseMovingManagement(c); err != nil {
			return commandError(err)
		}
		messages, err := sys.ApplyAll(c, apply.Options{DryRun: true, SourceText: &text})
		if err != nil {
			return commandError(err)
		}
		return message(true, strings.Join(messages, "; ")), nil
	}
	unlock, err := lockApply(s.lockPath())
	if err != nil {
		return commandError(err)
	}
	defer unlock()
	confirm, _ := request.Get("confirm")
	return s.applyLocked(c, text, config.Truthy(confirm), userOf(request))
}

// refuseMovingManagement (ROADMAP SEC-27): only the webUI address
// setting moves the webUI and SSH -- never the side effect of another
// change.
func (s *Server) refuseMovingManagement(c *config.Config) error {
	sys := s.sys()
	if moved := sys.MovesManagement(c, sys.LoadAppliedConfig()); moved != "" {
		return &apply.Error{Step: "the webUI address", Cause: errors.New(moved)}
	}
	return nil
}

func (s *Server) applyLocked(c *config.Config, text string, confirm bool, user string) (any, error) {
	sys := s.sys()
	held, err := s.readHeld()
	if err != nil {
		return commandError(err)
	}
	now := apply.NowSeconds(sys.Now())
	if held != nil {
		return message(false, "The last apply is waiting for confirmation ("+held.remaining(now).String()+
			" s left): confirm it or go back before applying again"), nil
	}
	if err := s.refuseMovingManagement(c); err != nil {
		return commandError(err)
	}
	previous, hadPrevious := sys.AppliedConfigText()
	messages, err := sys.ApplyAll(c, apply.Options{SourceText: &text})
	if err != nil {
		return commandError(err)
	}
	var kept *heldApply
	seconds := c.Management.ConfirmApplySeconds
	if confirm && seconds > 0 && hadPrevious && previous != text {
		// Where the admin can reach the webUI now: loopback is no one's
		// way in.
		var reachable []string
		for _, a := range sys.ListenAddresses(c) {
			if a != render.Loopback {
				reachable = append(reachable, a)
			}
		}
		kept, err = s.beginHeld(previous, seconds, user, reachable)
		var pe *PendingError
		switch {
		case errors.As(err, &pe):
			messages = append([]string{"Applied, but not held for confirmation: " + pe.Msg}, messages...)
		case err != nil:
			return commandError(err)
		default:
			messages = append([]string{fmt.Sprintf("Applied -- confirm it within %d s, or the router goes back to "+
				"the config applied before it", seconds)}, messages...)
		}
	}
	if problem := sys.RefreshSensorCopy(sys.Paths.Config); problem != "" {
		messages = append(messages, problem)
	}
	r := applyReply{OK: true, Message: strings.Join(messages, "; ")}
	if kept != nil {
		r.Pending = kept.public(apply.NowSeconds(sys.Now()))
	}
	return r, nil
}

func (s *Server) withLock(f func() (any, error)) (any, error) {
	unlock, err := lockApply(s.lockPath())
	if err != nil {
		return commandError(err)
	}
	defer unlock()
	return f()
}

func (s *Server) cmdApplyConfirm(request *config.Map) (any, error) {
	return s.withLock(func() (any, error) {
		id, _ := request.Get("id")
		text := ""
		if config.Truthy(id) {
			text = config.Str(id)
		}
		if err := s.confirmHeld(text); err != nil {
			return commandError(err)
		}
		return message(true, "Apply confirmed: the router keeps this config"), nil
	})
}

func (s *Server) cmdApplyRevert() (any, error) {
	return s.withLock(func() (any, error) {
		messages, err := s.Revert("the admin went back")
		if err != nil {
			return commandError(err)
		}
		return message(true, messages[0]), nil
	})
}

func (s *Server) cmdRestoreRejected() (any, error) {
	return s.withLock(func() (any, error) {
		text, err := s.restoreRejected()
		if err != nil {
			return commandError(err)
		}
		return message(true, text), nil
	})
}

func (s *Server) cmdRollback() (any, error) {
	sys := s.sys()
	restored, err := apply.RollbackLast(sys.Run, sys.Paths.BackupDir)
	if err != nil {
		return commandError(err)
	}
	return message(true, "Rolled back to "+restored), nil
}

// cmdSaveConfig checks a config before writing anything, then writes
// config.yaml (its owner and mode kept) and the parser daemons' copy,
// without secrets: they re-read it, so a change reaches them without an
// apply (ROADMAP SEC-11).
func (s *Server) cmdSaveConfig(request *config.Map) (any, error) {
	sys := s.sys()
	v, _ := request.Get("yaml")
	text, ok := v.(string)
	if !ok {
		return message(false, "'yaml' must be a string"), nil
	}
	raw, err := config.LoadYAML(text)
	if err != nil {
		return commandError(err)
	}
	if _, err := config.Parse(raw); err != nil {
		return commandError(err)
	}
	if err := apply.WriteKeepingOwner(sys.Paths.Config, text); err != nil {
		return commandError(err)
	}
	reply := "Config saved to " + sys.Paths.Config
	if err := sys.WriteSensorCopy(raw); err != nil {
		reply += "; could not refresh the sensors' config copy: " + err.Error()
	}
	return message(true, reply), nil
}
