package apply

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The accounts FR_OS runs as and the group they share (frfw.accounts):
// fr_os-webui runs the webUI, fr_os-sensor the daemons that parse
// untrusted traffic, and fr_os-feeds is the one group the two share
// (the helper's socket, the SNI event file, the resolver's query log).
// fr_os-sensor is never in fr_os-webui's group, which reads config.yaml
// with its secrets (ROADMAP SEC-11, review v0.2.0 R17).
const (
	FeedsGroup = "fr_os-feeds"
	nologin    = "/usr/sbin/nologin"
)

// AccountsError is a program ensure-accounts runs failing (1.x's
// AccountsError).
type AccountsError struct{ Msg string }

func (e *AccountsError) Error() string { return e.Msg }

// NoAccountError is a lookup of an account that does not exist where
// 1.x's pwd/grp raise KeyError: firewall-cli dies on it.
type NoAccountError struct{ Name string }

func (e *NoAccountError) Error() string { return config.Repr(e.Name) }

// Kind is the exception's name.
func (e *NoAccountError) Kind() string { return "KeyError" }

func lookupUser(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	uid, err := strconv.Atoi(u.Uid)
	return uid, err == nil
}

func lookupGroup(name string) (int, []string, bool) {
	gid, ok := groupOf(name)
	if !ok {
		return 0, nil, false
	}
	members, _ := groupMembers(name)
	return gid, members, true
}

// accountRun runs one of useradd, groupadd, usermod and gpasswd.
func (s *System) accountRun(argv ...string) error {
	res, err := s.Run(Cmd{Argv: argv})
	if errors.Is(err, ErrNotFound) {
		return &AccountsError{argv[0] + " not found"}
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		out := res.Stderr
		if out == "" {
			out = res.Stdout
		}
		return &AccountsError{strings.Join(argv, " ") + " failed: " + config.PyStrip(out)}
	}
	return nil
}

func (s *System) hasMember(group, name string) bool {
	_, members, ok := s.Group(group)
	return ok && containsString(members, name)
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// EnsureAccounts is firewall-cli ensure-accounts (fr-accounts.service,
// which every unit running as one of these accounts pulls in): what is
// missing is created, and what was done is returned for the log. It is
// idempotent.
func (s *System) EnsureAccounts() ([]string, error) {
	var done []string
	for _, name := range []string{WebUIUser, SensorUser} {
		if _, ok := s.User(name); ok {
			continue
		}
		if err := s.accountRun("useradd", "--system", "--user-group", "--no-create-home", "--shell", nologin,
			"--", name); err != nil {
			return nil, err
		}
		done = append(done, "created user "+name)
	}
	if _, _, ok := s.Group(FeedsGroup); !ok {
		if err := s.accountRun("groupadd", "--system", "--", FeedsGroup); err != nil {
			return nil, err
		}
		done = append(done, "created group "+FeedsGroup)
	}
	for _, name := range []string{WebUIUser, SensorUser} {
		if s.hasMember(FeedsGroup, name) {
			continue
		}
		if err := s.accountRun("usermod", "--append", "--groups", FeedsGroup, "--", name); err != nil {
			return nil, err
		}
		done = append(done, "added "+name+" to group "+FeedsGroup)
	}
	// ROADMAP SEC-11: an earlier version put the sensor account in the
	// webUI's group; a router updated from it loses that here, at boot,
	// before any sensor daemon starts.
	if s.hasMember(WebUIUser, SensorUser) {
		if err := s.accountRun("gpasswd", "--delete", SensorUser, WebUIUser); err != nil {
			return nil, err
		}
		done = append(done, "removed "+SensorUser+" from group "+WebUIUser)
	}
	moved, err := s.regroupFeeds()
	if err != nil {
		return nil, err
	}
	done = append(done, moved...)
	if _, _, ok := s.Group(render.SSHGroup); !ok {
		// sshd's AllowGroups: empty until the admin adds someone, so no
		// SSH login at all by default.
		if err := s.accountRun("groupadd", "--system", "--", render.SSHGroup); err != nil {
			return nil, err
		}
		done = append(done, "created group "+render.SSHGroup)
	}
	if err := os.MkdirAll(filepath.Dir(s.Paths.Config), 0o755); err != nil {
		return nil, pyOSError(err)
	}
	dirs := []struct {
		path        string
		mode        fs.FileMode
		user, group string
	}{
		{s.Paths.WebUIState, 0o700, WebUIUser, WebUIUser},
		{s.Paths.SensorState, 0o750, SensorUser, WebUIUser},
		// The audit log is root's; the webUI reads it (G9/E6).
		{filepath.Dir(s.Paths.AuditLog), 0o750, "root", WebUIUser},
	}
	for _, d := range dirs {
		if err := s.ensureDir(d.path, d.mode, d.user, d.group); err != nil {
			return nil, err
		}
	}
	return done, nil
}

// regroupFeeds moves the feeds an earlier version made with the webUI's
// group, and the live helper socket (whose unit names the new group, but
// which keeps its group until the unit restarts), to fr_os-feeds. Mode
// untouched; a symlink is left alone.
func (s *System) regroupFeeds() ([]string, error) {
	gid, _, ok := s.Group(FeedsGroup)
	if !ok {
		return nil, nil
	}
	var done []string
	for _, path := range []string{filepath.Dir(s.Paths.SNIEvents), s.Paths.SNIEvents,
		filepath.Dir(s.Paths.DNSQueryLog), s.Paths.DNSQueryLog, s.Paths.ApplySocket} {
		st, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, pyOSError(err)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Gid) == gid {
			continue
		}
		if err := s.Chown(path, -1, gid); err != nil {
			return nil, pyOSError(err)
		}
		done = append(done, "moved "+path+" to group "+FeedsGroup)
	}
	return done, nil
}

func (s *System) ensureDir(path string, mode fs.FileMode, owner, group string) error {
	if err := os.MkdirAll(path, 0o777); err != nil {
		return pyOSError(err)
	}
	uid, ok := s.User(owner)
	if !ok {
		return &NoAccountError{owner}
	}
	gid, _, ok := s.Group(group)
	if !ok {
		return &NoAccountError{group}
	}
	if err := s.Chown(path, uid, gid); err != nil {
		return pyOSError(err)
	}
	return pyOSError(os.Chmod(path, mode))
}
