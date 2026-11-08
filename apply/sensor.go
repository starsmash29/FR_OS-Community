package apply

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// --- the parser daemons' config copy (frfw.config.export, ROADMAP SEC-11) -----------

// Removed stands for a ZTNA password hash in an export: an imported user
// with it can't sign in until given a new password.
const Removed = "<removed on export: set a new password>"

// SensorCopyHeader heads the copy.
const SensorCopyHeader = "# Generated from config.yaml without its secrets, for the parser daemons\n" +
	"# (ROADMAP SEC-11). Rewritten on every save and apply: edit config.yaml.\n"

// Redacted is raw without its secrets (security-lessons G3): the ZTNA
// users' password hashes and the /metrics token digest. raw is not
// changed.
func Redacted(raw config.Value) *config.Map {
	m, ok := raw.(*config.Map)
	if !ok {
		return config.NewMap()
	}
	out := deepCopy(m).(*config.Map)
	if z, _ := out.Get("ztna"); z != nil {
		if ztna, ok := z.(*config.Map); ok {
			if u, _ := ztna.Get("users"); config.Truthy(u) {
				if users, ok := u.([]config.Value); ok {
					for _, user := range users {
						if um, ok := user.(*config.Map); ok && um.Has("password_hash") {
							um.Set("password_hash", Removed)
						}
					}
				}
			}
		}
	}
	if mv, _ := out.Get("metrics"); mv != nil {
		if metrics, ok := mv.(*config.Map); ok && metrics.Has("token_sha256") {
			out.Set("metrics", withoutKey(metrics, "token_sha256"))
		}
	}
	return out
}

func deepCopy(v config.Value) config.Value {
	switch x := v.(type) {
	case []config.Value:
		out := make([]config.Value, len(x))
		for i, e := range x {
			out[i] = deepCopy(e)
		}
		return out
	case *config.Map:
		out := config.NewMap()
		for i, k := range x.Keys() {
			out.SetKey(k, deepCopy(x.Values()[i]))
		}
		return out
	}
	return v
}

func withoutKey(m *config.Map, key string) *config.Map {
	out := config.NewMap()
	for i, k := range m.Keys() {
		if k != key {
			out.SetKey(k, m.Values()[i])
		}
	}
	return out
}

// WriteSensorCopy writes raw, redacted, as the parser daemons' config:
// root:fr_os-sensor 0640, replaced atomically, never briefly readable by
// anyone else.
func (s *System) WriteSensorCopy(raw config.Value) error {
	body, err := config.FlowYAML(Redacted(raw))
	if err != nil {
		return err
	}
	path := s.Paths.SensorConfig
	if err := mkdirParent(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := unlinkMissingOK(tmp); err != nil {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(SensorCopyHeader + body + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && s.root() {
		gid, ok := groupOf(SensorUser)
		if !ok {
			gid = 0 // no sensor account (a dev box): root's alone
		}
		err = s.Chown(tmp, 0, gid)
	}
	if err == nil {
		err = os.Chmod(tmp, 0o640)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// RefreshSensorCopy is WriteSensorCopy from the config file at
// configPath. It returns "" or what went wrong: a failure never fails
// the save or apply it follows (the daemons keep the copy they have).
func (s *System) RefreshSensorCopy(configPath string) string {
	data, err := os.ReadFile(configPath)
	var raw config.Value
	if err == nil {
		text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
		raw, err = config.LoadYAML(text)
	}
	if err == nil {
		err = s.WriteSensorCopy(raw)
	}
	if err != nil {
		return "could not refresh the sensors' config copy: " + osErrorText(err)
	}
	return ""
}

// --- security alerts (frfw.webui.audit) ----------------------------------------------

// maxAuditBytes is where the activity log rotates.
const maxAuditBytes = 1 << 20

// Alert writes a security alert to the activity log the webUI shows
// (security-lessons G9). Auditing never breaks what it describes: a
// failure is dropped.
func (s *System) Alert(message, user, client string) {
	path := s.Paths.AuditLog
	if !exists(path) {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
		if err != nil {
			return
		}
		f.Close()
		if s.root() {
			if gid, ok := groupOf(WebUIUser); ok {
				s.Chown(filepath.Dir(path), 0, gid)
				s.Chown(path, 0, gid)
			}
		}
	}
	entry := config.NewMap()
	entry.Set("alert", message)
	entry.Set("client", client)
	entry.Set("ts", NowSeconds(s.Now()))
	entry.Set("user", user)
	line, err := config.PyJSON(entry, -1, true)
	if err != nil {
		return
	}
	line += "\n"
	if st, err := os.Stat(path); err == nil && st.Size()+int64(len(line)) > maxAuditBytes {
		if os.Rename(path, path+".1") != nil {
			return
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(line)
}

// --- the config file -----------------------------------------------------------------

// ReadConfig is 1.x's read_config: the checked config at path and the
// text it came from.
func ReadConfig(path string) (*config.Config, string, error) {
	if !isFile(path) {
		return nil, "", &StepError{"Config file not found: " + path}
	}
	c, text, err := config.ReadFile(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return nil, "", pyOSError(err)
		}
		return nil, "", err
	}
	return c, text, nil
}

// NowSeconds is time.time() at t.
func NowSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }
