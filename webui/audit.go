package webui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// Who changed what (1.x's frfw.webui.audit, phase 18, security-lessons
// G9/E6). The log is root's (/var/log/fr_os/audit.log, 0640
// root:fr_os-webui): the webUI reads it but adds to it only through the
// apply-helper's audit_append, so a compromised webUI can add lines but
// not rewrite the ones that show what it did. Form contents are never
// recorded. An entry with an "alert" is a security event the dashboard
// shows an admin until they have seen it.

// auditAppend sends one entry to the helper; auditing never breaks the
// request it describes.
func (s *Server) auditAppend(entry *config.Map) {
	_, _ = s.helper.AuditAppend(entry)
}

// auditAlert is an entry that is also a security alert: the fields,
// then "alert".
func (s *Server) auditAlert(message string, entry *config.Map) {
	entry.Set("alert", message)
	s.auditAppend(entry)
}

// readRecentAudit is the newest entries first, across the log and its
// rotated generation.
func readRecentAudit(path string, limit int) []*config.Map {
	var entries []*config.Map
	for _, candidate := range []string{path, path + ".1"} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		lines := config.PySplitlines(string(data))
		for i := len(lines) - 1; i >= 0; i-- {
			v, err := config.ParseJSONLastWins([]byte(lines[i]))
			if err != nil {
				continue
			}
			if m, ok := v.(*config.Map); ok {
				entries = append(entries, m)
			}
			if len(entries) >= limit {
				return entries
			}
		}
	}
	return entries
}

// alertsSince is the alerts newer than since, newest first, at most 50.
func alertsSince(path string, since float64) []*config.Map {
	var out []*config.Map
	for _, e := range readRecentAudit(path, 2000) {
		alert, _ := e.Get("alert")
		ts, _ := e.Get("ts")
		f, _ := number(ts)
		if config.Truthy(alert) && f > since {
			out = append(out, e)
			if len(out) == 50 {
				break
			}
		}
	}
	return out
}

// alertsSeen is when user last marked the alerts seen.
func alertsSeen(path, user string) float64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return 0
	}
	m, ok := v.(*config.Map)
	if !ok {
		return 0
	}
	raw, _ := m.Get(user)
	f, _ := number(raw)
	return f
}

func markAlertsSeen(path, user string, until float64) error {
	data := config.NewMap()
	if text, err := os.ReadFile(path); err == nil {
		if v, err := config.ParseJSONLastWins(text); err == nil {
			if m, ok := v.(*config.Map); ok {
				data = m
			}
		}
	}
	data.Set(user, until)
	text, err := config.PyJSON(data, -1, false)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	tmp := strings.TrimSuffix(path, ".json") + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o666); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
