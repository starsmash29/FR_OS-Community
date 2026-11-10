package webui

import (
	"fmt"
	"math/big"

	"github.com/starsmash29/fr_os-community/config"
)

// The Zero Trust Network Access gate (1.x's routes/ztna.py). Two trust
// levels: /ztna/login and /ztna/status are public, for the gate's end
// users (not the router's admin); /ztna and its POSTs are the admin's
// settings. The webUI only checks the password; the apply-helper puts
// the source address in the kernel's set, and /ztna/status asks it,
// every time, whether the address is still there (no cookie of its own).

const defaultZTNASessionSeconds = 8 * 3600

// findZTNAUser is _find_user: the ztna.users entry named username.
func findZTNAUser(raw *config.Map, username string) (*config.Map, error) {
	section, err := getMapOr(raw, "ztna")
	if err != nil {
		return nil, err
	}
	usersV, _ := section.Get("users")
	users, err := pyIter(orNil(usersV))
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if m, ok := u.(*config.Map); ok && strEq(field(m, "username"), username) {
			return m, nil
		}
	}
	return nil, nil
}

// orNil is `v or []` for pyIter: a falsy value iterates as nothing.
func orNil(v config.Value) config.Value {
	if !config.Truthy(v) {
		return nil
	}
	return v
}

// pySeconds is a stored number of seconds as an int (a bool is one).
func pySeconds(v config.Value) (int64, error) {
	switch x := v.(type) {
	case *big.Int:
		if x.IsInt64() {
			return x.Int64(), nil
		}
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	}
	return 0, errInternal
}

// formatZTNADuration is _format_duration.
func formatZTNADuration(seconds int64) string {
	seconds = max(seconds, 0)
	hours, rest := seconds/3600, seconds%3600
	minutes, secs := rest/60, rest%60
	switch {
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	case minutes > 0:
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	return fmt.Sprintf("%ds", secs)
}

// -- public: the end user's sign-in and status ------------------------------------------

type ztnaLoginData struct{ ClientIP string }

func (s *Server) ztnaLoginForm(q *request) (*answer, error) {
	return s.render(q, "ztna_login", &page{Error: q.queryGet("error"), Data: ztnaLoginData{q.clientIP()}})
}

func (s *Server) ztnaLoginSubmit(q *request) (*answer, error) {
	var username, password string
	if err := q.fields(func(p *formParams) { username, password = p.str("username"), p.str("password") }); err != nil {
		return nil, err
	}
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	ip := q.clientIP()
	section, err := getMapOr(raw, "ztna")
	if err != nil {
		return nil, err
	}
	if !config.Truthy(field(section, "enabled")) {
		return errorRedirect("/ztna/login", "The ZTNA gate is currently disabled"), nil
	}
	account := "ztna:" + username
	if locked := s.guard.accountLocked(account, ip); locked > 0 {
		hashPassword(s.env, password) // the same timing as a real check
		return errorRedirect("/ztna/login", lockedMessage(locked)), nil
	}
	user, err := findZTNAUser(raw, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// An unknown name takes as long as a wrong password.
		hashPassword(s.env, password)
		return s.rejectFailedLogin(ip, "/ztna/login", account)
	}
	stored, _ := pyGet(user, "password_hash", "").(string)
	if !verifyPassword(password, stored) {
		return s.rejectFailedLogin(ip, "/ztna/login", account)
	}
	if needsRehash(stored) {
		// Security-lessons G2: a pre-scrypt hash is replaced on this
		// sign-in; a save that fails doesn't lock the user out.
		user.Set("password_hash", hashPassword(s.env, password))
		if _, _, err := s.trySave(raw); err != nil {
			return nil, err
		}
	}
	s.guard.recordSuccess(ip, account)
	result, err := s.helper.AuthorizeZTNA(ip, username)
	if err != nil {
		return nil, err
	}
	if !config.Truthy(field(result, "ok")) {
		message := field(result, "message")
		if !config.Truthy(message) {
			return errorRedirect("/ztna/login", "Authorization failed"), nil
		}
		return errorRedirect("/ztna/login", pyStr(message)), nil
	}
	return successRedirect("/ztna/status", fmt.Sprintf("Welcome, %s -- access granted", username)), nil
}

type ztnaStatusData struct {
	ClientIP                        string
	Authorized, NotDirect           bool
	ZTNAUsername, BoundMAC, Expires string
}

func (s *Server) ztnaStatus(q *request) (*answer, error) {
	ip := q.clientIP()
	result, err := s.helper.ZTNAStatus(ip)
	if err != nil {
		return nil, err
	}
	d := ztnaStatusData{ClientIP: ip,
		Authorized: config.Truthy(field(result, "ok")) && config.Truthy(field(result, "authorized"))}
	if notDirect, ok := field(result, "direct").(bool); ok && !notDirect {
		d.NotDirect = true
	}
	if d.Authorized {
		if v := field(result, "username"); config.Truthy(v) {
			d.ZTNAUsername = pyStr(v)
		}
		if v := field(result, "mac"); config.Truthy(v) {
			d.BoundMAC = pyStr(v)
		}
		if v, ok := result.Get("expires_in"); ok && v != nil {
			seconds, err := pySeconds(v)
			if err != nil {
				return nil, err
			}
			d.Expires = formatZTNADuration(seconds)
		}
	}
	return s.render(q, "ztna_status", flash(q, &page{Data: d}))
}

// -- the admin's settings ---------------------------------------------------------------

type ztnaData struct {
	Enabled           bool
	SessionTTL        string
	SessionTTLDisplay string
	Users, GatedRules []string
}

func (s *Server) showZTNA(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "ztna")
	if err != nil {
		return nil, err
	}
	d := &ztnaData{Enabled: config.Truthy(pyGet(section, "enabled", false))}
	ttl := pyGet(section, "session_ttl_seconds", pyInt(defaultZTNASessionSeconds))
	seconds, err := pySeconds(ttl)
	if err != nil {
		return nil, err
	}
	d.SessionTTL, d.SessionTTLDisplay = pyStr(ttl), formatZTNADuration(seconds)
	users, err := pyIter(orNil(field(section, "users")))
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if m, ok := u.(*config.Map); ok {
			d.Users = append(d.Users, pyStr(field(m, "username")))
		}
	}
	rules, err := pyIter(orNil(field(raw, "rules")))
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if m, ok := r.(*config.Map); ok && config.Truthy(field(m, "require_ztna")) {
			d.GatedRules = append(d.GatedRules, pyStr(field(m, "name")))
		}
	}
	return s.render(q, "ztna", flash(q, &page{Username: q.user.Username, Data: d}))
}

func (s *Server) saveZTNA(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	var ttl *big.Int
	if err = q.fields(func(p *formParams) {
		enabled, ttl = p.boolOr("enabled", false), p.intOr("session_ttl_seconds", pyInt(defaultZTNASessionSeconds))
	}); err != nil {
		return nil, err
	}
	section, err := setdefaultMap(raw, "ztna")
	if err != nil {
		return nil, err
	}
	section.Set("enabled", enabled)
	section.Set("session_ttl_seconds", ttl)
	setdefault(section, "users", []config.Value{})
	return s.saved(raw, "/ztna", "ZTNA gate settings saved -- click Apply on the dashboard to load them into the kernel")
}

func (s *Server) addZTNAUser(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var name, password string
	if err = q.fields(func(p *formParams) { name, password = p.str("new_username"), p.str("new_password") }); err != nil {
		return nil, err
	}
	if weak := passwordProblem(password, name); weak != "" { // security-lessons G6
		return errorRedirect("/ztna", weak), nil
	}
	section, err := setdefaultMap(raw, "ztna")
	if err != nil {
		return nil, err
	}
	setdefault(section, "users", []config.Value{})
	users, err := getList(section, "users", false)
	if err != nil {
		return nil, err
	}
	existed := false
	kept := []*config.Map{}
	for _, u := range users {
		if strEq(field(u, "username"), name) {
			existed = true
		} else {
			kept = append(kept, u)
		}
	}
	kept = append(kept, cmdMap("username", name, "password_hash", hashPassword(s.env, password)))
	section.Set("users", values(kept)) // users[:] = ...: the list stays where it is
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/ztna", message), nil
	}
	// Security-lessons G9: a way in through the ZTNA gate.
	what := "new ZTNA user"
	if existed {
		what = "password of ZTNA user"
	}
	s.auditAlert(fmt.Sprintf("%s %s set by %s", what, config.Repr(name), config.Repr(q.user.Username)),
		entry("user", q.user.Username, "client", q.clientIP()))
	return successRedirect("/ztna", fmt.Sprintf("ZTNA user %s saved", config.Repr(name))), nil
}

func (s *Server) removeZTNAUser(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	target := q.params["target_username"]
	section, err := setdefaultMap(raw, "ztna")
	if err != nil {
		return nil, err
	}
	users, err := getList(section, "users", true)
	if err != nil {
		return nil, err
	}
	remaining := []*config.Map{}
	for _, u := range users {
		if !strEq(field(u, "username"), target) {
			remaining = append(remaining, u)
		}
	}
	if len(remaining) == len(users) {
		return errorRedirect("/ztna", fmt.Sprintf("No such ZTNA user %s", config.Repr(target))), nil
	}
	section.Set("users", values(remaining))
	return s.saved(raw, "/ztna", fmt.Sprintf("ZTNA user %s removed", config.Repr(target)))
}
