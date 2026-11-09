package webui

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// routes are 1.x's, in its order (the first route whose path matches
// answers a wrong method with 405). A nil handler is a screen phase 3
// has not ported yet (3b-3d); it still signs in first, as 1.x does.
var routes = []route{
	{"GET", "/login", "", (*Server).loginForm},
	{"POST", "/login", "", (*Server).loginSubmit},
	{"POST", "/logout", "", (*Server).logout},
	{"GET", "/setup", "login", (*Server).setupForm},
	{"POST", "/setup", "login", (*Server).setupSubmit},
	{"GET", "/users", "admin", (*Server).listUsers},
	{"POST", "/users/add", "admin", (*Server).addUser},
	{"POST", "/users/{target}/role", "admin", (*Server).changeRole},
	{"POST", "/users/{target}/password", "admin", (*Server).resetPassword},
	{"POST", "/users/{target}/delete", "admin", (*Server).deleteUser},
	{"GET", "/account", "login", (*Server).showAccount},
	{"POST", "/account/password", "login", (*Server).changeOwnPassword},
	{"POST", "/account/logout-everywhere", "login", (*Server).logoutEverywhere},
	{"GET", "/login/mfa", "", (*Server).mfaForm},
	{"POST", "/login/mfa/totp", "", (*Server).mfaTOTP},
	{"POST", "/login/mfa/webauthn/options", "", (*Server).mfaWebAuthnOptions},
	{"POST", "/login/mfa/webauthn/verify", "", (*Server).mfaWebAuthnVerify},
	{"GET", "/account/mfa", "login", (*Server).mfaAccount},
	{"GET", "/account/mfa/totp", "login", (*Server).mfaTOTPStart},
	{"POST", "/account/mfa/totp", "login", (*Server).mfaTOTPConfirm},
	{"POST", "/account/mfa/webauthn/options", "login", (*Server).mfaKeyOptions},
	{"POST", "/account/mfa/webauthn/register", "login", (*Server).mfaKeyRegister},
	{"POST", "/account/mfa/remove", "login", (*Server).mfaRemove},
	{"POST", "/users/mfa-policy", "admin", (*Server).mfaPolicy},
	{"POST", "/users/{target}/mfa-reset", "admin", (*Server).mfaReset},
	{"GET", "/", "login", nil},
	{"POST", "/apply", "login", (*Server).applyNow},
	{"POST", "/apply/confirm", "login", (*Server).applyConfirm},
	{"POST", "/apply/revert", "login", (*Server).applyRevert},
	{"POST", "/apply/rejected/restore", "login", (*Server).restoreRejected},
	{"POST", "/rollback", "login", (*Server).rollbackNow},
	{"POST", "/alerts/seen", "admin", (*Server).alertsSeen},
	{"GET", "/interfaces", "login", nil},
	{"POST", "/interfaces/save", "login", nil},
	{"POST", "/interfaces/delete/{name}", "login", nil},
	{"POST", "/interfaces/ipv6", "login", nil},
	{"GET", "/rules", "login", nil},
	{"POST", "/rules/add", "login", nil},
	{"POST", "/rules/move/{name}", "login", nil},
	{"POST", "/rules/remove-expired", "login", nil},
	{"POST", "/rules/delete/{name}", "login", nil},
	{"POST", "/rules/timezone", "login", nil},
	{"GET", "/nat", "login", nil},
	{"POST", "/nat/masquerade/add", "login", nil},
	{"POST", "/nat/masquerade/delete/{out_zone}", "login", nil},
	{"POST", "/nat/portforward/add", "login", nil},
	{"POST", "/nat/portforward/delete/{name}", "login", nil},
	{"GET", "/dhcp", "login", nil},
	{"POST", "/dhcp/{zone}/save", "login", nil},
	{"POST", "/dhcp/{zone}/delete", "login", nil},
	{"POST", "/dhcp/{zone}/reservations/add", "login", nil},
	{"POST", "/dhcp/{zone}/reservations/delete/{mac}", "login", nil},
	{"GET", "/ai-ids", "login", nil},
	{"POST", "/ai-ids/settings", "login", nil},
	{"GET", "/update", "login", nil},
	{"POST", "/update/apply", "login", nil},
	{"POST", "/update/rollback", "login", nil},
	{"POST", "/update/auto-security", "login", nil},
	{"POST", "/update/kernel/check", "login", nil},
	{"POST", "/update/kernel/try", "login", nil},
	{"POST", "/update/kernel/cancel", "login", nil},
	{"POST", "/update/kernel-updates", "login", nil},
	{"GET", "/xdp", "login", nil},
	{"POST", "/xdp/settings", "login", nil},
	{"POST", "/xdp/blocklist/remove", "login", nil},
	{"GET", "/xdp/logs/stream", "login", nil},
	{"GET", "/ztna/login", "", nil},
	{"POST", "/ztna/login", "", nil},
	{"GET", "/ztna/status", "", nil},
	{"GET", "/ztna", "login", nil},
	{"POST", "/ztna/settings", "login", nil},
	{"POST", "/ztna/users/add", "login", nil},
	{"POST", "/ztna/users/remove/{target_username}", "login", nil},
	{"GET", "/vpn", "login", nil},
	{"POST", "/vpn/settings", "login", nil},
	{"POST", "/vpn/peers/add", "login", nil},
	{"POST", "/vpn/peers/remove/{peer_name}", "login", nil},
	{"GET", "/segments", "login", nil},
	{"POST", "/segments", "login", nil},
	{"GET", "/security", "login", nil},
	{"GET", "/system", "login", nil},
	{"POST", "/system/pqc/settings", "login", nil},
	{"POST", "/system/management", "login", nil},
	{"POST", "/system/management-ipv6", "login", nil},
	{"POST", "/system/management-addresses", "login", nil},
	{"GET", "/system/cert.pem", "login", nil},
	{"POST", "/system/metrics/site", "login", nil},
	{"POST", "/system/metrics/token", "login", nil},
	{"GET", "/surface", "login", nil},
	{"GET", "/adblock", "login", nil},
	{"POST", "/adblock/local-dns/add", "login", nil},
	{"POST", "/adblock/local-dns/remove", "login", nil},
	{"POST", "/adblock/local-dns/domain", "login", nil},
	{"POST", "/adblock/settings", "login", nil},
	{"POST", "/adblock/refresh", "login", nil},
	{"GET", "/iot", "login", nil},
	{"POST", "/iot/settings", "login", nil},
	{"POST", "/iot/scan", "login", nil},
	{"POST", "/iot/device", "login", nil},
	{"GET", "/apps", "login", nil},
	{"POST", "/apps/settings", "login", nil},
	{"POST", "/apps/block", "login", nil},
	{"GET", "/tls", "login", nil},
	{"POST", "/tls/settings", "login", nil},
	{"POST", "/tls/block", "login", nil},
	{"POST", "/tls/unblock", "login", nil},
	{"GET", "/metrics", "", nil},
}

func entry(pairs ...any) *config.Map { return cmdMap(pairs...) }

// -- cookies -----------------------------------------------------------------------------------

func (s *Server) httpDate(offset float64) string {
	return time.Unix(int64(s.env.Now()+offset), 0).UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

// deleteCookie is Starlette's delete_cookie: an empty value, expired now.
func (s *Server) deleteCookie(a *answer, name, path string) {
	zero := 0
	a.header("set-cookie", cookie{name: name, value: `""`, expires: s.httpDate(0), maxAge: &zero, path: path,
		sameSite: "lax"}.String())
}

// issueSession gives the browser a fresh session for the account.
func (s *Server) issueSession(q *request, a *answer, account *Account) (*answer, error) {
	value, err := s.sessions.CreateCookie(account)
	if err != nil {
		return nil, err
	}
	a.header("set-cookie", cookie{name: CookieName, value: value, httpOnly: true, path: "/", sameSite: "lax",
		secure: q.scheme == "https"}.String())
	return a, nil
}

// -- signing in -------------------------------------------------------------------------------

func (s *Server) loginForm(q *request) (*answer, error) {
	exists, err := s.store.Exists()
	if err != nil {
		return nil, err
	}
	return s.render(q, "login", &page{Error: q.queryGet("error"), Data: struct{ NoAccount bool }{!exists}})
}

// rejectFailedLogin records a failed sign-in (per source, and per
// account when one is named) and, when the source just crossed the
// limit, has the apply-helper jail it (G6).
func (s *Server) rejectFailedLogin(ip, redirectPath, account string) (*answer, error) {
	if account != "" {
		s.guard.recordAccountFailure(account)
	}
	if s.guard.recordFailure(ip) {
		if _, err := s.helper.BanIP(ip, BanSeconds); err != nil {
			return nil, err
		}
		return redirect(redirectWith(redirectPath, "error",
			"Too many failed login attempts -- this address is temporarily blocked")), nil
	}
	return redirect(redirectWith(redirectPath, "error", "Invalid credentials")), nil
}

func (s *Server) loginSubmit(q *request) (*answer, error) {
	var username, password string
	if err := q.fields(func(p *formParams) { username, password = p.str("username"), p.str("password") }); err != nil {
		return nil, err
	}
	ip := q.clientIP()
	if locked := s.guard.accountLocked(username, ip); locked > 0 {
		// The password isn't checked, but hashed, for the same timing.
		hashPassword(s.env, password)
		s.auditAppend(entry("user", username, "client", ip, "event", "login refused: account locked"))
		return redirect(redirectWith("/login", "error", lockedMessage(locked))), nil
	}
	account, err := s.store.Verify(username, password)
	if err != nil {
		return nil, err
	}
	if account == nil {
		s.auditAppend(entry("user", username, "client", ip, "event", "login failed"))
		// Counted for any name: a lockout mustn't tell which exist.
		return s.rejectFailedLogin(ip, "/login", username)
	}
	if account.HasMFA() && s.tickets.accountLocked(account.Username) {
		s.auditAppend(entry("user", username, "client", ip, "event", "second factor locked"))
		return redirect(redirectWith("/login", "error",
			"Too many wrong second-factor attempts for this account -- try again in 15 minutes")), nil
	}
	if account.HasMFA() {
		// G5: the password alone gets no session, only a single-use
		// ticket for the second step.
		s.auditAppend(entry("user", username, "client", ip, "event", "password ok, second factor pending"))
		a := redirect("/login/mfa")
		age := TicketSeconds
		a.header("set-cookie", cookie{name: TicketCookie, value: s.tickets.create(account), httpOnly: true,
			maxAge: &age, path: "/login", sameSite: "strict", secure: q.scheme == "https"}.String())
		return a, nil
	}
	return s.signedIn(q, ip, account, "login", redirect("/"))
}

// signedIn records a sign-in (and a sign-in from a new source as an
// alert, G9) and issues the session on a.
func (s *Server) signedIn(q *request, ip string, account *Account, event string, a *answer) (*answer, error) {
	newSource := s.guard.recordSuccess(ip, account.Username)
	e := entry("user", account.Username, "role", account.Role, "client", ip, "event", event)
	if newSource {
		e.Set("new_source", true)
	}
	s.auditAppend(e)
	if newSource {
		s.auditAlert(fmt.Sprintf("%s signed in from a new address %s", config.Repr(account.Username), ip),
			entry("user", account.Username, "client", ip))
	}
	return s.issueSession(q, a, account)
}

func (s *Server) logout(q *request) (*answer, error) {
	// G7: the session ends on the server, not only in this browser.
	if err := s.sessions.RevokeCookie(q.cookies[CookieName]); err != nil {
		return nil, err
	}
	a := redirect("/login")
	s.deleteCookie(a, CookieName, "/")
	return a, nil
}

func (s *Server) setupForm(q *request) (*answer, error) {
	if !q.user.MustChange {
		return redirect("/"), nil
	}
	return s.render(q, "setup", &page{Error: q.queryGet("error"), Data: struct{ Current string }{q.user.Username}})
}

func (s *Server) setupSubmit(q *request) (*answer, error) {
	var newUsername, password, confirm string
	if err := q.fields(func(p *formParams) {
		newUsername, password, confirm = p.str("username"), p.str("password"), p.str("password_confirm")
	}); err != nil {
		return nil, err
	}
	if !q.user.MustChange {
		return redirect("/"), nil
	}
	if password != confirm {
		return redirect(redirectWith("/setup", "error", "Passwords do not match")), nil
	}
	username := q.user.Username
	account, err := s.store.CompleteSetup(username, newUsername, password)
	var ae *AccountError
	if errors.As(err, &ae) {
		return redirect(redirectWith("/setup", "error", ae.Msg)), nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.sessions.RevokeUser(username); err != nil {
		return nil, err
	}
	s.auditAppend(entry("user", account.Username, "client", q.clientIP(), "event",
		"first-run setup: renamed "+config.Repr(username)))
	// K4: next, the offer to split IoT and guests off.
	return s.issueSession(q, redirect("/segments?first_run=1"), account)
}

// -- accounts ------------------------------------------------------------------------------------

type auditRow struct {
	When, User, Role, Client, Alert, Event, Method, Path, Status string
	Denied, OK                                                   bool
}

func (s *Server) localTime(ts float64, layout string) string {
	return time.Unix(int64(ts), 0).In(s.env.Local).Format(layout)
}

func (s *Server) listUsers(q *request) (*answer, error) {
	var rows []auditRow
	for _, e := range readRecentAudit(s.env.Paths.AuditLog(), 200) {
		row := auditRow{When: "-"}
		if ts, ok := e.Get("ts"); ok {
			if f, isNum := number(ts); isNum {
				row.When = s.localTime(f, "2006-01-02 15:04:05")
			}
		}
		or := func(key, def string) string {
			v, _ := e.Get(key)
			if !config.Truthy(v) {
				return def
			}
			return pyStr(v)
		}
		row.User, row.Role, row.Client = or("user", "-"), or("role", ""), or("client", "-")
		row.Alert, row.Event = or("alert", ""), or("event", "")
		row.Method, row.Path = jinjaStr(e, "method"), jinjaStr(e, "path")
		if st, _ := e.Get("status"); config.Truthy(st) {
			row.Status = pyStr(st)
			f, ok := number(st)
			if !ok {
				return nil, errInternal // 1.x: comparing it with 400 raises
			}
			row.Denied, row.OK = f == 403, f < 400
		}
		rows = append(rows, row)
	}
	users, _, err := s.store.Users()
	if err != nil {
		return nil, err
	}
	var list []*Account
	for _, a := range users {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	return s.render(q, "users", flash(q, &page{Username: q.user.Username, Data: struct {
		Users      []*Account
		Roles      []string
		RequireMFA bool
		Audit      []auditRow
	}{list, roles, s.store.RequireMFA(), rows}}))
}

// accountAction runs a change and redirects to /users with its success
// message, or the refusal.
func (s *Server) accountAction(action func() error, success string) (*answer, error) {
	err := action()
	var ae *AccountError
	if errors.As(err, &ae) {
		return redirect(redirectWith("/users", "error", ae.Msg)), nil
	}
	if err != nil {
		return nil, err
	}
	return redirect(redirectWith("/users", "success", success)), nil
}

func (s *Server) addUser(q *request) (*answer, error) {
	var name, password, role string
	if err := q.fields(func(p *formParams) {
		name, password, role = p.str("new_username"), p.str("new_password"), p.str("role")
	}); err != nil {
		return nil, err
	}
	name = config.PyStrip(name)
	return s.accountAction(func() error {
		if err := s.store.AddUser(name, password, role); err != nil {
			return err
		}
		if role == RoleAdmin {
			// G9: a new admin is how an intruder stays.
			s.auditAlert(fmt.Sprintf("new admin account %s added by %s", config.Repr(name),
				config.Repr(q.user.Username)), entry("user", q.user.Username, "client", q.clientIP()))
		}
		return nil
	}, fmt.Sprintf("User %s added as %s", config.Repr(name), role))
}

func (s *Server) changeRole(q *request) (*answer, error) {
	var role string
	if err := q.fields(func(p *formParams) { role = p.str("role") }); err != nil {
		return nil, err
	}
	target := q.params["target"]
	return s.accountAction(func() error {
		before, err := s.store.Get(target)
		if err != nil {
			return err
		}
		if err := s.store.SetRole(target, role); err != nil {
			return err
		}
		if role == RoleAdmin && before != nil && !before.IsAdmin() {
			s.auditAlert(fmt.Sprintf("%s made an admin by %s", config.Repr(target), config.Repr(q.user.Username)),
				entry("user", q.user.Username, "client", q.clientIP()))
		}
		return nil
	}, fmt.Sprintf("%s is now %s", config.Repr(target), role))
}

func (s *Server) resetPassword(q *request) (*answer, error) {
	var password string
	if err := q.fields(func(p *formParams) { password = p.str("new_password") }); err != nil {
		return nil, err
	}
	target := q.params["target"]
	return s.accountAction(func() error {
		account, err := s.store.Get(target)
		if err != nil {
			return err
		}
		if account == nil {
			return accountErr("No such user %s", config.Repr(target))
		}
		if err := validatePassword(password, target); err != nil {
			return err
		}
		if err := s.store.SetPassword(target, password, "", false); err != nil {
			return err
		}
		if _, err := s.sessions.RevokeUser(target); err != nil { // G7
			return err
		}
		if account.IsAdmin() && target != q.user.Username {
			s.auditAlert(fmt.Sprintf("password of admin %s reset by %s", config.Repr(target),
				config.Repr(q.user.Username)), entry("user", q.user.Username, "client", q.clientIP()))
		}
		return nil
	}, fmt.Sprintf("Password of %s reset; their open sessions have ended", config.Repr(target)))
}

func (s *Server) deleteUser(q *request) (*answer, error) {
	target := q.params["target"]
	return s.accountAction(func() error {
		if err := s.store.DeleteUser(target); err != nil {
			return err
		}
		_, err := s.sessions.RevokeUser(target) // G7
		return err
	}, fmt.Sprintf("User %s deleted", config.Repr(target)))
}

func (s *Server) showAccount(q *request) (*answer, error) {
	return s.render(q, "account", flash(q, &page{Username: q.user.Username, Data: struct {
		Role   string
		HasMFA bool
	}{q.user.Role, q.user.HasMFA()}}))
}

func (s *Server) changeOwnPassword(q *request) (*answer, error) {
	var current, password, confirm string
	if err := q.fields(func(p *formParams) {
		current, password, confirm = p.str("current_password"), p.str("new_password"), p.str("new_password_confirm")
	}); err != nil {
		return nil, err
	}
	username := q.user.Username
	account, err := s.store.Verify(username, current)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return redirect(redirectWith("/account", "error", "Current password is wrong")), nil
	}
	if password != confirm {
		return redirect(redirectWith("/account", "error", "New passwords do not match")), nil
	}
	if err := validatePassword(password, username); err != nil {
		return redirect(redirectWith("/account", "error", err.Error())), nil
	}
	if err := s.store.SetPassword(username, password, "", false); err != nil {
		return nil, err
	}
	// G7: every session of this account ends, this one included; this
	// browser gets a fresh one.
	if _, err := s.sessions.RevokeUser(username); err != nil {
		return nil, err
	}
	fresh, err := s.store.Get(username)
	if err != nil {
		return nil, err
	}
	return s.issueSession(q, redirect("/account?success=Password+changed"), fresh)
}

func (s *Server) logoutEverywhere(q *request) (*answer, error) {
	ended, err := s.sessions.RevokeUser(q.user.Username)
	if err != nil {
		return nil, err
	}
	s.auditAppend(entry("user", q.user.Username, "event", fmt.Sprintf("logged out everywhere (%d session(s))", ended)))
	a := redirect("/login")
	s.deleteCookie(a, CookieName, "/")
	return a, nil
}

// -- the dashboard's buttons ---------------------------------------------------------------------

// helperResult is the redirect to / with the helper's message, or the
// default for its outcome.
func helperResult(reply *config.Map, success, failure string) *answer {
	ok, _ := reply.Get("ok")
	msg, _ := reply.Get("message")
	if config.Truthy(ok) {
		if config.Truthy(msg) {
			success = pyStr(msg)
		}
		return redirect(redirectWith("/", "success", success))
	}
	if config.Truthy(msg) {
		failure = pyStr(msg)
	}
	return redirect(redirectWith("/", "error", failure))
}

func (s *Server) applyNow(q *request) (*answer, error) {
	dryRun := q.queryGet("dry_run") == "1"
	// SEC-26: held until confirmed from a request that reaches the
	// router through the new rules and addresses.
	reply, err := s.helper.Apply(dryRun, true, q.user.Username)
	if err != nil {
		return nil, err
	}
	return helperResult(reply, "Applied", "Apply failed"), nil
}

func (s *Server) applyConfirm(q *request) (*answer, error) {
	var id string
	if err := q.fields(func(p *formParams) { id = p.str("id") }); err != nil {
		return nil, err
	}
	reply, err := s.helper.ApplyConfirm(id)
	if err != nil {
		return nil, err
	}
	return helperResult(reply, "Apply confirmed", "Could not confirm the apply"), nil
}

func (s *Server) applyRevert(q *request) (*answer, error) {
	reply, err := s.helper.ApplyRevert()
	if err != nil {
		return nil, err
	}
	return helperResult(reply, "Went back to the previous config", "Could not go back"), nil
}

func (s *Server) restoreRejected(q *request) (*answer, error) {
	reply, err := s.helper.RestoreRejected()
	if err != nil {
		return nil, err
	}
	return helperResult(reply, "Loaded", "Could not load it"), nil
}

func (s *Server) rollbackNow(q *request) (*answer, error) {
	reply, err := s.helper.Rollback()
	if err != nil {
		return nil, err
	}
	return helperResult(reply, "Rolled back", "Rollback failed"), nil
}

// alertsSeen: an admin has seen the alerts up to until (the newest one
// shown), so one that came in meanwhile still shows (G9).
func (s *Server) alertsSeen(q *request) (*answer, error) {
	var until float64
	if err := q.fields(func(p *formParams) { until = p.float("until") }); err != nil {
		return nil, err
	}
	if err := markAlertsSeen(s.env.Paths.AlertsSeen(), q.user.Username, until); err != nil {
		return nil, err
	}
	return redirect(redirectWith("/", "success", "Security alerts marked as seen")), nil
}
