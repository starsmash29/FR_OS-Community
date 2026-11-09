package webui

import (
	"errors"
	"fmt"
	"html/template"
	"math"
	"math/big"
	"net/http"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
)

// Second-factor sign-in and enrolment, held to 1.x's
// frfw.webui.routes.mfa (security-lessons G5). The password alone only
// gets a ticket cookie; /login/mfa takes a TOTP code or a security-key
// assertion and only then issues the session. Enrolling or removing a
// factor always asks for the current password again, so a hijacked
// session can't quietly add its own factor or remove the owner's.

// rp is the relying-party id and origin for the name the browser used.
func (q *request) rp() (string, string) {
	return rpIDFor(q.host), originFor(q.scheme, q.host, q.port)
}

// ticket is the sign-in ticket the browser holds, its entry and its
// account, or all empty.
func (s *Server) ticket(q *request) (string, *ticketEntry, *Account, error) {
	tid := q.cookies[TicketCookie]
	entry, account, err := s.tickets.get(tid, s.store.Get)
	if err != nil || entry == nil {
		return "", nil, nil, err
	}
	return tid, entry, account, nil
}

// finishLogin is 1.x's _finish_login: the ticket is used up (only one
// of two racing requests gets it) and the session issued.
func (s *Server) finishLogin(q *request, tid string, account *Account, how string) (*answer, error) {
	if !s.tickets.consume(tid) {
		return redirect(redirectWith("/login", "error", "This sign-in was already completed or has expired")), nil
	}
	a := redirect("/")
	s.deleteCookie(a, TicketCookie, "/login")
	fresh, err := s.store.Get(account.Username)
	if err != nil {
		return nil, err
	}
	if fresh == nil {
		return nil, errors.New("account vanished during sign-in")
	}
	return s.signedIn(q, q.clientIP(), fresh, "login ("+how+")", a)
}

// -- the second sign-in step -----------------------------------------------------------------

func (s *Server) mfaForm(q *request) (*answer, error) {
	_, _, account, err := s.ticket(q)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return redirect(redirectWith("/login", "error", "Sign in again")), nil
	}
	rpID, _ := q.rp()
	keys := false
	for _, c := range webauthnList(account) {
		if rpID != "" && mapStr(c, "rp_id") == rpID {
			keys = true
		}
	}
	totp, _ := account.MFA.Get("totp")
	return s.render(q, "mfa_login", &page{Error: q.queryGet("error"), Data: struct{ TOTP, Keys, KeysElsewhere bool }{
		config.Truthy(totp), keys, len(webauthnList(account)) > 0 && !keys}})
}

// totpMap is account.mfa.get("totp") or {}: an error where 1.x's
// .get on it would raise.
func totpMap(a *Account) (*config.Map, error) {
	v, _ := a.MFA.Get("totp")
	if !config.Truthy(v) {
		return nil, nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, fmt.Errorf("totp is not a mapping: %s", config.Repr(v))
	}
	return m, nil
}

// pyIntOf is int() of a stored JSON number (a float is truncated).
func pyIntOf(v config.Value) (int64, error) {
	switch x := v.(type) {
	case *big.Int:
		if !x.IsInt64() {
			return 0, errors.New("time step out of range")
		}
		return x.Int64(), nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return 0, errors.New("time step is not finite")
		}
		return int64(x), nil
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case string:
		if n, ok := config.PyInt(x); ok && n.IsInt64() {
			return n.Int64(), nil
		}
	}
	return 0, fmt.Errorf("invalid time step %s", config.Repr(v))
}

func (s *Server) mfaTOTP(q *request) (*answer, error) {
	var code string
	if err := q.fields(func(p *formParams) { code = p.str("code") }); err != nil {
		return nil, err
	}
	tid, _, account, err := s.ticket(q)
	if err != nil {
		return nil, err
	}
	if account == nil || s.tickets.accountLocked(account.Username) {
		return redirect(redirectWith("/login", "error", "Sign in again")), nil
	}
	// Checking a code and recording its time step is one step, so two
	// requests racing with the same code can't both get through.
	s.totpMu.Lock()
	ok, err := func() (bool, error) {
		fresh, err := s.store.Get(account.Username)
		if err != nil {
			return false, err
		}
		if fresh == nil {
			return false, errors.New("account vanished during sign-in")
		}
		account = fresh
		totp, err := totpMap(account)
		if err != nil || totp == nil {
			return false, err
		}
		last := int64(-1)
		if v, has := totp.Get("last_step"); has {
			if last, err = pyIntOf(v); err != nil {
				return false, err
			}
		}
		step, matched, err := totpStep(mapStr(totp, "secret"), code, last, s.env.Now())
		if err != nil || !matched {
			return false, err
		}
		// A code works once: remember its time step before anything else.
		updated := copyMap(totp)
		updated.Set("last_step", big.NewInt(step))
		mfa := copyMap(account.MFA)
		mfa.Set("totp", updated)
		_, err = s.store.SetMFA(account.Username, mfa)
		return err == nil, err
	}()
	s.totpMu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		ip := q.clientIP()
		s.auditAppend(entry("user", account.Username, "client", ip, "event", "second factor failed"))
		path := "/login"
		if s.tickets.fail(tid) {
			path = "/login/mfa"
		}
		return s.rejectFailedLogin(ip, path, "")
	}
	return s.finishLogin(q, tid, account, "TOTP")
}

func (s *Server) mfaWebAuthnOptions(q *request) (*answer, error) {
	tid, _, account, err := s.ticket(q)
	if err != nil {
		return nil, err
	}
	rpID, _ := q.rp()
	if account == nil || rpID == "" {
		return jsonAnswer(http.StatusBadRequest, `{"error":"sign in again, by name (not IP address)"}`), nil
	}
	options, challenge, err := authenticationOptions(s.env, account, rpID)
	if err != nil {
		return nil, err
	}
	s.tickets.update(tid, func(e *ticketEntry) { e.challenge = challenge })
	return jsonAnswer(http.StatusOK, options), nil
}

func (s *Server) mfaWebAuthnVerify(q *request) (*answer, error) {
	tid, te, account, err := s.ticket(q)
	if err != nil {
		return nil, err
	}
	rpID, origin := q.rp()
	var challenge []byte
	if te != nil {
		s.tickets.update(tid, func(e *ticketEntry) { challenge, e.challenge = e.challenge, nil })
	}
	if account == nil || rpID == "" || challenge == nil || s.tickets.accountLocked(account.Username) {
		return jsonAnswer(http.StatusBadRequest, `{"error":"sign in again"}`), nil
	}
	var updated *config.Map
	verr := errors.New("the body is not UTF-8")
	if utf8.Valid(q.body) {
		updated, verr = verifyAuthentication(account, q.body, challenge, rpID, origin)
	}
	if verr != nil {
		// Any verification failure is a failed sign-in.
		ip := q.clientIP()
		s.auditAppend(entry("user", account.Username, "client", ip, "event", "second factor failed"))
		s.tickets.fail(tid)
		if _, err := s.rejectFailedLogin(ip, "/login", ""); err != nil {
			return nil, err
		}
		return jsonAnswer(http.StatusForbidden, `{"error":"the security key was not accepted"}`), nil
	}
	if _, err := s.store.SetMFA(account.Username, updated); err != nil {
		return nil, err
	}
	a, err := s.finishLogin(q, tid, account, "security key")
	if err != nil {
		return nil, err
	}
	if location(a) != "/" {
		return jsonAnswer(http.StatusConflict, `{"error":"this sign-in was already completed"}`), nil
	}
	out := jsonAnswer(http.StatusOK, `{"redirect":"/"}`)
	for _, h := range a.headers {
		if h[0] == "set-cookie" {
			out.header(h[0], h[1])
		}
	}
	return out, nil
}

func location(a *answer) string {
	for _, h := range a.headers {
		if h[0] == "location" {
			return h[1]
		}
	}
	return ""
}

// -- enrolment ----------------------------------------------------------------------------------

type keyRow struct{ ID, Name, RPID string }

type newTOTP struct {
	TID, Secret string
	QR          template.HTML
}

// mfaView is 1.x's _view: the Second factor screen.
func (s *Server) mfaView(q *request, fresh *newTOTP) (*answer, error) {
	account, err := s.store.Get(q.user.Username)
	if err != nil {
		return nil, err
	}
	if account == nil {
		return nil, errors.New("account vanished")
	}
	rpID, _ := q.rp()
	var keys []keyRow
	for _, c := range webauthnList(account) {
		keys = append(keys, keyRow{jinjaStr(c, "id"), jinjaStr(c, "name"), jinjaStr(c, "rp_id")})
	}
	totp, _ := account.MFA.Get("totp")
	data := struct {
		TOTP     bool
		Keys     []keyRow
		RPID     string
		Required bool
		NewTOTP  *newTOTP
	}{config.Truthy(totp), keys, rpID, s.store.RequireMFA() && account.IsAdmin() && !account.HasMFA(), fresh}
	return s.render(q, "mfa_account", flash(q, &page{Username: account.Username, Data: data}))
}

func (s *Server) mfaAccount(q *request) (*answer, error) { return s.mfaView(q, nil) }

// qrSVG is the authenticator-app QR code for uri, as 1.x draws it
// (scale 5); none when it can't be drawn as 1.x would.
func qrSVG(uri string) template.HTML {
	svg, err := qrSVGOf(uri, 5, "#0C141F", "#FFFFFF")
	if err != nil {
		return ""
	}
	return svg
}

func (s *Server) mfaTOTPStart(q *request) (*answer, error) {
	secret := newTOTPSecret(s.env)
	tid := s.enrolments.create(q.user)
	s.enrolments.update(tid, func(e *ticketEntry) { e.totpSecret, e.hasSecret = secret, true })
	host := q.host
	if host == "" {
		host = "fr-router"
	}
	return s.mfaView(q, &newTOTP{TID: tid, Secret: secret, QR: qrSVG(totpURI(secret, q.user.Username, host))})
}

func (s *Server) mfaTOTPConfirm(q *request) (*answer, error) {
	var tid, code, password string
	if err := q.fields(func(p *formParams) { tid, code, password = p.str("tid"), p.str("code"), p.str("password") }); err != nil {
		return nil, err
	}
	username := q.user.Username
	if ok, err := s.verifies(username, password); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return redirect(redirectWith("/account/mfa", "error", "Current password is wrong")), nil
	}
	e, account, err := s.enrolments.get(tid, s.store.Get)
	if err != nil {
		return nil, err
	}
	if e == nil || account.Username != username || !e.hasSecret {
		return redirect(redirectWith("/account/mfa", "error", "That setup expired -- start again")), nil
	}
	step, matched, err := totpStep(e.totpSecret, code, -1, s.env.Now())
	if err != nil {
		return nil, err
	}
	if !matched {
		return redirect(redirectWith("/account/mfa", "error",
			"The code didn't match -- check the phone's clock and try again")), nil
	}
	s.enrolments.consume(tid)
	if account, err = s.store.Get(username); err != nil || account == nil {
		return nil, errors.Join(err, errors.New("account vanished"))
	}
	totp := config.NewMap()
	totp.Set("secret", e.totpSecret)
	totp.Set("last_step", big.NewInt(step))
	mfa := copyMap(account.MFA)
	mfa.Set("totp", totp)
	if _, err := s.store.SetMFA(username, mfa); err != nil {
		return nil, err
	}
	s.auditAppend(entry("user", username, "client", q.clientIP(), "event", "added authenticator app"))
	return redirect(redirectWith("/account/mfa", "success", "Authenticator app added")), nil
}

// verifies is store.verify(...) is not None.
func (s *Server) verifies(username, password string) (bool, error) {
	a, err := s.store.Verify(username, password)
	return a != nil, err
}

// jsonBody is await request.json() where 1.x then calls .get on it:
// anything but a JSON object is an error (a 500, as in 1.x).
func (q *request) jsonBody() (*config.Map, error) {
	v, err := config.ParseJSONLastWins(q.body)
	if err != nil {
		return nil, err
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, errors.New("the JSON body is not an object")
	}
	return m, nil
}

// bodyStr is str(body.get(name, "")).
func bodyStr(body *config.Map, name string) string {
	v, ok := body.Get(name)
	if !ok {
		return ""
	}
	return pyStr(v)
}

func (s *Server) mfaKeyOptions(q *request) (*answer, error) {
	body, err := q.jsonBody()
	if err != nil {
		return nil, err
	}
	rpID, _ := q.rp()
	if rpID == "" {
		return jsonAnswer(http.StatusBadRequest,
			`{"error":"open the router by name, not IP address, to add a security key"}`), nil
	}
	username := q.user.Username
	if ok, err := s.verifies(username, bodyStr(body, "password")); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return jsonAnswer(http.StatusForbidden, `{"error":"current password is wrong"}`), nil
	}
	account, err := s.store.Get(username)
	if err != nil || account == nil {
		return nil, errors.Join(err, errors.New("account vanished"))
	}
	options, challenge, err := registrationOptions(s.env, account, rpID)
	if err != nil {
		return nil, err
	}
	tid := s.enrolments.create(account)
	name := bodyStr(body, "name")
	s.enrolments.update(tid, func(e *ticketEntry) { e.challenge, e.name = challenge, name })
	return jsonAnswer(http.StatusOK, `{"tid":`+jsonStr(tid)+`,"options":`+options+`}`), nil
}

func (s *Server) mfaKeyRegister(q *request) (*answer, error) {
	body, err := q.jsonBody()
	if err != nil {
		return nil, err
	}
	tid := bodyStr(body, "tid")
	username := q.user.Username
	e, account, err := s.enrolments.get(tid, s.store.Get)
	if err != nil {
		return nil, err
	}
	rpID, origin := q.rp()
	if e == nil || account.Username != username || rpID == "" || !s.enrolments.consume(tid) {
		return jsonAnswer(http.StatusBadRequest, `{"error":"that setup expired -- start again"}`), nil
	}
	credential, _ := body.Get("credential")
	key, verr := func() (*config.Map, error) {
		if e.challenge == nil {
			return nil, errors.New("no challenge for this setup") // a KeyError in 1.x
		}
		text, err := config.PyJSON(credential, -1, false)
		if err != nil {
			return nil, err
		}
		return verifyRegistration(s.env, []byte(text), e.challenge, rpID, origin, e.name)
	}()
	if verr != nil {
		return jsonAnswer(http.StatusBadRequest, `{"error":"the security key's answer did not verify"}`), nil
	}
	if account, err = s.store.Get(username); err != nil || account == nil {
		return nil, errors.Join(err, errors.New("account vanished"))
	}
	mfa := copyMap(account.MFA)
	var list []config.Value
	for _, c := range webauthnList(account) {
		list = append(list, c)
	}
	mfa.Set("webauthn", append(list, key))
	if _, err := s.store.SetMFA(username, mfa); err != nil {
		return nil, err
	}
	name, _ := key.Get("name")
	s.auditAppend(entry("user", username, "client", q.clientIP(), "event", "added security key "+config.Repr(name)))
	return jsonAnswer(http.StatusOK, `{"redirect":"/account/mfa?success=Security+key+added"}`), nil
}

func (s *Server) mfaRemove(q *request) (*answer, error) {
	var kind, password, keyID string
	if err := q.fields(func(p *formParams) {
		kind, password, keyID = p.str("kind"), p.str("password"), p.strOr("key_id", "")
	}); err != nil {
		return nil, err
	}
	username := q.user.Username
	if ok, err := s.verifies(username, password); err != nil || !ok {
		if err != nil {
			return nil, err
		}
		return redirect(redirectWith("/account/mfa", "error", "Current password is wrong")), nil
	}
	account, err := s.store.Get(username)
	if err != nil || account == nil {
		return nil, errors.Join(err, errors.New("account vanished"))
	}
	current := config.NewMap()
	switch kind {
	case "totp":
		for i, k := range account.MFA.Keys() {
			if k != "totp" {
				current.SetKey(k, account.MFA.Values()[i])
			}
		}
	case "webauthn":
		var kept []config.Value
		for _, c := range webauthnList(account) {
			id, has := c.Get("id")
			if !has {
				return nil, errors.New("a stored key has no id") // a KeyError in 1.x
			}
			if id != keyID {
				kept = append(kept, c)
			}
		}
		current = copyMap(account.MFA)
		if kept == nil {
			kept = []config.Value{}
		}
		current.Set("webauthn", kept)
	default:
		return redirect(redirectWith("/account/mfa", "error", "Unknown factor")), nil
	}
	if _, err := s.store.SetMFA(username, current); err != nil {
		return nil, err
	}
	s.auditAlert(fmt.Sprintf("%s removed a second factor (%s)", config.Repr(username), kind),
		entry("user", username, "client", q.clientIP(), "event", "removed "+kind))
	return redirect(redirectWith("/account/mfa", "success", "Removed")), nil
}

// -- admin controls ------------------------------------------------------------------------------

func (s *Server) mfaPolicy(q *request) (*answer, error) {
	var require bool
	if err := q.fields(func(p *formParams) { require = p.boolOr("require", false) }); err != nil {
		return nil, err
	}
	username := q.user.Username
	wasRequired := s.store.RequireMFA()
	if err := s.store.SetPolicy(require); err != nil {
		return nil, err
	}
	if require || !wasRequired {
		s.auditAppend(entry("user", username, "client", q.clientIP(), "event",
			"require MFA for admins: "+pyStr(require)))
	} else {
		s.auditAlert(config.Repr(username)+" turned the second-factor requirement for admins off",
			entry("user", username, "client", q.clientIP()))
	}
	if require {
		return redirect(redirectWith("/users", "success", "Admins must use a second factor")), nil
	}
	return redirect(redirectWith("/users", "success", "A second factor is optional again")), nil
}

func (s *Server) mfaReset(q *request) (*answer, error) {
	target := q.params["target"]
	if _, err := s.store.SetMFA(target, config.NewMap()); err != nil {
		var ae *AccountError
		if errors.As(err, &ae) {
			return redirect(redirectWith("/users", "error", ae.Msg)), nil
		}
		return nil, err
	}
	if _, err := s.sessions.RevokeUser(target); err != nil {
		return nil, err
	}
	s.auditAlert(fmt.Sprintf("second factors of %s removed by %s", config.Repr(target), config.Repr(q.user.Username)),
		entry("user", q.user.Username, "client", q.clientIP()))
	return redirect(redirectWith("/users", "success",
		fmt.Sprintf("Second factors of %s removed; their sessions ended", config.Repr(target)))), nil
}
