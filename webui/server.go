package webui

import (
	"bytes"
	"crypto/md5"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
)

// The webUI (1.x's frfw.webui.app): server-rendered pages, no
// JavaScript framework, nothing from the internet (G11). It runs
// unprivileged; root work goes through the apply-helper (A1, I1).

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// securityHeaders go on every answer (review v0.2.0 R15,
// security-lessons H1). No 'unsafe-inline' for scripts: every script is
// a static file and no template carries an inline <script> or on*=
// handler; inline style attributes remain.
var securityHeaders = [][2]string{
	{"Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; " +
		"form-action 'self';"},
	{"X-Frame-Options", "DENY"},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "strict-origin-when-cross-origin"},
	{"Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=(), usb=()"},
}

// Server is the webUI.
type Server struct {
	env               Env
	version, codename string
	store             *AdminStore
	sessions          *SessionManager
	helper            helper
	guard             *bruteforceGuard
	tickets           *ticketStore
	enrolments        *ticketStore
	// totpMu makes checking a TOTP code and recording its time step one
	// step, so two requests racing with the same code can't both pass.
	totpMu sync.Mutex
	pages  map[string]*template.Template
}

// New is the webUI for env, showing version and codename as the
// installed release.
func New(env Env, version, codename string) (*Server, error) {
	sessions, err := newSessionManager(env)
	if err != nil {
		return nil, err
	}
	s := &Server{env: env, version: version, codename: codename, store: newAdminStore(env), sessions: sessions,
		helper: helper{env}, tickets: newTicketStore(env, TicketSeconds), enrolments: newTicketStore(env, 600)}
	s.guard = newBruteforceGuard(env, env.Paths.LoginGuard(), deviceLookup(s.helper))
	s.pages = map[string]*template.Template{}
	base := template.Must(template.New("").ParseFS(templateFS, "templates/base.html", "templates/auth_head.html"))
	for _, name := range []string{"login", "setup", "account", "users", "mfa_account", "mfa_login", "dashboard"} {
		t := template.Must(template.Must(base.Clone()).ParseFS(templateFS, "templates/"+name+".html"))
		s.pages[name] = t
	}
	return s, nil
}

// -- requests and answers ---------------------------------------------------------------

// httpError is FastAPI's HTTPException: JSON {"detail": ...}, with
// headers (a 303's Location).
type httpError struct {
	status   int
	detail   string
	location string
}

func (e *httpError) Error() string { return e.detail }

func seeOther(location string) *httpError {
	return &httpError{status: http.StatusSeeOther, detail: "See Other", location: location}
}

// errInternal is an exception 1.x doesn't catch: Starlette answers 500,
// plain text, before any middleware adds headers or an audit line.
var errInternal = errors.New("internal error")

type answer struct {
	status  int
	headers [][2]string
	body    []byte
}

func (a *answer) header(k, v string) { a.headers = append(a.headers, [2]string{k, v}) }

func redirect(location string) *answer {
	a := &answer{status: http.StatusSeeOther}
	a.header("location", starletteQuote(location))
	return a
}

// starletteQuote is RedirectResponse's quote(url, safe=...).
func starletteQuote(u string) string {
	const safe = ":/%#?=@[]!$&'()*+,;"
	var b strings.Builder
	for _, c := range []byte(u) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("_.-~", c) >= 0 ||
			strings.IndexByte(safe, c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func jsonAnswer(status int, body string) *answer {
	a := &answer{status: status, body: []byte(body)}
	a.header("content-type", "application/json")
	return a
}

func detailAnswer(e *httpError) *answer {
	a := &answer{status: e.status}
	if e.location != "" {
		a.header("location", e.location)
	}
	a.header("content-type", "application/json")
	a.body = []byte(`{"detail":` + jsonStr(e.detail) + `}`)
	return a
}

// request is one request as the routes see it.
type request struct {
	r       *http.Request
	path    string
	body    []byte
	query   form
	cookies map[string]string
	params  map[string]string
	f       *form
	fErr    error
	// user is request.state.user: set by requireLogin once the session
	// is good, also when it then refuses the request.
	user *Account
	csrf string
	// scheme, host and port are request.url's.
	scheme, host string
	port         int
}

func (q *request) form() (form, error) {
	if q.f == nil {
		f, err := readForm(q.r, q.body)
		q.f, q.fErr = &f, err
	}
	return *q.f, q.fErr
}

func (q *request) clientIP() string {
	host, _, err := net.SplitHostPort(q.r.RemoteAddr)
	if err != nil {
		if q.r.RemoteAddr == "" {
			return "0.0.0.0"
		}
		return q.r.RemoteAddr
	}
	return host
}

func (q *request) queryGet(name string) string { v, _ := q.query.get(name); return v }

// cookieParse is Starlette's cookie_parser: chunks split on ';', each
// "name=value" (or a bare value under the name ""), stripped, a quoted
// value unquoted as http.cookies does.
func cookieParse(header string) map[string]string {
	out := map[string]string{}
	for _, chunk := range strings.Split(header, ";") {
		key, val, ok := strings.Cut(chunk, "=")
		if !ok {
			key, val = "", chunk
		}
		key, val = config.PyStrip(key), config.PyStrip(val)
		if key != "" || val != "" {
			out[key] = cookieUnquote(val)
		}
	}
	return out
}

// cookieUnquote is http.cookies._unquote.
func cookieUnquote(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	s = s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		if i+3 < len(s)+0 && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			n, _ := strconv.ParseUint(s[i+1:i+4], 8, 16)
			b.WriteRune(rune(n))
			i += 3
			continue
		}
		b.WriteByte(s[i+1])
		i++
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// hostOf is request.url's hostname (lower case, no port, no brackets)
// and port from the Host header.
func hostOf(hostHeader string) (string, int) {
	host, port := hostHeader, ""
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i >= 0 {
			host, port = host[1:i], strings.TrimPrefix(host[i+1:], ":")
		}
	} else if i := strings.LastIndex(host, ":"); i >= 0 {
		host, port = host[:i], host[i+1:]
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		n = 0
	}
	return strings.ToLower(host), n
}

// -- the pipeline --------------------------------------------------------------------------

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeAnswer(w, &answer{status: http.StatusRequestEntityTooLarge, body: []byte("Request Entity Too Large")})
		return
	}
	q := &request{r: r, path: r.URL.Path, body: body, params: map[string]string{}, scheme: "http"}
	if r.TLS != nil {
		q.scheme = "https"
	}
	q.host, q.port = hostOf(r.Host)
	q.query, _ = parseQuery(r.URL.RawQuery)
	q.cookies = map[string]string{}
	if values := r.Header.Values("Cookie"); len(values) > 0 {
		q.cookies = cookieParse(values[0])
	}
	a, err := s.handle(q)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
		return
	}
	for _, h := range securityHeaders {
		a.header(strings.ToLower(h[0]), h[1])
	}
	if q.user != nil && r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
		entry := config.NewMap()
		entry.Set("user", q.user.Username)
		entry.Set("role", q.user.Role)
		entry.Set("client", q.clientIP())
		entry.Set("method", r.Method)
		entry.Set("path", q.path)
		entry.Set("status", bigInt(a.status))
		s.auditAppend(entry)
	}
	writeAnswer(w, a)
}

func parseQuery(raw string) (form, error) {
	f := form{values: map[string]string{}, has: true}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		f.values[pyUnquotePlus([]byte(name))] = pyUnquotePlus([]byte(value))
	}
	return f, nil
}

func bigInt(n int) *big.Int { return big.NewInt(int64(n)) }

func md5Hex(data []byte) string {
	sum := md5.Sum(data)
	return hex.EncodeToString(sum[:])
}

func writeAnswer(w http.ResponseWriter, a *answer) {
	for _, h := range a.headers {
		w.Header().Add(h[0], h[1])
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(a.body)))
	w.WriteHeader(a.status)
	w.Write(a.body)
}

// route is one of 1.x's routes; handler nil marks one not ported yet,
// which still checks the sign-in as 1.x does before anything else.
type route struct {
	method, pattern string
	auth            string // "", "login" or "admin"
	handler         func(*Server, *request) (*answer, error)
}

func (rt route) match(path string) (map[string]string, bool) {
	want := strings.Split(rt.pattern, "/")
	got := strings.Split(path, "/")
	if len(want) != len(got) {
		return nil, false
	}
	params := map[string]string{}
	for i, w := range want {
		if strings.HasPrefix(w, "{") {
			if got[i] == "" {
				return nil, false
			}
			params[w[1:len(w)-1]] = got[i]
			continue
		}
		if w != got[i] {
			return nil, false
		}
	}
	return params, true
}

func (s *Server) handle(q *request) (*answer, error) {
	if strings.HasPrefix(q.path, "/static/") || q.path == "/static" {
		return s.static(q), nil
	}
	method := q.r.Method
	var partial *route
	for i := range routes {
		rt := &routes[i]
		params, ok := rt.match(q.path)
		if !ok {
			continue
		}
		if rt.method != method {
			if partial == nil {
				partial = rt
			}
			continue
		}
		q.params = params
		return s.run(rt, q)
	}
	if partial != nil {
		// The first route with this path answers, naming its method.
		a := jsonAnswer(http.StatusMethodNotAllowed, `{"detail":"Method Not Allowed"}`)
		a.headers = append([][2]string{{"allow", partial.method}}, a.headers...)
		return a, nil
	}
	if q.path != "/" {
		other := q.path + "/"
		if strings.HasSuffix(q.path, "/") {
			other = strings.TrimRight(q.path, "/")
		}
		for _, rt := range routes {
			if _, ok := rt.match(other); ok {
				target := q.scheme + "://" + q.r.Host + other
				if q.r.URL.RawQuery != "" {
					target += "?" + q.r.URL.RawQuery
				}
				a := &answer{status: http.StatusTemporaryRedirect}
				a.header("location", starletteQuote(target))
				return a, nil
			}
		}
	}
	return jsonAnswer(http.StatusNotFound, `{"detail":"Not Found"}`), nil
}

func (s *Server) run(rt *route, q *request) (*answer, error) {
	switch rt.auth {
	case "login", "admin":
		if _, err := s.requireLogin(q); err != nil {
			return errAnswer(err)
		}
		if rt.auth == "admin" && !q.user.IsAdmin() {
			return detailAnswer(&httpError{status: http.StatusForbidden, detail: "Admins only"}), nil
		}
	}
	if rt.handler == nil {
		return jsonAnswer(http.StatusNotImplemented, `{"detail":"Not ported to FR_OS 2 yet"}`), nil
	}
	a, err := rt.handler(s, q)
	if err != nil {
		return errAnswer(err)
	}
	return a, nil
}

func errAnswer(err error) (*answer, error) {
	var he *httpError
	if errors.As(err, &he) {
		return detailAnswer(he), nil
	}
	var ve validationError
	if errors.As(err, &ve) {
		return jsonAnswer(http.StatusUnprocessableEntity, detailJSON(ve)), nil
	}
	return nil, err
}

// validationError is FastAPI's RequestValidationError: a 422.
type validationError []fieldError

func (v validationError) Error() string { return "validation error" }

// fields reads a route's Form fields: a form that can't be read is
// Starlette's 400, a missing or malformed field FastAPI's 422.
func (q *request) fields(read func(*formParams)) error {
	f, err := q.form()
	if err != nil {
		return &httpError{status: http.StatusBadRequest, detail: "There was an error parsing the body"}
	}
	p := &formParams{f: f}
	read(p)
	if len(p.errors) > 0 {
		return validationError(p.errors)
	}
	return nil
}

const (
	mfaEnrolPrefix = "/account/mfa"
)

var viewerAllowed = map[string]bool{"/logout": true, "/account/password": true, "/account/logout-everywhere": true,
	"/account/mfa/totp": true, "/account/mfa/webauthn/options": true, "/account/mfa/webauthn/register": true,
	"/account/mfa/remove": true}

var setupPaths = map[string]bool{"/setup": true, "/logout": true}

// requireLogin is 1.x's deps.require_login, which every protected route
// depends on: it re-reads the account on each request, records it for
// the templates and the audit log, verifies the session's CSRF token on
// every change, and enforces the role in one place.
func (s *Server) requireLogin(q *request) (string, error) {
	cookie := q.cookies[CookieName]
	username, version, ok := s.sessions.Session(cookie)
	var account *Account
	if ok {
		a, err := s.store.Get(username)
		if err != nil {
			return "", err
		}
		account = a
	}
	if account == nil || version != account.SessionVersion() {
		return "", seeOther("/login")
	}
	q.user = account
	q.csrf = s.sessions.CSRFToken(cookie)
	if account.MustChange && !setupPaths[q.path] {
		return "", seeOther("/setup")
	}
	if account.IsAdmin() && !account.HasMFA() && !strings.HasPrefix(q.path, mfaEnrolPrefix) && !setupPaths[q.path] &&
		s.store.RequireMFA() {
		return "", seeOther(mfaEnrolPrefix)
	}
	if m := q.r.Method; m != "GET" && m != "HEAD" && m != "OPTIONS" {
		good, err := s.sessions.VerifyCSRF(cookie, q.submittedCSRF())
		if err != nil {
			return "", err
		}
		if !good {
			return "", &httpError{status: http.StatusForbidden, detail: "CSRF token missing or invalid"}
		}
		if !account.IsAdmin() && !viewerAllowed[q.path] {
			return "", &httpError{status: http.StatusForbidden, detail: "This account is read-only (viewer role)"}
		}
	}
	return account.Username, nil
}

// submittedCSRF is the token the request carries: the X-CSRF-Token or
// X-CSRFToken header, else the csrf_token field of a JSON or form body.
// Never the query string, which lands in logs and Referer headers.
func (q *request) submittedCSRF() string {
	for _, h := range []string{"X-Csrf-Token", "X-Csrftoken"} {
		if v := q.r.Header.Get(h); v != "" {
			return v
		}
	}
	ct := strings.ToLower(q.r.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		v, err := config.ParseJSONLastWins(q.body)
		if err != nil {
			return ""
		}
		m, ok := v.(*config.Map)
		if !ok {
			return ""
		}
		t, _ := m.Get("csrf_token")
		s, _ := t.(string)
		return s
	}
	f, err := q.form()
	if err != nil {
		return ""
	}
	v, _ := f.get("csrf_token")
	return v
}

// -- pages ----------------------------------------------------------------------------------

type navItem struct {
	Label, Href, Icon string
	Active            bool
}

type navSection struct {
	Section string
	Items   []navItem
}

type navEntry struct {
	label, href, icon string
	adminOnly         bool
}

// nav is the sidebar: icons are symbol ids in static/icons.svg.
var nav = []struct {
	section string
	items   []navEntry
}{
	{"Core", []navEntry{{"Dashboard", "/", "dashboard", false}}},
	{"Network", []navEntry{{"Interfaces", "/interfaces", "settings_ethernet", false},
		{"Segments", "/segments", "lan", false}, {"Rules", "/rules", "security", false},
		{"NAT", "/nat", "alt_route", false}, {"DHCP", "/dhcp", "dynamic_form", false}, {"VPN", "/vpn", "key", false}}},
	{"Protection", []navEntry{{"AI IDS/IPS", "/ai-ids", "psychology", false},
		{"TLS SNI Filter", "/xdp", "filter_alt", false}, {"Ad-Block", "/adblock", "block", false},
		{"IoT Devices", "/iot", "devices", false}, {"Applications", "/apps", "apps", false},
		{"TLS Fingerprints", "/tls", "fingerprint", false}, {"ZTNA Gate", "/ztna", "vpn_lock", false}}},
	{"System", []navEntry{{"Update", "/update", "system_update_alt", false}, {"System", "/system", "tune", false},
		{"Attack surface", "/surface", "shield_lock", false}, {"Security score", "/security", "verified_user", false},
		{"Users", "/users", "group", true}}},
}

func navMatches(path, href string) bool {
	if href == "/" {
		return path == href
	}
	return path == href || strings.HasPrefix(path, href+"/")
}

type here struct{ Section, Label string }

// page is what every template gets.
type page struct {
	s           *Server
	q           *request
	Username    string
	Error       string
	Success     string
	MinPassword int
	Data        any
}

func (p *page) CSRF() string { return p.q.csrf }

func (p *page) CSRFInput() template.HTML {
	if p.q.csrf == "" {
		return ""
	}
	return template.HTML(`<input type="hidden" name="csrf_token" value="` + template.HTMLEscapeString(p.q.csrf) + `">`)
}

func (p *page) Version() string  { return p.s.version }
func (p *page) Codename() string { return p.s.codename }
func (p *page) IsViewer() bool   { return p.q.user != nil && !p.q.user.IsAdmin() }

// Hostname is shell_hostname: the router's name from the config the
// webUI edits, read on every page so it is right straight after a save.
func (p *page) Hostname() string {
	data, err := os.ReadFile(p.s.env.Paths.Config())
	if errors.Is(err, os.ErrNotExist) {
		return "fr-router"
	}
	if err != nil || !utf8.Valid(data) {
		return "fr-router"
	}
	v, err := config.LoadYAML(string(data))
	if err != nil {
		return "fr-router"
	}
	m, ok := v.(*config.Map)
	if !ok {
		return "fr-router"
	}
	h, _ := m.Get("hostname")
	if !config.Truthy(h) {
		return "fr-router"
	}
	return pyStr(h)
}

func (p *page) Nav() []navSection {
	var out []navSection
	for _, sec := range nav {
		ns := navSection{Section: sec.section}
		for _, it := range sec.items {
			if it.adminOnly && (p.q.user == nil || !p.q.user.IsAdmin()) {
				continue
			}
			ns.Items = append(ns.Items, navItem{it.label, it.href, it.icon, navMatches(p.q.path, it.href)})
		}
		out = append(out, ns)
	}
	return out
}

func (p *page) Here() *here {
	for _, sec := range nav {
		for _, it := range sec.items {
			if navMatches(p.q.path, it.href) {
				return &here{sec.section, it.label}
			}
		}
	}
	if p.q.path == "/account" {
		return &here{"System", "Account"}
	}
	return nil
}

type updateNotice struct {
	Security bool
	Latest   string
}

// UpdateNotice is what the periodic update check found (G10), for the
// banner on every page.
func (p *page) UpdateNotice() *updateNotice {
	data, err := os.ReadFile(p.s.env.Paths.UpdateCheck())
	if err != nil {
		return nil
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil
	}
	if cur, _ := m.Get("current_version"); cur != p.s.version {
		return nil
	}
	avail, _ := m.Get("update_available")
	latest, _ := m.Get("latest_version")
	if !config.Truthy(avail) || !config.Truthy(latest) {
		return nil
	}
	sec, _ := m.Get("security")
	return &updateNotice{Security: config.Truthy(sec), Latest: pyStr(latest)}
}

type held struct {
	Pending, Rejected bool
	Remaining, By, ID string
	Addresses         string
}

// Held is an apply waiting for confirmation, or a reverted one whose
// config is kept (ROADMAP SEC-26), for the banner on every page.
// Nothing when the helper can't say.
func (p *page) Held() *held {
	reply, err := p.s.helper.ApplyStatus()
	if err != nil {
		return nil
	}
	ok, _ := reply.Get("ok")
	pending, _ := reply.Get("pending")
	rejected, _ := reply.Get("rejected")
	if !config.Truthy(ok) || !(config.Truthy(pending) || config.Truthy(rejected)) {
		return nil
	}
	h := &held{Pending: config.Truthy(pending), Rejected: config.Truthy(rejected)}
	if m, ok := pending.(*config.Map); ok {
		h.Remaining = jinjaStr(m, "remaining")
		h.By = jinjaStr(m, "by")
		h.ID = jinjaStr(m, "id")
		if by, _ := m.Get("by"); !config.Truthy(by) {
			h.By = ""
		}
		if list, ok := m.Get("addresses"); ok && config.Truthy(list) {
			if items, ok := list.([]config.Value); ok {
				parts := make([]string, len(items))
				for i, it := range items {
					parts[i] = pyStr(it)
				}
				h.Addresses = strings.Join(parts, ", ")
			}
		}
	}
	return h
}

// jinjaStr is how a template shows m[key]: missing is empty, None is
// "None".
func jinjaStr(m *config.Map, key string) string {
	v, ok := m.Get(key)
	if !ok {
		return ""
	}
	return pyStr(v)
}

func (s *Server) render(q *request, name string, p *page) (*answer, error) {
	p.s, p.q, p.MinPassword = s, q, MinPasswordLength
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "base", p); err != nil {
		return nil, err
	}
	a := &answer{status: http.StatusOK, body: buf.Bytes()}
	a.header("content-type", "text/html; charset=utf-8")
	return a, nil
}

// flash is the one-shot ?error= and ?success= messages.
func flash(q *request, p *page) *page {
	p.Error, p.Success = q.queryGet("error"), q.queryGet("success")
	return p
}

// -- static files -----------------------------------------------------------------------------

var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
	".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8",
}

// static serves the stylesheet, fonts, icons and scripts: public on
// purpose (the login page needs them), and they hold nothing about the
// router. The ETag is the content's digest (the files are in the
// binary, which has no file times).
func (s *Server) static(q *request) *answer {
	if q.r.Method != "GET" && q.r.Method != "HEAD" {
		a := &answer{status: http.StatusMethodNotAllowed, body: []byte("Method Not Allowed")}
		a.header("content-type", "text/plain; charset=utf-8")
		return a
	}
	name := strings.TrimPrefix(q.path, "/static/")
	data, err := fs.ReadFile(staticFS, "static/"+name)
	if err != nil || name == "" || strings.Contains(name, "..") {
		a := &answer{status: http.StatusNotFound, body: []byte("Not Found")}
		a.header("content-type", "text/plain; charset=utf-8")
		return a
	}
	ext := name[strings.LastIndex(name, "."):]
	ct := staticTypes[ext]
	if ct == "" {
		ct = "application/octet-stream"
	}
	etag := `"` + md5Hex(data) + `"`
	if match := q.r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		a := &answer{status: http.StatusNotModified}
		a.header("etag", etag)
		return a
	}
	a := &answer{status: http.StatusOK, body: data}
	a.header("content-type", ct)
	a.header("accept-ranges", "bytes")
	a.header("etag", etag)
	if q.r.Method == "HEAD" {
		a.body = nil
	}
	return a
}
