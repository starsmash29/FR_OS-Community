package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/starsmash29/fr_os-community/config"
)

// Sessions (1.x's frfw.webui.auth). A session is a signed, not
// encrypted, cookie -- {"username", "v": the account's session version,
// "sid"} -- and its id must also still be in the server's SessionStore
// (security-lessons G7), so signing out really ends it.

// CookieName is the session cookie.
const CookieName = "fr_os_session"

// SessionMaxAge is how long a session lasts, in seconds.
const SessionMaxAge = 12 * 3600

func loadOrCreateSecretKey(env Env, path string) ([]byte, error) {
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		return os.ReadFile(path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return nil, err
	}
	key := env.bytes(32)
	tmp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := os.WriteFile(tmp, key, 0o666); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return nil, err
	}
	return key, os.Rename(tmp, path)
}

// sessionStore is the sessions still valid, by the SHA-256 of their id
// (the file holds nothing a browser could present): 0600, next to the
// session key; if it is lost, everyone is signed out (fails closed).
type sessionStore struct {
	path string
	env  Env
	mu   sync.Mutex
}

func sidKey(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return hex.EncodeToString(sum[:])
}

func (s *sessionStore) load() *config.Map {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return config.NewMap()
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return config.NewMap()
	}
	m, ok := v.(*config.Map)
	if !ok {
		return config.NewMap()
	}
	return m
}

func (s *sessionStore) save(data *config.Map) error {
	text, err := config.PyJSON(data, -1, false)
	if err != nil {
		return err
	}
	return writePrivate(s.path, []byte(text), false)
}

func number(v config.Value) (float64, bool) {
	switch x := v.(type) {
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case *big.Int:
		f, _ := new(big.Float).SetInt(x).Float64()
		return f, true
	case float64:
		return x, true
	}
	return 0, false
}

func entryField(entry config.Value, key string) (config.Value, bool) {
	m, ok := entry.(*config.Map)
	if !ok {
		return nil, false
	}
	return m.Get(key)
}

func expiresAfter(entry config.Value, now float64) bool {
	v, ok := entryField(entry, "expires")
	if !ok {
		return 0 > now
	}
	f, ok := number(v)
	return ok && f > now
}

func (s *sessionStore) add(username string) (string, error) {
	sid := s.env.tokenURLSafe(32)
	now := s.env.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.load()
	kept := config.NewMap()
	for i, k := range data.Keys() {
		if expiresAfter(data.Values()[i], now) {
			kept.SetKey(k, data.Values()[i])
		}
	}
	entry := config.NewMap()
	entry.Set("user", username)
	entry.Set("expires", now+SessionMaxAge)
	kept.Set(sidKey(sid), entry)
	return sid, s.save(kept)
}

func (s *sessionStore) valid(sid, username string) bool {
	entry, _ := s.load().Get(sidKey(sid))
	user, _ := entryField(entry, "user")
	return user == username && expiresAfter(entry, s.env.Now())
}

func (s *sessionStore) revoke(sid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.load()
	if !data.Has(sidKey(sid)) {
		return nil
	}
	return s.save(without(data, func(k string, _ config.Value) bool { return k == sidKey(sid) }))
}

func (s *sessionStore) revokeUser(username string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := s.load()
	kept := without(data, func(_ string, v config.Value) bool {
		user, _ := entryField(v, "user")
		return user == username
	})
	if kept.Len() == data.Len() {
		return 0, nil
	}
	return data.Len() - kept.Len(), s.save(kept)
}

func without(m *config.Map, drop func(string, config.Value) bool) *config.Map {
	out := config.NewMap()
	for i, k := range m.Keys() {
		name, _ := k.(string)
		if !drop(name, m.Values()[i]) {
			out.SetKey(k, m.Values()[i])
		}
	}
	return out
}

// SessionManager signs session cookies and checks them against the
// SessionStore, and derives each session's CSRF token (review v0.2.0
// R15): HMAC-SHA256(secret, "csrf:" + sid).
type SessionManager struct {
	env      Env
	secret   []byte
	signer   signer
	sessions *sessionStore
}

func newSessionManager(env Env) (*SessionManager, error) {
	key, err := loadOrCreateSecretKey(env, env.Paths.SecretKey())
	if err != nil {
		return nil, err
	}
	return &SessionManager{env: env, secret: key, signer: newSigner(key),
		sessions: &sessionStore{path: env.Paths.Sessions(), env: env}}, nil
}

// CreateCookie is a new session for account and its cookie value.
func (m *SessionManager) CreateCookie(a *Account) (string, error) {
	sid, err := m.sessions.add(a.Username)
	if err != nil {
		return "", err
	}
	payload := `{"username":` + config.PyJSONString(a.Username) + `,"v":` + config.PyJSONString(a.SessionVersion()) +
		`,"sid":` + config.PyJSONString(sid) + `}`
	return m.signer.dumps([]byte(payload), m.env.seconds()), nil
}

type cookieData struct {
	username, sid string
	// v is str(data.get("v", "")): the session version it was made for.
	v string
}

// pyStr is Python's str() of a JSON value, for the session version a
// cookie carries (an int compares as its digits, as in 1.x).
func pyStr(v config.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case *big.Int:
		return x.String()
	case float64:
		return config.FloatRepr(x)
	}
	return config.Repr(v)
}

func (m *SessionManager) load(cookie string) (*cookieData, bool) {
	if cookie == "" {
		return nil, false
	}
	payload, err := m.signer.loads(cookie, SessionMaxAge, m.env.seconds())
	if err != nil {
		return nil, false
	}
	v, err := config.ParseJSONLastWins(payload)
	if err != nil {
		return nil, false
	}
	data, ok := v.(*config.Map)
	if !ok {
		return nil, false
	}
	user, _ := data.Get("username")
	sid, _ := data.Get("sid")
	u, ok1 := user.(string)
	s, ok2 := sid.(string)
	if !ok1 || !ok2 {
		return nil, false
	}
	version := ""
	if raw, ok := data.Get("v"); ok {
		version = pyStr(raw)
	}
	return &cookieData{username: u, sid: s, v: version}, true
}

func (m *SessionManager) live(cookie string) (*cookieData, bool) {
	d, ok := m.load(cookie)
	if !ok || !m.sessions.valid(d.sid, d.username) {
		return nil, false
	}
	return d, true
}

func (m *SessionManager) csrfFor(sid string) string {
	h := hmac.New(sha256.New, m.secret)
	h.Write([]byte("csrf:" + sid))
	return hex.EncodeToString(h.Sum(nil))
}

// CSRFToken is the CSRF token of the cookie's live session, or "".
func (m *SessionManager) CSRFToken(cookie string) string {
	d, ok := m.live(cookie)
	if !ok {
		return ""
	}
	return m.csrfFor(d.sid)
}

// errNotASCII is compare_digest's TypeError on a str that isn't ASCII:
// 1.x answers 500 for it.
var errNotASCII = errors.New("webui: a CSRF token that is not ASCII")

// VerifyCSRF is whether token is the CSRF token of the cookie's live
// session.
func (m *SessionManager) VerifyCSRF(cookie, token string) (bool, error) {
	if cookie == "" || token == "" {
		return false, nil
	}
	d, ok := m.live(cookie)
	if !ok || d.sid == "" {
		return false, nil
	}
	for i := 0; i < len(token); i++ {
		if token[i] >= 0x80 {
			return false, errNotASCII
		}
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(m.csrfFor(d.sid))) == 1, nil
}

// Session is (username, session version) of a valid, unexpired cookie
// whose session the server still has.
func (m *SessionManager) Session(cookie string) (string, string, bool) {
	d, ok := m.live(cookie)
	if !ok {
		return "", "", false
	}
	return d.username, d.v, true
}

// RevokeCookie ends the cookie's session on the server (sign-out).
func (m *SessionManager) RevokeCookie(cookie string) error {
	if d, ok := m.load(cookie); ok {
		return m.sessions.revoke(d.sid)
	}
	return nil
}

// RevokeUser ends every session of username.
func (m *SessionManager) RevokeUser(username string) (int, error) {
	return m.sessions.revokeUser(username)
}
