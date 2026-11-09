package webui

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/starsmash29/fr_os-community/config"
)

// Second factors for signing in (1.x's frfw.webui.mfa, security-lessons
// G5): security keys and passkeys (WebAuthn, phishing-resistant: the
// browser binds each signature to the origin; only on a name, never on
// an IP address) and authenticator-app codes (TOTP, RFC 6238; each 30 s
// step accepted once). No protocol or crypto of our own (F4): WebAuthn
// is go-webauthn's, TOTP is the RFC's HMAC-SHA1.
//
// After the password, an account with a factor gets no session, only a
// login ticket: a random 256-bit id in a cookie, kept by the server for
// 5 minutes, usable once, bound to the account and its password
// version, dropped after 5 wrong codes.

const (
	TicketCookie        = "fr_os_mfa"
	TicketSeconds       = 300
	maxCodeAttempts     = 5
	maxAccountFailures  = 10
	accountLockSeconds  = 15 * 60
	totpIssuer          = "FR_OS"
	rpName              = "FR_OS router"
	webauthnChallengeSz = 64
)

// -- TOTP ----------------------------------------------------------------------------

// newTOTPSecret is pyotp.random_base32(): 32 base32 characters from 20
// random bytes.
func newTOTPSecret(env Env) string { return base32.StdEncoding.EncodeToString(env.bytes(20)) }

// pyQuote is urllib.parse.quote(s) (safe "/").
func pyQuote(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', strings.IndexByte("_.-~/", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// totpURI is pyotp's provisioning URI for the authenticator app.
func totpURI(secret, username, host string) string {
	args := "secret=" + strings.ReplaceAll(url.QueryEscape(secret), "+", "%20") +
		"&issuer=" + strings.ReplaceAll(url.QueryEscape(totpIssuer), "+", "%20")
	return "otpauth://totp/" + pyQuote(totpIssuer) + ":" + pyQuote(username+"@"+host) + "?" + args
}

// totpAt is pyotp.TOTP(secret).at(counter * 30).
func totpAt(secret string, counter int64) (string, error) {
	s := strings.ToUpper(secret)
	if r := len(s) % 8; r != 0 {
		s += strings.Repeat("=", 8-r)
	}
	key, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	sum := h.Sum(nil)
	off := sum[len(sum)-1] & 0xf
	code := (uint32(sum[off]&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])) % 1_000_000
	return fmt.Sprintf("%06d", code), nil
}

// totpStep is the time step code is valid for (now, or one either side
// for clock drift) if it is newer than lastStep -- a code works once --
// else ok is false.
func totpStep(secret, code string, lastStep int64, now float64) (int64, bool, error) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 {
		return 0, false, nil
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return 0, false, nil
		}
	}
	step := int64(math.Floor(now / 30))
	for _, candidate := range []int64{step - 1, step, step + 1} {
		if candidate <= lastStep {
			continue
		}
		want, err := totpAt(secret, candidate)
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return candidate, true, nil
		}
	}
	return 0, false, nil
}

// -- WebAuthn ------------------------------------------------------------------------

// rpIDFor is the relying-party id for the name the browser used, or ""
// where WebAuthn can't work: browsers refuse IP addresses as RP ids.
func rpIDFor(host string) string {
	if host == "" || config.CheckHostname(host) != nil {
		return ""
	}
	allDigits := true
	for _, part := range strings.Split(host, ".") {
		if !pyIsDigit(part) {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "" // an IPv4 address also passes the host-name syntax
	}
	return strings.ToLower(host)
}

// pyIsDigit is str.isdigit() for the ASCII a host name can hold.
func pyIsDigit(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func originFor(scheme, host string, port int) string {
	def := 80
	if scheme == "https" {
		def = 443
	}
	if port == 0 || port == def {
		return scheme + "://" + host
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// unb64 is base64.urlsafe_b64decode(text + padding).
func unb64(text string) ([]byte, error) { return pyB64Decode(text) }

func webauthnList(a *Account) []*config.Map {
	v, _ := a.MFA.Get("webauthn")
	list, _ := v.([]config.Value)
	var out []*config.Map
	for _, c := range list {
		if m, ok := c.(*config.Map); ok {
			out = append(out, m)
		}
	}
	return out
}

func mapStr(m *config.Map, key string) string {
	v, _ := m.Get(key)
	s, _ := v.(string)
	return s
}

func descriptors(a *Account, rpID string) (string, error) {
	var b strings.Builder
	b.WriteByte('[')
	n := 0
	for _, c := range webauthnList(a) {
		if v, _ := c.Get("rp_id"); v != rpID {
			continue
		}
		id, err := unb64(mapStr(c, "id"))
		if err != nil {
			return "", err
		}
		if n > 0 {
			b.WriteByte(',')
		}
		n++
		b.WriteString(`{"id":` + jsonStr(b64(id)) + `,"type":"public-key"}`)
	}
	b.WriteByte(']')
	return b.String(), nil
}

// jsonStr is a string as Starlette's JSONResponse writes it
// (ensure_ascii=False).
func jsonStr(s string) string {
	out, err := jsontext.AppendQuote(nil, s)
	if err != nil {
		return `""`
	}
	return string(out)
}

// registrationOptions is py_webauthn's options for enrolling a key, as
// the JSON 1.x sends, and the challenge.
func registrationOptions(env Env, a *Account, rpID string) (string, []byte, error) {
	exclude, err := descriptors(a, rpID)
	if err != nil {
		return "", nil, err
	}
	challenge := env.bytes(webauthnChallengeSz)
	userID := sha256.Sum256([]byte(a.Username))
	options := `{"rp":{"name":` + jsonStr(rpName) + `,"id":` + jsonStr(rpID) + `},` +
		`"user":{"id":` + jsonStr(b64(userID[:])) + `,"name":` + jsonStr(a.Username) + `,"displayName":` +
		jsonStr(a.Username) + `},"challenge":` + jsonStr(b64(challenge)) +
		`,"pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},` +
		`{"type":"public-key","alg":-257}],"timeout":60000,"excludeCredentials":` + exclude +
		`,"authenticatorSelection":{"residentKey":"discouraged","requireResidentKey":false,` +
		`"userVerification":"preferred"},"attestation":"none"}`
	return options, challenge, nil
}

// authenticationOptions is py_webauthn's options for signing in with
// the account's keys for rpID, and the challenge.
func authenticationOptions(env Env, a *Account, rpID string) (string, []byte, error) {
	allow, err := descriptors(a, rpID)
	if err != nil {
		return "", nil, err
	}
	challenge := env.bytes(webauthnChallengeSz)
	return `{"challenge":` + jsonStr(b64(challenge)) + `,"timeout":60000,"rpId":` + jsonStr(rpID) +
		`,"allowCredentials":` + allow + `,"userVerification":"preferred"}`, challenge, nil
}

var credentialParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

// verifyRegistration checks a new key's answer and is the credential to
// store: {"id", "public_key", "sign_count", "rp_id", "name", "added"}.
func verifyRegistration(env Env, credential []byte, challenge []byte, rpID, origin, name string) (*config.Map, error) {
	pcc, err := protocol.ParseCredentialCreationResponseBytes(credential)
	if err != nil {
		return nil, err
	}
	if _, err := pcc.Verify(b64(challenge), rpID, []string{origin}, nil, nil,
		protocol.TopOriginImplicitVerificationMode, true, false, true, nil, credentialParams,
		protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		return nil, err
	}
	data := pcc.Response.AttestationObject.AuthData
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Security key"
	}
	if utf8.RuneCountInString(name) > 40 {
		name = string([]rune(name)[:40])
	}
	key := config.NewMap()
	key.Set("id", b64(data.AttData.CredentialID))
	key.Set("public_key", b64(data.AttData.CredentialPublicKey))
	key.Set("sign_count", big.NewInt(int64(data.Counter)))
	key.Set("rp_id", rpID)
	key.Set("name", name)
	key.Set("added", big.NewInt(env.seconds()))
	return key, nil
}

var errUnknownKey = errors.New("this security key is not registered for this account")

// verifyAuthentication checks a key's sign-in answer and is the
// account's second factors with the key's new sign count; an error for
// an unknown key, a wrong origin or challenge, a bad signature, or a
// sign count that didn't go up.
func verifyAuthentication(a *Account, body []byte, challenge []byte, rpID, origin string) (*config.Map, error) {
	v, err := config.ParseJSONLastWins(body)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(*config.Map)
	if !ok {
		return nil, errors.New("not an object")
	}
	id, _ := obj.Get("id")
	var stored []config.Value
	var match *config.Map
	for _, c := range webauthnList(a) {
		copied := copyMap(c)
		stored = append(stored, copied)
		cid, _ := c.Get("id")
		if match == nil && cid == id && mapStr(c, "rp_id") == rpID {
			match = copied
		}
	}
	if match == nil {
		return nil, errUnknownKey
	}
	par, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, err
	}
	publicKey, err := unb64(mapStr(match, "public_key"))
	if err != nil {
		return nil, err
	}
	if err := par.Verify(b64(challenge), rpID, "", []string{origin}, nil, nil,
		protocol.TopOriginImplicitVerificationMode, true, false, true, publicKey, protocol.SignaturePolicy{}); err != nil {
		return nil, err
	}
	current := big.NewInt(0)
	if n, ok := match.Get("sign_count"); ok {
		if i, ok := n.(*big.Int); ok {
			current = i
		}
	}
	count := big.NewInt(int64(par.Response.AuthenticatorData.Counter))
	if (count.Sign() > 0 || current.Sign() > 0) && count.Cmp(current) <= 0 {
		return nil, fmt.Errorf("sign count %s was not greater than %s", count, current)
	}
	match.Set("sign_count", count)
	out := copyMap(a.MFA)
	out.Set("webauthn", stored)
	return out, nil
}

// -- login tickets and pending challenges ----------------------------------------------

type ticketEntry struct {
	user, version string
	expires       float64
	attempts      int
	challenge     []byte
	name          string
	totpSecret    string
	hasSecret     bool
}

// ticketStore is short-lived, single-use server-side state keyed by a
// random id: the login tickets between password and second factor, and
// the challenges of an enrolment in progress. In memory: a webUI
// restart just means signing in again.
type ticketStore struct {
	env      Env
	lifetime float64
	mu       sync.Mutex
	entries  map[string]*ticketEntry
	failures map[string][]float64
}

func newTicketStore(env Env, lifetime float64) *ticketStore {
	return &ticketStore{env: env, lifetime: lifetime, entries: map[string]*ticketEntry{},
		failures: map[string][]float64{}}
}

func ticketKey(tid string) string {
	sum := sha256.Sum256([]byte(tid))
	return hex.EncodeToString(sum[:])
}

func (t *ticketStore) create(a *Account) string {
	tid := t.env.tokenURLSafe(32)
	now := t.env.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.entries {
		if e.expires <= now {
			delete(t.entries, k)
		}
	}
	t.entries[ticketKey(tid)] = &ticketEntry{user: a.Username, version: a.SessionVersion(), expires: now + t.lifetime}
	return tid
}

// get is the live entry and its re-read account, or nil: expired,
// unknown, or the password changed since.
func (t *ticketStore) get(tid string, accountOf func(string) (*Account, error)) (*ticketEntry, *Account, error) {
	if tid == "" {
		return nil, nil, nil
	}
	t.mu.Lock()
	entry := t.entries[ticketKey(tid)]
	t.mu.Unlock()
	if entry == nil || entry.expires <= t.env.Now() {
		return nil, nil, nil
	}
	a, err := accountOf(entry.user)
	if err != nil || a == nil || a.SessionVersion() != entry.version {
		return nil, nil, err
	}
	return entry, a, nil
}

// accountLocked is whether username had too many wrong second factors
// lately.
func (t *ticketStore) accountLocked(username string) bool {
	cutoff := t.env.Now() - accountLockSeconds
	t.mu.Lock()
	defer t.mu.Unlock()
	var recent []float64
	for _, ts := range t.failures[username] {
		if ts > cutoff {
			recent = append(recent, ts)
		}
	}
	t.failures[username] = recent
	return len(recent) >= maxAccountFailures
}

// fail counts a wrong code; true while the ticket may still be used.
func (t *ticketStore) fail(tid string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[ticketKey(tid)]
	if entry == nil {
		return false
	}
	t.failures[entry.user] = append(t.failures[entry.user], t.env.Now())
	entry.attempts++
	if entry.attempts >= maxCodeAttempts {
		delete(t.entries, ticketKey(tid))
		return false
	}
	return true
}

// consume uses a ticket up; true only for the one caller that got it.
func (t *ticketStore) consume(tid string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.entries[ticketKey(tid)]; !ok {
		return false
	}
	delete(t.entries, ticketKey(tid))
	return true
}

// update changes a live entry's data under the lock (1.x's entry.data,
// which the routes write to and pop from).
func (t *ticketStore) update(tid string, fn func(*ticketEntry)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e := t.entries[ticketKey(tid)]; e != nil {
		fn(e)
	}
}
