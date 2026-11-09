package webui

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/scrypt"

	"github.com/starsmash29/fr_os-community/config"
)

// The local accounts that sign in to the webUI, as 1.x's
// frfw.admin_account keeps them, in the same file
// (/etc/fr_os/webui/auth.json) and format, so an upgrade keeps every
// account, password and second factor:
//
//	{"version": 2, "users": {name: {"password_hash", "role",
//	 ["must_change": true], ["mfa": {...}]}}, ["policy": {...}]}
//
// Roles: admin (everything) and viewer (every screen read-only; only its
// own password and second factors). The store always keeps an admin.

const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

var roles = []string{RoleAdmin, RoleViewer}

// Security-lessons G2: scrypt with OWASP's N=2^15, r=8, p=3 (32 MiB per
// check), stored as scrypt$N$r$p$salt$digest. A stored hash can't ask
// for less work than that (H1). PBKDF2-SHA256 hashes from before G2
// (at least 200 000 iterations) still verify and are replaced on the
// next successful sign-in.
const (
	scryptN       = 1 << 15
	scryptR       = 8
	scryptP       = 3
	scryptMinCost = scryptN * scryptR * scryptP
	scryptMaxMem  = 256 * 1024 * 1024
	minPBKDF2     = 200_000
)

var usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// reservedUsernames are the names first-run setup refuses: the ones
// every credential-stuffing list tries first (security-lessons G1).
var reservedUsernames = map[string]bool{"admin": true, "administrator": true, "root": true, "user": true,
	"fr_os": true, "fros": true}

// AccountError is a refused account change; its text is shown as is.
type AccountError struct{ Msg string }

func (e *AccountError) Error() string { return e.Msg }

func accountErr(format string, args ...any) error { return &AccountError{fmt.Sprintf(format, args...)} }

// Account is one webUI account.
type Account struct {
	Username     string
	PasswordHash string
	Role         string
	// MustChange marks the account first boot generates: its first
	// sign-in goes to the setup step before anything else.
	MustChange bool
	// MFA is the second factors (security-lessons G5), as stored:
	// {"totp": {"secret", "last_step"}, "webauthn": [{"id",
	// "public_key", "sign_count", "rp_id", "name", "added"}]}.
	MFA *config.Map
}

func (a *Account) IsAdmin() bool { return a.Role == RoleAdmin }

// HasMFA is bool(totp) or bool(webauthn).
func (a *Account) HasMFA() bool {
	t, _ := a.MFA.Get("totp")
	w, _ := a.MFA.Get("webauthn")
	return config.Truthy(t) || config.Truthy(w)
}

// SessionVersion changes whenever the password does: a session cookie
// carries it, so a new password ends every session opened with the old
// one.
func (a *Account) SessionVersion() string {
	sum := sha256.Sum256([]byte(a.PasswordHash))
	return hex.EncodeToString(sum[:])[:16]
}

func (a *Account) withMFA(m *config.Map) *Account {
	c := *a
	c.MFA = m
	return &c
}

func hashPassword(env Env, password string) string {
	salt := env.bytes(16)
	digest, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		panic(err) // fixed, valid parameters
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s", scryptN, scryptR, scryptP, hex.EncodeToString(salt),
		hex.EncodeToString(digest))
}

// verifyPassword is whether password matches stored. It fails closed on
// anything it doesn't fully understand or that is weaker than the floors.
func verifyPassword(password, stored string) bool {
	fields := strings.Split(stored, "$")
	var actual, expected []byte
	switch {
	case fields[0] == "scrypt" && len(fields) == 6:
		var nrp [3]*big.Int
		for i := range nrp {
			n, ok := config.PyInt(fields[1+i])
			if !ok {
				return false
			}
			nrp[i] = n
		}
		salt, ok1 := pyFromHex(fields[4])
		want, ok2 := pyFromHex(fields[5])
		if !ok1 || !ok2 {
			return false
		}
		cost := new(big.Int).Mul(nrp[0], nrp[1])
		cost.Mul(cost, nrp[2])
		n, r, p := nrp[0], nrp[1], nrp[2]
		pow2 := new(big.Int).And(n, new(big.Int).Sub(n, big.NewInt(1)))
		if cost.Cmp(big.NewInt(scryptMinCost)) < 0 || r.Cmp(big.NewInt(scryptR)) < 0 || pow2.Sign() != 0 ||
			len(salt) < 16 || len(want) != 32 {
			return false
		}
		// hashlib.scrypt's own limits: N a power of two above 1, and
		// OpenSSL's memory need within maxmem (256 MiB).
		if !n.IsInt64() || !r.IsInt64() || !p.IsInt64() || n.Int64() < 2 || p.Sign() <= 0 {
			return false
		}
		ni, ri, pi := n.Int64(), r.Int64(), p.Int64()
		if ri > 1<<24 || pi > 1<<24 || ni > 1<<40 || 128*ri*(ni+2)+128*ri*pi > scryptMaxMem {
			return false
		}
		got, err := scrypt.Key([]byte(password), salt, int(ni), int(ri), int(pi), 32)
		if err != nil {
			return false
		}
		actual, expected = got, want
	case fields[0] == "pbkdf2_sha256" && len(fields) == 4:
		iterations, ok := config.PyInt(fields[1])
		salt, ok1 := pyFromHex(fields[2])
		want, ok2 := pyFromHex(fields[3])
		if !ok || !ok1 || !ok2 || iterations.Cmp(big.NewInt(minPBKDF2)) < 0 || len(salt) < 16 || len(want) != 32 ||
			!iterations.IsInt64() || iterations.Int64() > 1<<31-1 {
			return false
		}
		got, err := pbkdf2.Key(sha256.New, password, salt, int(iterations.Int64()), 32)
		if err != nil {
			return false
		}
		actual, expected = got, want
	default:
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func needsRehash(stored string) bool {
	return !strings.HasPrefix(stored, fmt.Sprintf("scrypt$%d$%d$%d$", scryptN, scryptR, scryptP))
}

// pyFromHex is bytes.fromhex(text): pairs of hex digits, ASCII
// whitespace allowed between them.
func pyFromHex(text string) ([]byte, bool) {
	var out []byte
	for i := 0; i < len(text); {
		switch text[i] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			i++
			continue
		}
		if i+1 >= len(text) {
			return nil, false
		}
		b, err := hex.DecodeString(text[i : i+2])
		if err != nil {
			return nil, false
		}
		out = append(out, b[0])
		i += 2
	}
	return out, true
}

func validateUsername(name string) error {
	if !usernameRE.MatchString(name) {
		return accountErr("Username must start with a lowercase letter or '_' and use only " +
			"lowercase letters, digits, '_', '.', '-' (max 32 characters)")
	}
	return nil
}

func validatePassword(password, username string) error {
	if reason := passwordProblem(password, username); reason != "" {
		return &AccountError{reason}
	}
	return nil
}

// AdminStore reads and writes the account file. Every change is a
// read-modify-write done under an exclusive flock on the file's
// directory (security-lessons J1): the webUI serves requests in
// parallel and firewall-cli is another process. Readers need no lock:
// the file is replaced atomically.
type AdminStore struct {
	path string
	env  Env
	mu   sync.Mutex
}

func newAdminStore(env Env) *AdminStore { return &AdminStore{path: env.Paths.Auth(), env: env} }

// lock runs fn holding the store's lock: in this process, then across
// processes (the directory, not the file: the file is replaced on every
// write, a lock on it would be on the old inode).
func (s *AdminStore) lock(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return err
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	return fn()
}

func (s *AdminStore) read() (*config.Map, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil, err
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, errors.New("webui: the account file is not a JSON object")
	}
	return m, nil
}

// Users are the accounts by name, in the file's order.
func (s *AdminStore) Users() (map[string]*Account, []string, error) {
	data, err := s.read()
	if err != nil || data == nil {
		return map[string]*Account{}, nil, err
	}
	str := func(m *config.Map, key string) (string, error) {
		v, ok := m.Get(key)
		if !ok {
			return "", fmt.Errorf("webui: account file: no %q", key)
		}
		text, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("webui: account file: %q is not a string", key)
		}
		return text, nil
	}
	users := map[string]*Account{}
	var order []string
	raw, ok := data.Get("users")
	if !ok { // the pre-phase-18 single-account file
		name, err := str(data, "username")
		if err != nil {
			return nil, nil, err
		}
		hash, err := str(data, "password_hash")
		if err != nil {
			return nil, nil, err
		}
		users[name] = &Account{Username: name, PasswordHash: hash, Role: RoleAdmin, MFA: config.NewMap()}
		return users, []string{name}, nil
	}
	list, ok := raw.(*config.Map)
	if !ok {
		return nil, nil, errors.New("webui: account file: users is not an object")
	}
	for i, k := range list.Keys() {
		name, _ := k.(string)
		entry, ok := list.Values()[i].(*config.Map)
		if !ok {
			return nil, nil, errors.New("webui: account file: an account is not an object")
		}
		hash, err := str(entry, "password_hash")
		if err != nil {
			return nil, nil, err
		}
		role := RoleAdmin
		if v, ok := entry.Get("role"); ok {
			role, _ = v.(string)
		}
		must, _ := entry.Get("must_change")
		mfa := config.NewMap()
		if v, _ := entry.Get("mfa"); config.Truthy(v) {
			if m, ok := v.(*config.Map); ok {
				mfa = copyMap(m)
			}
		}
		users[name] = &Account{Username: name, PasswordHash: hash, Role: role, MustChange: config.Truthy(must), MFA: mfa}
		order = append(order, name)
	}
	return users, order, nil
}

// Policy is the account-wide rules: {"require_mfa_for_admins": bool}.
func (s *AdminStore) Policy() (*config.Map, error) {
	data, err := s.read()
	if err != nil || data == nil {
		return config.NewMap(), err
	}
	if v, _ := data.Get("policy"); config.Truthy(v) {
		if m, ok := v.(*config.Map); ok {
			return copyMap(m), nil
		}
	}
	return config.NewMap(), nil
}

// RequireMFA is policy.get("require_mfa_for_admins"), truthy.
func (s *AdminStore) RequireMFA() bool {
	p, err := s.Policy()
	if err != nil {
		return false
	}
	v, _ := p.Get("require_mfa_for_admins")
	return config.Truthy(v)
}

// Exists is whether any account exists (none: the login page says to
// create one on the console).
func (s *AdminStore) Exists() (bool, error) {
	users, _, err := s.Users()
	return len(users) > 0, err
}

// Get is the account, or nil.
func (s *AdminStore) Get(username string) (*Account, error) {
	users, _, err := s.Users()
	if err != nil {
		return nil, err
	}
	return users[username], nil
}

// Verify is the account if the password is right, else nil. A hash
// from before security-lessons G2 is replaced by a scrypt one right
// here, on the successful sign-in.
func (s *AdminStore) Verify(username, password string) (*Account, error) {
	account, err := s.Get(username)
	if err != nil {
		return nil, err
	}
	if account == nil {
		// Still hash, so the timing doesn't tell whether the name exists.
		hashPassword(s.env, password)
		return nil, nil
	}
	if !verifyPassword(password, account.PasswordHash) {
		return nil, nil
	}
	if !needsRehash(account.PasswordHash) {
		return account, nil
	}
	var out *Account
	err = s.lock(func() error {
		users, order, err := s.Users()
		if err != nil {
			return err
		}
		current := users[username]
		if current == nil || current.PasswordHash != account.PasswordHash {
			// Changed meanwhile: check against what is there now.
			if current != nil && verifyPassword(password, current.PasswordHash) {
				out = current
			}
			return nil
		}
		c := *current
		c.PasswordHash = hashPassword(s.env, password)
		users[username] = &c
		out = &c
		return s.write(users, order, nil)
	})
	return out, err
}

func copyMap(m *config.Map) *config.Map {
	out := config.NewMap()
	for i, k := range m.Keys() {
		out.SetKey(k, m.Values()[i])
	}
	return out
}

// write replaces the file: 0600 from creation (security-lessons G3), and
// when written by root (firewall-cli, first boot) owned by whoever owns
// the state directory, the webUI's account. The accounts are sorted by
// name; policy nil keeps the file's.
func (s *AdminStore) write(users map[string]*Account, _ []string, policy *config.Map) error {
	if policy == nil {
		p, err := s.Policy()
		if err != nil {
			return err
		}
		policy = p
	}
	names := make([]string, 0, len(users))
	for name := range users {
		names = append(names, name)
	}
	sort.Strings(names)
	list := config.NewMap()
	for _, name := range names {
		a := users[name]
		entry := config.NewMap()
		entry.Set("password_hash", a.PasswordHash)
		entry.Set("role", a.Role)
		if a.MustChange {
			entry.Set("must_change", true)
		}
		if a.MFA != nil && a.MFA.Len() > 0 {
			entry.Set("mfa", a.MFA)
		}
		list.Set(name, entry)
	}
	data := config.NewMap()
	data.Set("version", big.NewInt(2))
	data.Set("users", list)
	if policy.Len() > 0 {
		data.Set("policy", policy)
	}
	text, err := config.PyJSON(data, 1, false)
	if err != nil {
		return err
	}
	return writePrivate(s.path, []byte(text), os.Geteuid() == 0)
}

// writePrivate is 1.x's tmp-then-replace with O_EXCL and mode 0600;
// chown hands the file to the owner of its directory (written by root).
func writePrivate(path string, data []byte, chown bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		return err
	}
	tmp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if chown {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Dir(path), &st); err != nil {
			return err
		}
		if err := os.Chown(tmp, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	return os.Rename(tmp, path)
}

func (s *AdminStore) change(fn func(users map[string]*Account) error) error {
	return s.lock(func() error {
		users, order, err := s.Users()
		if err != nil {
			return err
		}
		if err := fn(users); err != nil {
			return err
		}
		return s.write(users, order, nil)
	})
}

func keepsAnAdmin(users map[string]*Account, username, newRole string) error {
	for name, a := range users {
		if a.IsAdmin() && name != username {
			return nil
		}
	}
	if newRole == RoleAdmin {
		return nil
	}
	return accountErr("At least one admin account must remain")
}

func knownRole(role string) bool { return role == RoleAdmin || role == RoleViewer }

// SetPassword creates the account or changes its password. A new
// account gets role (default admin: also the CLI's recovery path); an
// existing one keeps its role unless role is given. A password change
// keeps the second factors.
func (s *AdminStore) SetPassword(username, password, role string, mustChange bool) error {
	return s.change(func(users map[string]*Account) error {
		return s.setPasswordIn(users, username, password, role, mustChange)
	})
}

func (s *AdminStore) setPasswordIn(users map[string]*Account, username, password, role string, mustChange bool) error {
	existing := users[username]
	newRole := role
	if newRole == "" {
		newRole = RoleAdmin
		if existing != nil {
			newRole = existing.Role
		}
	}
	if !knownRole(newRole) {
		return accountErr("Unknown role %s", config.Repr(newRole))
	}
	if err := keepsAnAdmin(users, username, newRole); err != nil {
		return err
	}
	mfa := config.NewMap()
	if existing != nil {
		mfa = copyMap(existing.MFA)
	}
	users[username] = &Account{Username: username, PasswordHash: hashPassword(s.env, password), Role: newRole,
		MustChange: mustChange, MFA: mfa}
	return nil
}

// CompleteSetup is first-run setup (security-lessons G1): the generated
// account becomes newUsername with the admin's own password; the
// generated name and password stop working at once.
func (s *AdminStore) CompleteSetup(current, newUsername, password string) (*Account, error) {
	if err := validateUsername(newUsername); err != nil {
		return nil, err
	}
	if reservedUsernames[newUsername] {
		return nil, accountErr("Choose a username other than %s -- it's the first one attackers try",
			config.Repr(newUsername))
	}
	if err := validatePassword(password, newUsername); err != nil {
		return nil, err
	}
	var out *Account
	err := s.change(func(users map[string]*Account) error {
		account := users[current]
		if account == nil || !account.MustChange {
			return accountErr("This account has already been set up")
		}
		if _, taken := users[newUsername]; newUsername != current && taken {
			return accountErr("User %s already exists", config.Repr(newUsername))
		}
		if verifyPassword(password, account.PasswordHash) {
			return accountErr("Choose a new password, not the generated one")
		}
		delete(users, current)
		out = &Account{Username: newUsername, PasswordHash: hashPassword(s.env, password), Role: account.Role,
			MFA: config.NewMap()}
		users[newUsername] = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AddUser adds an account with a role.
func (s *AdminStore) AddUser(username, password, role string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validatePassword(password, username); err != nil {
		return err
	}
	if !knownRole(role) {
		return accountErr("Unknown role %s", config.Repr(role))
	}
	return s.change(func(users map[string]*Account) error {
		if _, taken := users[username]; taken {
			return accountErr("User %s already exists", config.Repr(username))
		}
		return s.setPasswordIn(users, username, password, role, false)
	})
}

// SetRole changes an account's role.
func (s *AdminStore) SetRole(username, role string) error {
	if !knownRole(role) {
		return accountErr("Unknown role %s", config.Repr(role))
	}
	return s.change(func(users map[string]*Account) error {
		a := users[username]
		if a == nil {
			return accountErr("No such user %s", config.Repr(username))
		}
		if err := keepsAnAdmin(users, username, role); err != nil {
			return err
		}
		c := *a
		c.Role = role
		users[username] = &c
		return nil
	})
}

// DeleteUser removes an account.
func (s *AdminStore) DeleteUser(username string) error {
	return s.change(func(users map[string]*Account) error {
		if users[username] == nil {
			return accountErr("No such user %s", config.Repr(username))
		}
		if err := keepsAnAdmin(users, username, ""); err != nil {
			return err
		}
		delete(users, username)
		return nil
	})
}

// SetMFA replaces an account's second factors.
func (s *AdminStore) SetMFA(username string, mfa *config.Map) (*Account, error) {
	var out *Account
	err := s.change(func(users map[string]*Account) error {
		a := users[username]
		if a == nil {
			return accountErr("No such user %s", config.Repr(username))
		}
		out = a.withMFA(mfa)
		users[username] = out
		return nil
	})
	return out, err
}

// SetPolicy sets require_mfa_for_admins.
func (s *AdminStore) SetPolicy(requireMFA bool) error {
	return s.lock(func() error {
		users, order, err := s.Users()
		if err != nil {
			return err
		}
		policy, err := s.Policy()
		if err != nil {
			return err
		}
		policy.Set("require_mfa_for_admins", requireMFA)
		return s.write(users, order, policy)
	})
}
