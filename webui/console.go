package webui

import (
	"io"
	"path/filepath"

	"github.com/starsmash29/fr_os-community/config"
)

// ConsoleAccounts is the webUI's accounts as firewall-cli reaches them
// from the console, as root: the recovery path that always grants the
// admin role (set-admin-password), first boot's generated password, the
// check that takes it off the console once it no longer signs in, and a
// lost second factor's reset (mfa-reset). The files are the webUI's own
// (auth.json and sessions.json in its state directory).
type ConsoleAccounts struct {
	store    *AdminStore
	sessions *sessionStore
	env      Env
}

// NewConsoleAccounts opens the accounts in stateDir (/etc/fr_os/webui);
// rand is where new passwords and salts come from, now the clock.
func NewConsoleAccounts(stateDir string, rand io.Reader, now func() float64) *ConsoleAccounts {
	env := Env{Rand: rand, Now: now}
	return &ConsoleAccounts{
		store:    &AdminStore{path: filepath.Join(stateDir, "auth.json"), env: env},
		sessions: &sessionStore{path: filepath.Join(stateDir, "sessions.json"), env: env},
		env:      env,
	}
}

// GeneratePassword is secrets.token_urlsafe(18): first boot's password.
func (c *ConsoleAccounts) GeneratePassword() string { return c.env.tokenURLSafe(18) }

// SetAdmin creates the account, or changes its password, with the admin
// role; mustChange makes the first sign-in ask for the admin's own name
// and password (security-lessons G1).
func (c *ConsoleAccounts) SetAdmin(username, password string, mustChange bool) error {
	return c.store.SetPassword(username, password, RoleAdmin, mustChange)
}

// PasswordProblem is why the password is refused for username (G6), or
// "".
func PasswordProblem(password, username string) string { return passwordProblem(password, username) }

// SignsIn is whether password still signs in as username. Only a check:
// never a sign-in, which may replace an old hash (and the unit that
// asks can't write the account file).
func (c *ConsoleAccounts) SignsIn(username, password string) (bool, error) {
	account, err := c.store.Get(username)
	if err != nil || account == nil {
		return false, err
	}
	return verifyPassword(password, account.PasswordHash), nil
}

// ResetMFA removes every second factor of username and ends its
// sessions: one secured by the lost factor shouldn't outlive it.
func (c *ConsoleAccounts) ResetMFA(username string) error {
	if _, err := c.store.SetMFA(username, config.NewMap()); err != nil {
		return err
	}
	_, err := c.sessions.revokeUser(username)
	return err
}

// IsAccountError is whether err is a refused account change (a bad name,
// role or password, the last admin, no such user), which firewall-cli
// prints as "error: ...".
func IsAccountError(err error) bool {
	_, ok := err.(*AccountError)
	return ok
}
