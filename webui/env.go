package webui

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// Env is everything the webUI takes from the system: the clock, the
// random bytes, where its files are, and the helpers' sockets. The
// differential test replays 1.x's sessions with a recorded clock and
// byte stream (reference/test_fros_webui_cases.py), so every random
// value is drawn in the order and size 1.x draws it.
type Env struct {
	// Now is time.time(): seconds since the epoch.
	Now func() float64
	// Rand is secrets.token_bytes's source.
	Rand io.Reader
	// Local is the zone time.localtime formats in.
	Local *time.Location
	Paths Paths
	// Send is one request to a helper's socket and its decoded reply,
	// or a transport error (1.x's frfw.helper.client.send_command).
	Send func(socket string, cmd *config.Map, timeout float64, maxBytes int) (config.Value, error)
	// Run is a program run for the read-only views (systemctl
	// is-active, ...): its exit status and output.
	Run func(argv []string, timeout float64) (status int, stdout string, err error)
	// Kernel is os.uname().release.
	Kernel func() string
	// CPUs is os.cpu_count(), 0 when not known.
	CPUs func() int
	// Disk is the used and total bytes of the file system at path
	// (statvfs), ok false when it can't be read.
	Disk func(path string) (used, total int64, ok bool)
}

// Paths are 1.x's frfw.paths the webUI uses, all under Root.
type Paths struct {
	Root string
	// ConfigFile, when set, is config.yaml (fr-webui --config).
	ConfigFile string
}

func (p Paths) at(path string) string { return filepath.Join(p.Root, path) }

// The files, as 1.x's frfw.paths names them.
func (p Paths) Config() string {
	if p.ConfigFile != "" {
		return p.ConfigFile
	}
	return p.at("/etc/fr_os/config.yaml")
}
func (p Paths) WebUIState() string  { return p.at("/etc/fr_os/webui") }
func (p Paths) Auth() string        { return p.at("/etc/fr_os/webui/auth.json") }
func (p Paths) SecretKey() string   { return p.at("/etc/fr_os/webui/secret.key") }
func (p Paths) Sessions() string    { return p.at("/etc/fr_os/webui/sessions.json") }
func (p Paths) LoginGuard() string  { return p.at("/etc/fr_os/webui/login_guard.json") }
func (p Paths) AlertsSeen() string  { return p.at("/etc/fr_os/webui/alerts_seen.json") }
func (p Paths) AuditLog() string    { return p.at("/var/log/fr_os/audit.log") }
func (p Paths) UpdateCheck() string { return p.at("/etc/fr_os/update_check.json") }
func (p Paths) ApplySocket() string { return p.at("/run/fr_os/apply.sock") }
func (p Paths) UpdateSocket() string {
	return p.at("/run/fr_os/update.sock")
}

// DefaultEnv is the router's: the real clock, crypto/rand, local time,
// the real paths and sockets.
func DefaultEnv() Env {
	return Env{
		Now:    func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
		Rand:   rand.Reader,
		Local:  time.Local,
		Send:   sendCommand,
		Run:    runProgram,
		Kernel: kernelRelease,
		CPUs:   runtime.NumCPU,
		Disk:   diskUsage,
	}
}

func (e Env) bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(e.Rand, b); err != nil {
		// crypto/rand does not fail on Linux; a replay that runs out of
		// recorded bytes is a test failure.
		panic(fmt.Sprintf("webui: random bytes: %v", err))
	}
	return b
}

// tokenURLSafe is secrets.token_urlsafe(n).
func (e Env) tokenURLSafe(n int) string { return b64(e.bytes(n)) }

// tokenHex is secrets.token_hex(n).
func (e Env) tokenHex(n int) string { return hex.EncodeToString(e.bytes(n)) }

// seconds is int(time.time()).
func (e Env) seconds() int64 { return int64(e.Now()) }

func kernelRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func diskUsage(path string) (int64, int64, bool) {
	var st syscall.Statfs_t
	if syscall.Statfs(path, &st) != nil {
		return 0, 0, false
	}
	return st.Frsize * int64(st.Blocks-st.Bfree), st.Frsize * int64(st.Blocks), true
}
