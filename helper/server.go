package helper

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/ipc"
)

// Paths 1.x's helper uses (frfw.paths, frfw.kea, frfw.iot.leases).
const (
	SocketPath         = "/run/fr_os/apply.sock"
	ConfigPath         = "/etc/fr_os/config.yaml"
	BackupDir          = "/etc/fr_os/backups"
	KeaConfigPath      = "/etc/kea/kea-dhcp4.conf"
	ZtnaStatePath      = "/etc/fr_os/ztna_state.json"
	AdblockHostsPath   = "/etc/fr_os/adblock.hosts"
	KeaLeasesPath      = "/var/lib/kea/kea-leases4.csv"
	ApplyPendingPath   = "/etc/fr_os/apply-pending.json"
	RejectedConfigPath = "/etc/fr_os/config.rejected.yaml"
)

// Env is what the commands read and run: the paths the helper was
// started with, the nft it runs and the clock. Tests point it elsewhere.
type Env struct {
	ConfigPath, BackupDir, KeaConfigPath, ZtnaStatePath, AdblockHostsPath string
	KeaLeasesPath, ApplyPendingPath, RejectedConfigPath                   string
	// ApplyLockPath is the lock apply, confirm and revert share ("" is
	// Sys's).
	ApplyLockPath string
	// Sys is the system the mutating commands change (nil: the router's).
	Sys *apply.System

	Nft NftRunner
	// Now is the time as Python's time.time() gives it.
	Now func() float64
}

// DefaultEnv is the router's.
func DefaultEnv() Env {
	return Env{
		ConfigPath: ConfigPath, BackupDir: BackupDir, KeaConfigPath: KeaConfigPath, ZtnaStatePath: ZtnaStatePath,
		AdblockHostsPath: AdblockHostsPath, KeaLeasesPath: KeaLeasesPath, ApplyPendingPath: ApplyPendingPath,
		RejectedConfigPath: RejectedConfigPath,
		Nft:                RunNft,
		Now:                func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
	}
}

// invalidRequest is what 1.x answers with "invalid request: ..." (a
// ValueError or TypeError that reached its request handler).
type invalidRequest string

func (e invalidRequest) Error() string { return "invalid request: " + string(e) }

// errNoReply is where 1.x's handler dies on an exception it doesn't
// catch: the peer gets no reply, only the end of the stream.
var errNoReply = errors.New("helper: no reply")

// Server answers requests on a Unix socket.
type Server struct {
	Env Env
	// Policy is looked up for every connection, not once at start:
	// fr-accounts.service may create fr_os-sensor after the helper is
	// already running (the first boot after an update).
	Policy func() Policy
	// Log gets one line per refused request.
	Log io.Writer
	// ReadTimeout bounds the wait for a request line. 1.x waits forever,
	// one connection at a time, so a peer that connects and sends
	// nothing stops the helper; here it only holds its own connection.
	ReadTimeout time.Duration
	// MaxConns bounds the connections read at once.
	MaxConns int

	// run holds one request at a time: 1.x's socketserver serves one
	// connection after another, and its commands (an apply and its
	// confirmation, a ban during a reload) count on that.
	run sync.Mutex
	wg  sync.WaitGroup
}

// NewServer is a Server for the router.
func NewServer() *Server {
	return &Server{Env: DefaultEnv(), Policy: SystemPolicy, Log: os.Stderr, ReadTimeout: 30 * time.Second,
		MaxConns: 32}
}

// Serve answers connections on l until it is closed, then waits for the
// requests already running.
func (s *Server) Serve(l *net.UnixListener) error {
	defer s.wg.Wait()
	slots := make(chan struct{}, max(s.MaxConns, 1))
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(100 * time.Millisecond) // EMFILE and the like
			continue
		}
		slots <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer func() { <-slots; s.wg.Done() }()
			s.serveConn(c)
		}()
	}
}

func (s *Server) serveConn(c *net.UnixConn) {
	defer c.Close()
	pid, uid, _, err := PeerCredentials(c)
	if err != nil {
		return // as 1.x: its handler dies on the OSError, no reply
	}
	if s.ReadTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(s.ReadTimeout))
	}
	reply, err := s.Answer(bufio.NewReaderSize(c, 4096), pid, uid)
	if err != nil {
		return
	}
	c.SetWriteDeadline(time.Now().Add(time.Minute))
	if err := ipc.Write(c, ConntrackSampleMaxBytes, reply); err != nil && s.Log != nil {
		fmt.Fprintf(s.Log, "fr-apply-helper: reply to pid %d uid %d not sent: %v\n", pid, uid, err)
	}
}

// Answer reads one request line from r, sent by pid and uid, and is the
// reply, or errNoReply when 1.x would send none (nothing was sent; 1.x
// would die on the request).
func (s *Server) Answer(r *bufio.Reader, pid, uid int) (any, error) {
	request, err := readRequest(r)
	if err != nil {
		var bad invalidRequest
		if errors.As(err, &bad) {
			return message(false, bad.Error()), nil
		}
		return nil, errNoReply
	}
	cmd, _ := request.Get("cmd")
	policy := s.Policy()
	allowed, err := policy.Allows(uid, cmd)
	if err != nil {
		return message(false, err.Error()), nil
	}
	if !allowed {
		if s.Log != nil {
			fmt.Fprintf(s.Log, "fr-apply-helper: refused %s from pid %d uid %d\n", config.Repr(cmd), pid, uid)
		}
		return message(false, "command "+config.Repr(cmd)+" is not allowed for uid "+strconv.Itoa(uid)), nil
	}
	s.run.Lock()
	defer s.run.Unlock()
	reply, err := s.dispatch(cmd, request)
	if err != nil {
		var bad invalidRequest
		if errors.As(err, &bad) {
			return message(false, bad.Error()), nil
		}
		return nil, errNoReply
	}
	return reply, nil
}

// readRequest is the request's object. The line is checked as every
// FR_OS line is (package ipc), which is stricter than 1.x's json.loads
// in a few ways (testdata/reference/decisions.md, "the helper's
// requests").
func readRequest(r *bufio.Reader) (*config.Map, error) {
	line, err := ipc.ReadLine(r, MaxLineBytes)
	switch {
	case errors.Is(err, ipc.ErrTooLong):
		return nil, invalidRequest(fmt.Sprintf("the request is longer than %d bytes", MaxLineBytes))
	case errors.Is(err, ipc.ErrTruncated):
		return nil, invalidRequest("the request does not end with a newline")
	case err != nil:
		return nil, err // nothing sent, or the read failed: no reply
	}
	switch err := ipc.Check(line); {
	case errors.Is(err, ipc.ErrNotObject):
		return nil, invalidRequest("request must be a JSON object")
	case errors.Is(err, ipc.ErrInvalidUTF8):
		return nil, invalidRequest("the request is not UTF-8")
	case errors.Is(err, ipc.ErrDuplicate):
		return nil, invalidRequest("a name appears twice in the request")
	case err != nil:
		return nil, invalidRequest("the request is not JSON")
	}
	v, err := config.ParseJSON(line)
	if err != nil {
		return nil, invalidRequest("the request is not JSON")
	}
	return v.(*config.Map), nil
}

// Listen is the socket systemd passed (socket activation: LISTEN_PID is
// this process and LISTEN_FDS at least 1, the socket at fd 3), or else a
// socket the helper binds at path itself, for development and tests,
// removed when it is closed.
func Listen(path string) (*net.UnixListener, error) {
	if pid, fds := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"); pid != "" && fds != "" {
		p, err1 := strconv.Atoi(pid)
		n, err2 := strconv.Atoi(fds)
		if err1 == nil && err2 == nil && p == os.Getpid() && n >= 1 {
			// Not passed on to what the helper runs (nft and the rest).
			os.Unsetenv("LISTEN_PID")
			os.Unsetenv("LISTEN_FDS")
			os.Unsetenv("LISTEN_FDNAMES")
			f := os.NewFile(3, "systemd-socket")
			l, err := net.FileListener(f)
			f.Close()
			if err != nil {
				return nil, fmt.Errorf("helper: the socket systemd passed: %w", err)
			}
			ul, ok := l.(*net.UnixListener)
			if !ok {
				l.Close()
				return nil, errors.New("helper: the socket systemd passed is not a Unix socket")
			}
			return ul, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
}
