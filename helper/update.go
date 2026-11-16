package helper

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/ipc"
)

// The update-helper: the root side of the webUI's Update screen (1.x's
// frfw.helper.update_server), on a socket of its own, apart from the
// apply-helper, so a change to one's request handling can never reach
// the other. Only root and the webUI's account may use it: the socket
// belongs to fr_os-webui with mode 0600 (systemd/fr-update-helper.socket)
// and every connection's peer uid is checked again here, since what it
// does reboots the router.
//
// It installs a signed release and rolls back to the one before
// (apply.Updater, phase 4f-4b), and runs the kernel side of the screen
// (ROADMAP SEC-14): what kernel runs and which is ready to try, "check
// now" (starts fr-kernel-prepare.service), "try it" -- stage the
// prepared kernel and reboot into its trial, the one reboot FR_OS asks
// for, and only an admin's -- and cancelling a staged one.

// UpdateSocketPath is where the update-helper listens.
const UpdateSocketPath = "/run/fr_os/update.sock"

// PrepareUnit is the unit "check now" starts.
const PrepareUnit = "fr-kernel-prepare.service"

// rebootDelay is how long after its answer "try it" reboots: the
// answer has gone back to the webUI by then.
const rebootDelay = 3 * time.Second

// UpdateServer answers the update-helper's requests.
type UpdateServer struct {
	Sys *apply.System
	// Policy is looked up per connection, as the apply-helper's.
	Policy      func() Policy
	Log         io.Writer
	ReadTimeout time.Duration
	MaxConns    int
	// RebootSoon reboots once the answer is sent (nil: systemctl
	// reboot, rebootDelay later).
	RebootSoon func()
	// Repo is where releases are installed from (1.x's --repo, its
	// DEFAULT_REPO unless given). Updater makes the installer of a
	// request (nil: apply.NewUpdater).
	Repo    string
	Updater func() *apply.Updater

	run sync.Mutex
	wg  sync.WaitGroup
}

// NewUpdateServer is the router's.
func NewUpdateServer() *UpdateServer {
	return &UpdateServer{Sys: apply.DefaultSystem(), Policy: SystemPolicy, Log: os.Stderr,
		ReadTimeout: 30 * time.Second, MaxConns: 8, Repo: apply.DefaultUpdateRepo}
}

// Serve answers connections on l until it is closed.
func (u *UpdateServer) Serve(l *net.UnixListener) error {
	defer u.wg.Wait()
	slots := make(chan struct{}, max(u.MaxConns, 1))
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
			time.Sleep(100 * time.Millisecond)
			continue
		}
		slots <- struct{}{}
		u.wg.Add(1)
		go func() {
			defer func() { <-slots; u.wg.Done() }()
			u.serveConn(c)
		}()
	}
}

func (u *UpdateServer) serveConn(c *net.UnixConn) {
	defer c.Close()
	pid, uid, _, err := PeerCredentials(c)
	if err != nil {
		return
	}
	if u.ReadTimeout > 0 {
		c.SetReadDeadline(time.Now().Add(u.ReadTimeout))
	}
	reply, err := u.Answer(bufio.NewReaderSize(c, 4096), pid, uid)
	if err != nil {
		return
	}
	c.SetWriteDeadline(time.Now().Add(time.Minute))
	if err := ipc.Write(c, MaxLineBytes, reply); err != nil && u.Log != nil {
		fmt.Fprintf(u.Log, "fr-update-helper: reply to pid %d uid %d not sent: %v\n", pid, uid, err)
	}
}

// Answer reads one request line from r, sent by pid and uid: the reply,
// or errNoReply where 1.x sends none.
func (u *UpdateServer) Answer(r *bufio.Reader, pid, uid int) (any, error) {
	request, err := readRequest(r)
	if err != nil {
		var bad invalidRequest
		if errors.As(err, &bad) {
			return message(false, bad.Error()), nil
		}
		return nil, errNoReply
	}
	cmd, _ := request.Get("cmd")
	if u.Policy().Role(uid) != Full {
		if u.Log != nil {
			fmt.Fprintf(u.Log, "fr-update-helper: refused %s from pid %d uid %d\n", config.Repr(cmd), pid, uid)
		}
		return message(false, "uid "+strconv.Itoa(uid)+" may not use the update-helper"), nil
	}
	u.run.Lock()
	defer u.run.Unlock()
	reply, err := u.DispatchRequest(request)
	var (
		ue *apply.KernelUpdateError
		be *apply.KernelBootError
		re *apply.UpdateError
	)
	switch {
	case errors.As(err, &ue) || errors.As(err, &be) || errors.As(err, &re):
		return message(false, err.Error()), nil
	case err != nil:
		return nil, errNoReply
	}
	return reply, nil
}

// kernelReply is kernel_status's answer.
type kernelReply struct {
	OK     bool                 `json:"ok"`
	Kernel apply.KernelOverview `json:"kernel"`
}

// DispatchRequest runs one request: apply and rollback with what they
// take, the rest by Dispatch.
func (u *UpdateServer) DispatchRequest(request *config.Map) (any, error) {
	cmd, _ := request.Get("cmd")
	switch cmd {
	case "apply":
		v, _ := request.Get("version")
		target, ok := v.(string)
		if !ok || target == "" {
			return message(false, "'version' must be a non-empty string"), nil
		}
		installed, err := u.updater().Apply(target)
		if err != nil {
			return nil, err
		}
		return message(true, "Updated to "+installed), nil
	case "rollback":
		restored, err := u.updater().Rollback()
		if err != nil {
			return nil, err
		}
		return message(true, "Rolled back to "+restored), nil
	}
	return u.Dispatch(cmd)
}

func (u *UpdateServer) updater() *apply.Updater {
	if u.Updater != nil {
		return u.Updater()
	}
	return apply.NewUpdater(u.Sys, u.Repo)
}

// Dispatch runs one command; an error is one 1.x reports (an
// UpdateError, KernelUpdateError or KernelBootError) or one it sends no
// reply for.
func (u *UpdateServer) Dispatch(cmd config.Value) (any, error) {
	sys := u.Sys
	name, _ := cmd.(string)
	switch name {
	case "ping":
		return message(true, "pong"), nil
	case "kernel_status":
		o, err := sys.KernelOverview()
		if err != nil {
			return nil, err
		}
		return kernelReply{OK: true, Kernel: o}, nil
	case "kernel_check":
		r, err := sys.Run(apply.Cmd{Argv: []string{"systemctl", "start", "--no-block", PrepareUnit}})
		if err == nil && r.Code != 0 {
			err = fmt.Errorf("systemctl start %s: exit status %d", PrepareUnit, r.Code)
		}
		if err != nil {
			return nil, err
		}
		return message(true, "Checking Debian for a newer kernel -- this page shows the result"), nil
	case "kernel_try":
		dir, ok := sys.KernelBootDir()
		if !ok {
			return message(false, "no persistence partition in use: a kernel can't be tried"), nil
		}
		version, err := sys.TryPreparedKernel(dir)
		if err != nil {
			return nil, err
		}
		// Security-lessons G9.
		sys.Alert("kernel "+version+" staged from the webUI: the router reboots into its trial; it keeps it only "+
			"if it comes up on it", "webUI", "update-helper")
		u.rebootSoon()
		return message(true, "Kernel "+version+" staged -- the router reboots into its trial now"), nil
	case "kernel_cancel":
		dir, ok := sys.KernelBootDir()
		if !ok {
			return message(true, "Nothing was staged"), nil
		}
		removed, err := apply.UnstageKernel(dir)
		if err != nil {
			return nil, err
		}
		if !removed {
			return message(true, "Nothing was staged"), nil
		}
		sys.Alert("staged kernel removed from the webUI: the image's own kernel boots from the next reboot",
			"webUI", "update-helper")
		return message(true, "Staged kernel removed: the image's own kernel boots from the next reboot"), nil
	}
	return message(false, "unknown command "+config.Repr(cmd)), nil
}

func (u *UpdateServer) rebootSoon() {
	if u.RebootSoon != nil {
		u.RebootSoon()
		return
	}
	run := u.Sys.Run
	time.AfterFunc(rebootDelay, func() { _, _ = run(apply.Cmd{Argv: []string{"systemctl", "reboot"}}) })
}
