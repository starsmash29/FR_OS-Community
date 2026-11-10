package webui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/ipc"
)

// HelperError is a transport failure talking to a helper (1.x's
// frfw.helper.client.HelperError). A refusal is a normal reply with
// "ok": false, not an error.
type HelperError struct{ Msg string }

func (e *HelperError) Error() string { return e.Msg }

// pyOSError is Python's str() of an OSError for err: "[Errno N] text".
func pyOSError(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		text := errno.Error()
		if text != "" {
			text = strings.ToUpper(text[:1]) + text[1:]
		}
		return fmt.Sprintf("[Errno %d] %s", int(errno), text)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return "timed out"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	return err.Error()
}

// sendCommand is one request on a helper's socket: one JSON line out,
// the write side shut, then the reply up to maxBytes (0: the protocol's
// line limit) until the helper closes, as 1.x's send_command.
func sendCommand(socket string, cmd *config.Map, timeout float64, maxBytes int) (config.Value, error) {
	if maxBytes <= 0 {
		maxBytes = ipc.MaxLineBytes
	}
	line, err := config.PyJSON(cmd, -1, false)
	if err != nil {
		return nil, &HelperError{err.Error()}
	}
	deadline := time.Now().Add(time.Duration(timeout * float64(time.Second)))
	fail := func(err error) (config.Value, error) {
		return nil, &HelperError{fmt.Sprintf("cannot reach apply-helper at %s: %s", socket, pyOSError(err))}
	}
	conn, err := net.DialTimeout("unix", socket, time.Until(deadline))
	if err != nil {
		var op *net.OpError
		if errors.As(err, &op) && op.Err != nil {
			err = op.Err
		}
		return fail(err)
	}
	defer conn.Close()
	conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		return fail(err)
	}
	conn.(*net.UnixConn).CloseWrite()
	var buf bytes.Buffer
	chunk := make([]byte, 65536)
	for {
		n, err := conn.Read(chunk)
		buf.Write(chunk[:n])
		if buf.Len() > maxBytes {
			return nil, &HelperError{"response from apply-helper exceeded size limit"}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
	}
	raw := bytes.TrimSpace(buf.Bytes())
	if len(raw) == 0 {
		return nil, &HelperError{"apply-helper closed the connection without a response"}
	}
	v, err := config.ParseJSONLastWins(raw)
	if err != nil {
		return nil, &HelperError{fmt.Sprintf("invalid response from apply-helper: %q", raw)}
	}
	return v, nil
}

// runProgram runs argv with a timeout, as subprocess.run(capture_output=True).
func runProgram(argv []string, timeout float64) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*float64(time.Second)))
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), out.String(), nil
	}
	if err != nil {
		return -1, "", err
	}
	return 0, out.String(), nil
}

// helper is the webUI's view of the two helpers: each 1.x
// HelperClient method is one request.
type helper struct{ env Env }

func cmdMap(pairs ...any) *config.Map {
	m := config.NewMap()
	for i := 0; i < len(pairs); i += 2 {
		v := pairs[i+1]
		switch x := v.(type) {
		case int:
			v = big.NewInt(int64(x))
		case []string:
			list := make([]config.Value, len(x))
			for j, s := range x {
				list[j] = s
			}
			v = list
		}
		m.Set(pairs[i].(string), v)
	}
	return m
}

// reply is a helper's answer as a mapping (an answer that isn't one
// reads as empty, as 1.x's reply.get would fail on it only later).
func (h helper) send(socket string, cmd *config.Map, timeout float64) (*config.Map, error) {
	v, err := h.env.Send(socket, cmd, timeout, 0)
	if err != nil {
		return nil, err
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, fmt.Errorf("webui: the helper's reply is not an object")
	}
	return m, nil
}

func (h helper) apply(cmd *config.Map, timeout float64) (*config.Map, error) {
	return h.send(h.env.Paths.ApplySocket(), cmd, timeout)
}

func (h helper) Ping() (*config.Map, error) { return h.apply(cmdMap("cmd", "ping"), 10) }
func (h helper) Apply(dryRun, confirm bool, user string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "apply", "dry_run", dryRun, "confirm", confirm, "user", user), 120)
}
func (h helper) ApplyStatus() (*config.Map, error) { return h.apply(cmdMap("cmd", "apply_status"), 3) }
func (h helper) ApplyConfirm(id string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "apply_confirm", "id", id), 120)
}
func (h helper) ApplyRevert() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "apply_revert"), 120)
}
func (h helper) RestoreRejected() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "restore_rejected"), 10)
}
func (h helper) Rollback() (*config.Map, error) { return h.apply(cmdMap("cmd", "rollback"), 10) }
func (h helper) BanIP(ip string, seconds int) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "ban_ip", "ip", ip, "duration_seconds", seconds), 10)
}
func (h helper) IDSQuarantineStatus() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "ids_quarantine_status"), 10)
}

// KernelStatus is the update-helper's kernel_status (ROADMAP SEC-14).
func (h helper) KernelStatus() (*config.Map, error) {
	return h.send(h.env.Paths.UpdateSocket(), cmdMap("cmd", "kernel_status"), 60)
}
func (h helper) ListeningSockets() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "listening_sockets"), 10)
}
func (h helper) FirewallDrops() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "firewall_drops"), 10)
}
func (h helper) SourceDevice(ip string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "source_device", "ip", ip), 10)
}
func (h helper) AuditAppend(entry *config.Map) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "audit_append", "entry", entry), 10)
}
func (h helper) SaveConfig(yamlText string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "save_config", "yaml", yamlText), 10)
}
func (h helper) IPv6Status() (*config.Map, error) { return h.apply(cmdMap("cmd", "ipv6_status"), 10) }
func (h helper) IoTIsolationStatus() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "iot_isolation_status"), 10)
}

// IoTScan runs fr-iot-scan.service, which can take a while (1.x: 150 s).
func (h helper) IoTScan() (*config.Map, error) { return h.apply(cmdMap("cmd", "iot_scan"), 150) }
func (h helper) IoTSyncIsolation(macs []string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "iot_sync_isolation", "macs", macs), 10)
}

// RefreshAdblock downloads the lists (1.x: 60 s).
func (h helper) RefreshAdblock() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "refresh_adblock"), 60)
}
func (h helper) XDPStats() (*config.Map, error) { return h.apply(cmdMap("cmd", "xdp_stats"), 10) }
func (h helper) AuthorizeZTNA(ip, username string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "authorize_ztna", "ip", ip, "username", username), 10)
}
func (h helper) ZTNAStatus(ip string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "ztna_status", "ip", ip), 10)
}
func (h helper) WireGuardStatus() (*config.Map, error) {
	return h.apply(cmdMap("cmd", "wireguard_status"), 10)
}

// SetManagementAddresses moves the webUI and SSH, held until confirmed
// (1.x: 120 s).
func (h helper) SetManagementAddresses(addresses []string, user string) (*config.Map, error) {
	return h.apply(cmdMap("cmd", "set_management_addresses", "addresses", addresses, "user", user), 120)
}
