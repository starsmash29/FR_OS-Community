//go:build linux

package webui

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	json "encoding/json/v2"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestGoWebUIGoHelperSandbox is the root-only end to end of the Go webUI
// with the real Go apply-helper: no mocks, no Python, no network beyond
// loopback.
//
// The parent process only checks the environment (root, nft, ip,
// unshare, the Go toolchain), builds the real binaries
// (cmd/fr-apply-helper, cmd/fr-webui, cmd/fr-apply-revert) into a temp
// dir, and re-runs this test binary under `unshare -n -m`, so the child
// below gets a fresh network and mount namespace. The child bind-mounts
// temp directories over every absolute FR_OS path the daemons use
// (/etc/fr_os, /etc/kea, /etc/ssh, /var/log/fr_os, /var/lib/kea,
// /run/fr_os, /run/sshd), fabricates a fr_os-webui account (passwd/group
// bind-mount copies, so the helper's SystemPolicy grants it the Full
// role exactly as on the router), creates dummy links, fakes only
// systemctl, kea, kea-dhcp4, dnsmasq, wg and sshd on PATH (nft and ip are
// always the real ones), then drives the real HTTPS flow: first-boot
// sign-in, first-run setup, a password change, a firewall rule add, an
// apply, its confirmation (nft list ruleset carries the rule), then a
// second apply that is left to time out and must be reverted by the real
// fr-apply-revert code path.
//
// Hermetic: everything is under a temp dir, the namespaces are thrown
// away, nothing touches the internet, and every secret (account
// passwords, the TLS key) is generated at runtime and never committed.
//
// Run on Linux with root: go test ./webui/ -run TestGoWebUIGoHelperSandbox -v
func TestGoWebUIGoHelperSandbox(t *testing.T) {
	if os.Getenv(e2eSandboxedEnv) == e2eSandboxedValue {
		testGoWebUIGoHelperSandboxed(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"nft", "ip", "unshare"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("needs " + bin)
		}
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs the Go toolchain to build the binaries")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	modRoot := filepath.Dir(filepath.Dir(thisFile))
	for _, name := range []string{"fr-apply-helper", "fr-webui", "fr-apply-revert"} {
		out := filepath.Join(binDir, name)
		cmd := exec.Command("go", "build", "-o", out, "./cmd/"+name)
		cmd.Dir = modRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", name, err, data)
		}
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "-n", "-m", "--propagation", "private", self,
		"-test.run", "^TestGoWebUIGoHelperSandbox$")
	cmd.Env = append(os.Environ(), e2eSandboxedEnv+"="+e2eSandboxedValue, e2eRootEnv+"="+root)
	data, err := cmd.CombinedOutput()
	t.Logf("sandboxed run:\n%s", data)
	if err != nil {
		t.Fatalf("sandboxed run: %v", err)
	}
}

const e2eSandboxedEnv = "FROS_E2E_SANDBOXED"
const e2eSandboxedValue = "1"
const e2eRootEnv = "FROS_E2E_ROOT"

// e2eWebUIUID is the fabricated fr_os-webui account's uid/gid in the
// sandbox. helper.SystemPolicy grants Full to root, its own uid and
// the fr_os-webui user: a passwd/group bind-mount copy names this
// uid fr_os-webui, so the webUI authenticates to the helper exactly
// as the systemd units say (User=fr_os-webui in
// systemd/fr-webui.service, root for the helper). nobody (65534)
// cannot substitute: with no fr_os-webui entry it has NoRole and the
// helper refuses save_config and apply.
const e2eWebUIUID = 61533

const e2eSocketPath = "/run/fr_os/apply.sock"
const e2eRuleMarker = "rule:e2e-allow"
const e2eTempMarker = "rule:e2e-temp"

// testGoWebUIGoHelperSandboxed runs inside the namespaces. It fails the
// test (not skips) when the sandbox cannot be isolated: silently
// touching the host would be worse than a red test.
func testGoWebUIGoHelperSandboxed(t *testing.T) {
	root := os.Getenv(e2eRootEnv)
	if root == "" {
		t.Fatal("no " + e2eRootEnv)
	}
	mustBindMounts(t, root)
	uid, gid := mustSandboxUser(t)
	mustFreshProcSys(t)
	mustSandboxNet(t)
	fakeDir := mustFakes(t, root)
	os.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	binDir := filepath.Join(root, "bin")
	helperBin := filepath.Join(binDir, "fr-apply-helper")
	webuiBin := filepath.Join(binDir, "fr-webui")
	revertBin := filepath.Join(binDir, "fr-apply-revert")
	for _, bin := range []string{helperBin, webuiBin, revertBin} {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("missing binary %s: %v", bin, err)
		}
	}

	mustWriteFile(t, "/etc/fr_os/config.yaml", e2eBaseConfig, 0o644)

	// The first-boot generator (fr-accounts on the router) is outside
	// this sandbox; seed its output through the store itself, in the
	// same file and format, with a must-change admin.
	stateDir := "/etc/fr_os/webui"
	mustMkdirChown(t, stateDir, uid, gid)
	store := newAdminStore(Env{Paths: Paths{Root: "/"}, Rand: rand.Reader})
	bootUser, bootPass := "e2e-firstboot", e2eRandomHex(t, 20)
	if err := store.SetPassword(bootUser, bootPass, RoleAdmin, true); err != nil {
		t.Fatalf("seeding the first-boot account: %v", err)
	}

	helperProc := mustStart(t, helperBin, nil, 0, 0, filepath.Join(root, "helper.log"))
	t.Cleanup(func() { helperProc.Kill() })
	e2eWaitHelper(t)

	port := e2eFreePort(t)
	// The certificate is generated at runtime by fr-webui itself
	// (ensureSelfSignedCert) into the sandbox's state dir: never
	// committed, never read from the host.
	webuiProc := mustStart(t, webuiBin, []string{"--host", "127.0.0.1", "--port", strconv.Itoa(port)},
		uid, gid, filepath.Join(root, "webui.log"))
	t.Cleanup(func() { webuiProc.Kill() })
	client := e2eHTTPSClient(t)
	base := "https://127.0.0.1:" + strconv.Itoa(port)
	e2eWaitWebUI(t, client, base)

	// (1) First-boot sign-in: the generated account goes to /setup.
	e2ePost(t, client, base+"/login", url.Values{"username": {bootUser}, "password": {bootPass}}, 303, "/")
	if got := e2eGet(t, client, base+"/", 303); !strings.HasPrefix(got, "/setup") {
		t.Fatalf("after first-boot sign-in / goes to %q, want /setup", got)
	}

	// (2) First-run setup: a new name and password (routes.go setupSubmit:
	// username, password, password_confirm).
	adminUser := "e2e-admin"
	adminPass := e2eRandomHex(t, 20)
	csrf := e2eCSRF(t, client, base+"/setup")
	e2ePost(t, client, base+"/setup", url.Values{
		"username": {adminUser}, "password": {adminPass},
		"password_confirm": {adminPass}, "csrf_token": {csrf},
	}, 303, "/segments?first_run=1")

	// (3) Password change (routes.go changeOwnPassword: current_password,
	// new_password, new_password_confirm). The session rotates: the jar
	// picks the fresh cookie up from the answer.
	newPass := e2eRandomHex(t, 20)
	if newPass == adminPass {
		t.Fatal("passwords must differ")
	}
	csrf = e2eCSRF(t, client, base+"/rules")
	e2ePost(t, client, base+"/account/password", url.Values{
		"current_password": {adminPass}, "new_password": {newPass},
		"new_password_confirm": {newPass}, "csrf_token": {csrf},
	}, 303, "/account")

	// A first apply of the untouched config, so later applies have a
	// previous config to be held against (helper/applycmds.go: the first
	// apply is never held, nothing could be reverted to).
	e2ePost(t, client, base+"/apply", url.Values{"csrf_token": {csrf}}, 303, "/")
	if status := e2eApplyStatus(t); status.pending != nil {
		t.Fatalf("base apply must not be held, got pending %q", status.pending["id"])
	}

	// (4) A firewall rule (webui/rules.go addRule fields).
	csrf = e2eCSRF(t, client, base+"/rules")
	e2ePost(t, client, base+"/rules/add", url.Values{
		"name": {"e2e-allow"}, "action": {"accept"}, "from_zone": {"lan"},
		"to_zone": {"wan"}, "proto": {"tcp"}, "dst_port": {"8443"}, "csrf_token": {csrf},
	}, 303, "/rules")
	if body := e2eGetBody(t, client, base+"/rules", 200); !strings.Contains(body, "e2e-allow") {
		t.Fatal("the rules screen does not list e2e-allow after adding it")
	}

	// (5) Apply, confirm, and the nft ruleset carries the rule marker.
	e2ePost(t, client, base+"/apply", url.Values{"csrf_token": {csrf}}, 303, "/")
	pendingID := e2eApplyStatus(t).pendingID()
	if pendingID == "" {
		t.Fatal("no pending apply after the rule change")
	}
	csrf = e2eCSRF(t, client, base+"/rules")
	e2ePost(t, client, base+"/apply/confirm", url.Values{"id": {pendingID}, "csrf_token": {csrf}}, 303, "/")
	e2eAssertRuleset(t, e2eRuleMarker, true)

	// (6) A second apply, left to time out: the shortest real deadline is
	// confirm_apply_seconds 60 (config/load.go: 0 or 60-3600; the helper
	// has no test deadline flag). The real fr-apply-revert binary (the
	// same code fr-apply-revert.service runs: cmd/fr-apply-revert waits
	// for the pending deadline and reverts) performs the revert, since no
	// systemd runs the unit in the sandbox.
	csrf = e2eCSRF(t, client, base+"/rules")
	e2ePost(t, client, base+"/rules/add", url.Values{
		"name": {"e2e-temp"}, "action": {"drop"}, "from_zone": {"lan"},
		"to_zone": {"wan"}, "csrf_token": {csrf},
	}, 303, "/rules")
	e2ePost(t, client, base+"/apply", url.Values{"csrf_token": {csrf}}, 303, "/")
	if id := e2eApplyStatus(t).pendingID(); id == "" {
		t.Fatal("no pending apply for the timeout leg")
	}
	revert := exec.Command(revertBin)
	revert.Env = os.Environ()
	revert.Stdout = mustCreate(t, filepath.Join(root, "revert.log"))
	revert.Stderr = revert.Stdout
	if err := revert.Run(); err != nil {
		t.Fatalf("fr-apply-revert: %v", err)
	}
	status := e2eApplyStatus(t)
	if status.pending != nil {
		t.Fatalf("still pending after the revert: %q", status.pending["id"])
	}
	if !status.rejected {
		t.Fatal("the unconfirmed config was not kept (rejected) after the revert")
	}
	e2eAssertRuleset(t, e2eTempMarker, false)
	e2eAssertRuleset(t, e2eRuleMarker, true)
}

// e2eBaseConfig is the sandbox router: dummy devices from
// mustSandboxNet, no DHCP/WireGuard/IPv6/ad-block (those steps stay
// off), management zones only (never addresses: nothing moves the webUI
// and SSH, management.go refuseMovingManagement). confirm_apply_seconds
// 60 is the shortest real hold (config/load.go).
const e2eBaseConfig = `version: 1
hostname: fr-router
interfaces:
  wan: {device: dummy0, zone: wan}
  lan: {device: dummy1, zone: lan, address: 192.168.77.1/24}
zones: {wan: {}, lan: {}}
rules:
- {name: lan-to-wan, action: accept, from_zone: lan, to_zone: wan}
nat: {masquerade: [{out_zone: wan}]}
management: {zones: [lan], confirm_apply_seconds: 60}
`

// mustBindMounts redirects every absolute FR_OS path the daemons write
// into the temp dir. Private first, so nothing leaks to the host.
func mustBindMounts(t *testing.T, root string) {
	t.Helper()
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatalf("making mounts private: %v", err)
	}
	for _, target := range []string{"/etc/fr_os", "/etc/kea", "/etc/ssh", "/var/log/fr_os",
		"/var/lib/kea", "/run/fr_os", "/run/sshd", "/usr/local/share/fr_os"} {
		mirror := filepath.Join(root, "mnt"+target)
		if err := os.MkdirAll(mirror, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(mirror, target, "", syscall.MS_BIND, ""); err != nil {
			t.Fatalf("bind-mounting %s: %v", target, err)
		}
	}
}

// mustSandboxUser fabricates the fr_os-webui account: passwd/group
// copies with the uid appended, bind-mounted over /etc/passwd and
// /etc/group. os/user (CGO_ENABLED=0) reads them directly, so the
// helper's SystemPolicy sees fr_os-webui exactly as on the router.
func mustSandboxUser(t *testing.T) (int, int) {
	t.Helper()
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatalf("reading /etc/passwd: %v", err)
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		t.Fatalf("reading /etc/group: %v", err)
	}
	id := strconv.Itoa(e2eWebUIUID)
	for _, line := range append(strings.Split(string(passwd), "\n"), strings.Split(string(group), "\n")...) {
		if strings.HasPrefix(line, "fr_os-webui:") || strings.Contains(line, ":"+id+":") {
			t.Fatalf("uid/gid %s is taken in the sandbox", id)
		}
	}
	name := "fr_os-webui"
	passwd = append(passwd, name+":x:"+id+":"+id+":FR_OS webUI:/nonexistent:/usr/sbin/nologin"+"\n"...)
	group = append(group, name+":x:"+id+":"+"\n"...)
	root := os.Getenv(e2eRootEnv)
	pwCopy := filepath.Join(root, "passwd")
	grCopy := filepath.Join(root, "group")
	if err := os.WriteFile(pwCopy, passwd, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grCopy, group, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(pwCopy, "/etc/passwd", "", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("bind-mounting /etc/passwd for the fr_os-webui user (nobody 65534 cannot substitute: "+
			"it has NoRole in helper.SystemPolicy): %v", err)
	}
	if err := syscall.Mount(grCopy, "/etc/group", "", syscall.MS_BIND, ""); err != nil {
		t.Fatalf("bind-mounting /etc/group: %v", err)
	}
	return e2eWebUIUID, e2eWebUIUID
}

// mustFreshProcSys remounts proc and sysfs so the namespace sees only
// its own devices and sysctls. Without this the apply would read the
// host's /sys/class/net and write the host's /proc/sys.
func mustFreshProcSys(t *testing.T) {
	t.Helper()
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatalf("mounting a fresh /proc: %v", err)
	}
	if err := syscall.Mount("sysfs", "/sys", "sysfs", 0, ""); err != nil {
		t.Fatalf("mounting a fresh /sys: %v", err)
	}
}

// mustSandboxNet brings lo up and creates the dummy devices the config
// names, with ip (always real).
func mustSandboxNet(t *testing.T) {
	t.Helper()
	for _, argv := range [][]string{
		{"link", "set", "lo", "up"},
		{"link", "add", "dummy0", "type", "dummy"},
		{"link", "add", "dummy1", "type", "dummy"},
		{"link", "set", "dummy0", "up"},
		{"link", "set", "dummy1", "up"},
	} {
		if out, err := exec.Command("ip", argv...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(argv, " "), err, out)
		}
	}
}

// e2eFakeScripts are the programs an apply may run that must not touch
// the machine: systemctl (nothing is a unit here), kea, kea-dhcp4,
// dnsmasq, wg, sshd answer success without doing anything. nft and ip are
// never faked: the ruleset and the links are the real thing under test.
func e2eFakeScripts() map[string]string {
	fakes := map[string]string{}
	fakes["systemctl"] = "#!/bin/sh\n" +
		"echo \"$@\" >> \"$FROS_E2E_SYSTEMCTL_LOG\"\n" +
		"case \"$1\" in\n" +
		"is-system-running) echo \"running\"; exit 0;;\n" +
		"is-active) echo \"inactive\"; exit 3;;\n" +
		"is-enabled) echo \"disabled\"; exit 1;;\n" +
		"*) exit 0;;\n" +
		"esac\n"
	fakes["kea"] = "#!/bin/sh\nexit 0\n"
	fakes["kea-dhcp4"] = "#!/bin/sh\nexit 0\n"
	fakes["dnsmasq"] = "#!/bin/sh\nexit 0\n"
	fakes["wg"] = "#!/bin/sh\nexit 0\n"
	fakes["sshd"] = "#!/bin/sh\nexit 0\n"
	return fakes
}

func mustFakes(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "fakes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Setenv("FROS_E2E_SYSTEMCTL_LOG", filepath.Join(root, "systemctl.log"))
	for name, text := range e2eFakeScripts() {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustWriteFile(t *testing.T, path, text string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		t.Fatal(err)
	}
}

func mustMkdirChown(t *testing.T, path string, uid, gid int) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		t.Fatal(err)
	}
}

func mustCreate(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// mustStart runs a daemon binary: helper and revert as root, the webUI
// under the sandbox fr_os-webui uid, as systemd/fr-webui.service says.
func mustStart(t *testing.T, bin string, argv []string, uid, gid int, logPath string) *os.Process {
	t.Helper()
	cmd := exec.Command(bin, argv...)
	cmd.Env = os.Environ()
	cmd.Stdout = mustCreate(t, logPath)
	cmd.Stderr = cmd.Stdout
	if uid != 0 || gid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", bin, err)
	}
	return cmd.Process
}

// e2eApplyState is what the helper's apply_status says.
type e2eApplyState struct {
	pending  map[string]any
	rejected bool
}

func (s e2eApplyState) pendingID() string {
	if s.pending == nil {
		return ""
	}
	id, _ := s.pending["id"].(string)
	return id
}

// e2eHelperCall is one JSON line on the helper's socket, as
// webui.sendCommand speaks it (one object per line, write side shut,
// read to the end). encoding/json/v2 only, never encoding/json v1.
func e2eHelperCall(t *testing.T, cmd map[string]any) map[string]any {
	t.Helper()
	line, err := json.Marshal(cmd)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("unix", e2eSocketPath, 10*time.Second)
	if err != nil {
		t.Fatalf("dialing the helper: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		t.Fatalf("asking the helper: %v", err)
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading the helper: %v", err)
	}
	var reply map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &reply); err != nil {
		t.Fatalf("helper reply %q: %v", out, err)
	}
	return reply
}

func e2eApplyStatus(t *testing.T) e2eApplyState {
	t.Helper()
	reply := e2eHelperCall(t, map[string]any{"cmd": "apply_status"})
	ok, _ := reply["ok"].(bool)
	if !ok {
		t.Fatalf("apply_status refused: %v", reply)
	}
	state := e2eApplyState{}
	if p, _ := reply["pending"].(map[string]any); p != nil {
		state.pending = p
	}
	state.rejected, _ = reply["rejected"].(bool)
	return state
}

func e2eWaitHelper(t *testing.T) {
	t.Helper()
	// The socket is born root-owned; the webUI reaches it as the
	// sandbox fr_os-webui user, so the directory and the socket are
	// opened up (inside the mount namespace only).
	os.Chmod(filepath.Dir(e2eSocketPath), 0o777)
	for i := 0; i < 150; i++ {
		os.Chmod(e2eSocketPath, 0o777)
		if e2eTryPing() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the helper never answered ping")
}

// e2eTryPing asks the helper once, false on any transport failure (the
// socket may not exist yet while the daemon starts).
func e2eTryPing() bool {
	line, err := json.Marshal(map[string]any{"cmd": "ping"})
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("unix", e2eSocketPath, time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return false
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return false
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		return false
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		return false
	}
	var reply map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &reply); err != nil {
		return false
	}
	ok, _ := reply["ok"].(bool)
	return ok
}

// e2eHTTPSClient trusts the runtime-generated self-signed certificate;
// the sandbox has no other TLS endpoint.
func e2eHTTPSClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

func e2eWaitWebUI(t *testing.T, client *http.Client, base string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		resp, err := client.Get(base + "/login")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the webUI never answered HTTPS")
}

// e2eGet follows no redirects: a 303's Location is the assertion.
func e2eGet(t *testing.T, client *http.Client, target string, want int) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("GET %s: status %d, want %d", target, resp.StatusCode, want)
	}
	return resp.Header.Get("Location")
}

func e2eGetBody(t *testing.T, client *http.Client, target string, want int) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("GET %s: status %d, want %d: %.500s", target, resp.StatusCode, want, body)
	}
	return string(body)
}

func e2ePost(t *testing.T, client *http.Client, target string, form url.Values, want int, wantLoc string) string {
	t.Helper()
	resp, err := client.PostForm(target, form)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("POST %s: status %d, want %d: %.500s", target, resp.StatusCode, want, body)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, wantLoc) {
		t.Fatalf("POST %s: Location %q, want prefix %q: %.500s", target, loc, wantLoc, body)
	}
	return loc
}

var e2eCSRFRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// e2eCSRF reads the session's CSRF token the way a browser does: from
// the form's hidden field (server.go CSRFInput).
func e2eCSRF(t *testing.T, client *http.Client, page string) string {
	t.Helper()
	body := e2eGetBody(t, client, page, 200)
	m := e2eCSRFRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token on %s", page)
	}
	return m[1]
}

func e2eRandomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func e2eAssertRuleset(t *testing.T, marker string, want bool) {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset: %v\n%s", err, out)
	}
	if got := strings.Contains(string(out), marker); got != want {
		t.Fatalf("ruleset contains %q: %v, want %v\n%s", marker, got, want, out)
	}
}

func e2eFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
