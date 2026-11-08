package helper

import (
	"bufio"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

func testServer(t *testing.T, policy Policy) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	env := Env{
		ApplyPendingPath: filepath.Join(dir, "apply-pending.json"), RejectedConfigPath: filepath.Join(dir, "rejected"),
		KeaLeasesPath: filepath.Join(dir, "leases.csv"), Nft: RunNft,
		ConfigPath: filepath.Join(dir, "config.yaml"), Sys: inertSystem(dir),
		Now: func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
	}
	return &Server{Env: env, Policy: func() Policy { return policy }, ReadTimeout: 5 * time.Second, MaxConns: 4},
		filepath.Join(dir, "run", "apply.sock")
}

// inertSystem is a system under dir that runs no program: a test never
// touches the machine's own files or units.
func inertSystem(dir string) *apply.System {
	sys := apply.DefaultSystem()
	sys.Paths = apply.DefaultPaths().Under(dir)
	sys.Run = func(apply.Cmd) (apply.Result, error) { return apply.Result{}, apply.ErrNotFound }
	sys.Which = func(string) string { return "" }
	sys.LoginUsers = func() []string { return nil }
	sys.OpenSSLVersion = func() ([3]int, string) { return [3]int{3, 0, 0}, "OpenSSL 3.0.0" }
	sys.Sleep = func(time.Duration) {}
	return sys
}

func serve(t *testing.T, s *Server, path string) {
	t.Helper()
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	t.Cleanup(func() {
		l.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("socket file left behind: %v", err)
		}
	})
}

// send is 1.x's client (frfw.helper.client.send_command): the request,
// the end of what it writes, then everything up to the end of the stream.
func send(t *testing.T, path, request string) string {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite()
	out, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func only(uid int, role Role) Policy {
	p := Policy{FullUIDs: map[int]bool{}, SensorUIDs: map[int]bool{}}
	switch role {
	case Full:
		p.FullUIDs[uid] = true
	case Sensor:
		p.SensorUIDs[uid] = true
	}
	return p
}

func TestSocketRoles(t *testing.T) {
	uid := os.Getuid()
	for _, c := range []struct {
		role          Role
		request, want string
	}{
		{Full, `{"cmd": "ping"}` + "\n", `{"ok":true,"message":"pong"}` + "\n"},
		{Full, `{"cmd": "set_management_addresses"}` + "\n",
			`{"ok":false,"message":"command 'set_management_addresses' is not in FR_OS 2 yet"}` + "\n"},
		{Full, `{"cmd": "status"}` + "\n", `{"ok":false,"message":"unknown command 'status'"}` + "\n"},
		{Sensor, `{"cmd": "ping"}` + "\n", `{"ok":true,"message":"pong"}` + "\n"},
		{Sensor, `{"cmd": "save_config", "yaml": ""}` + "\n",
			`{"ok":false,"message":"command 'save_config' is not allowed for uid ` + strconv.Itoa(uid) + `"}` + "\n"},
		{NoRole, `{"cmd": "ping"}` + "\n",
			`{"ok":false,"message":"command 'ping' is not allowed for uid ` + strconv.Itoa(uid) + `"}` + "\n"},
		{Full, "", ""},
		{Full, `{"cmd": "ping"}`, `{"ok":false,"message":"invalid request: the request does not end with a newline"}` + "\n"},
		{Full, `{"cmd": "ping", "cmd": "apply"}` + "\n",
			`{"ok":false,"message":"invalid request: a name appears twice in the request"}` + "\n"},
		{Full, `{"cmd": "ping", "pad": "` + strings.Repeat("a", MaxLineBytes) + `"}` + "\n",
			`{"ok":false,"message":"invalid request: the request is longer than 65536 bytes"}` + "\n"},
	} {
		s, path := testServer(t, only(uid, c.role))
		serve(t, s, path)
		if got := send(t, path, c.request); got != c.want {
			t.Errorf("role %d, %.40q:\n got %q\nwant %q", c.role, c.request, got, c.want)
		}
	}
}

// TestSilentPeer: a peer that connects and sends nothing holds only its
// own connection (1.x served one connection at a time, so it held them
// all), and is dropped after ReadTimeout with no reply.
func TestSilentPeer(t *testing.T) {
	s, path := testServer(t, only(os.Getuid(), Full))
	s.ReadTimeout = 500 * time.Millisecond
	serve(t, s, path)
	silent, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	start := time.Now()
	if got := send(t, path, `{"cmd": "ping"}`+"\n"); got != `{"ok":true,"message":"pong"}`+"\n" {
		t.Fatalf("got %q", got)
	}
	if d := time.Since(start); d > 400*time.Millisecond {
		t.Errorf("the second peer waited %v", d)
	}
	silent.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(silent); err != nil || len(b) != 0 {
		t.Errorf("silent peer: %q, %v; want the end of the stream", b, err)
	}
}

func TestPeerCredentials(t *testing.T) {
	dir := t.TempDir()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", filepath.Join(dir, "s"))
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pid, uid, gid, err := PeerCredentials(c)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() || uid != os.Getuid() || gid != os.Getgid() {
		t.Errorf("got %d %d %d, want %d %d %d", pid, uid, gid, os.Getpid(), os.Getuid(), os.Getgid())
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{FullUIDs: map[int]bool{0: true, 990: true}, SensorUIDs: map[int]bool{991: true}}
	for _, c := range []struct {
		uid  int
		cmd  config.Value
		want bool
		err  string
	}{
		{0, "apply", true, ""}, {990, "save_config", true, ""}, {990, nil, true, ""},
		{991, "ping", true, ""}, {991, "quarantine_ip", true, ""}, {991, "conntrack_sample", true, ""},
		{991, "dhcp_leases", true, ""}, {991, "iot_sync_isolation", true, ""},
		{991, "apply", false, ""}, {991, "save_config", false, ""}, {991, "ban_ip", false, ""}, {991, nil, false, ""},
		{991, []config.Value{"ping"}, false, "invalid request: unhashable type: 'list'"},
		{991, config.NewMap(), false, "invalid request: unhashable type: 'dict'"},
		{992, "ping", false, ""}, {992, []config.Value{}, false, ""},
	} {
		got, err := p.Allows(c.uid, c.cmd)
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		if got != c.want || errText != c.err {
			t.Errorf("uid %d %s: %v %q, want %v %q", c.uid, config.Repr(c.cmd), got, errText, c.want, c.err)
		}
	}
	sys := SystemPolicy()
	if sys.Role(0) != Full || sys.Role(os.Geteuid()) != Full {
		t.Errorf("root and the helper's own uid must be full: %+v", sys)
	}
}

func TestNftArgv(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{[]string{"-j", "list", "set", "inet", "fr_os", "x"}, []string{"nft", "-j", "--", "list", "set", "inet", "fr_os", "x"}},
		{[]string{"-c", "-f", "-", "x"}, []string{"nft", "-c", "-f", "-", "--", "x"}},
		{[]string{"-f", "/tmp/s"}, []string{"nft", "-f", "/tmp/s"}},
		{[]string{"list", "-x"}, []string{"nft", "--", "list", "-x"}},
		{[]string{"-", "x"}, []string{"nft", "--", "-", "x"}},
		{nil, []string{"nft"}},
	} {
		if got := nftArgv(c.in...); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q want %q", c.in, got, c.want)
		}
	}
}

// TestSocketActivation runs the helper as systemd would: the socket at
// fd 3, LISTEN_PID and LISTEN_FDS set for it.
func TestSocketActivation(t *testing.T) {
	if os.Getenv("FROS_HELPER_ACTIVATED") == "1" {
		os.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
		os.Setenv("LISTEN_FDS", "1")
		l, err := Listen("/nonexistent/apply.sock") // must not bind this
		if err != nil {
			os.Stderr.WriteString(err.Error())
			os.Exit(3)
		}
		if os.Getenv("LISTEN_PID") != "" || os.Getenv("LISTEN_FDS") != "" {
			os.Exit(4)
		}
		s := &Server{Env: DefaultEnv(), Policy: func() Policy { return only(os.Getuid(), Full) },
			ReadTimeout: 5 * time.Second, MaxConns: 1}
		s.Serve(l)
		os.Exit(0)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "apply.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := l.File()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSocketActivation$")
	cmd.Env = append(os.Environ(), "FROS_HELPER_ACTIVATED=1")
	cmd.ExtraFiles = []*os.File{f}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	l.SetUnlinkOnClose(false)
	l.Close() // the child holds the socket now
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	if got := send(t, path, `{"cmd": "ping"}`+"\n"); got != `{"ok":true,"message":"pong"}`+"\n" {
		t.Fatalf("got %q (%s)", got, stderr.String())
	}
}

const runtimeYAML = `version: 1
hostname: fr-router
zones: {wan: {}, lan: {}, guest: {}}
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 10.73.1.1/24}
  guest: {device: eth2, zone: guest, address: 10.73.2.1/24}
rules: [{name: lan-out, action: accept, from_zone: lan, to_zone: wan}]
nat: {masquerade: [{out_zone: wan}]}
ztna:
  enabled: true
  session_ttl_seconds: 3600
  users: [{username: kolos, password_hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"}]
iot: {enabled: true, zones: [guest]}
`

// TestRealNft loads a ruleset nft.Build wrote, with members in every set
// the status commands read, into a network namespace of its own, and
// reads it back through the commands: the JSON shapes are the real nft's.
func TestRealNft(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"nft", "unshare"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("needs " + bin)
		}
	}
	raw, err := config.LoadYAML(runtimeYAML)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	script, err := nft.Build(cfg, nft.Options{Now: time.Unix(1793491200, 0), Runtime: &nft.RuntimeSets{
		BruteforceJail:    []nft.Timed{{Member: "10.73.1.5", Left: 600}},
		BruteforceJail6:   []nft.Timed{{Member: "2001:db8:1::5", Left: 600}, {Member: "2001:db8:2::/64", Left: 600}},
		BruteforceJailMac: []nft.Timed{{Member: "52:54:00:12:34:56", Left: 600}},
		IDSQuarantine:     []nft.Timed{{Member: "10.73.2.9", Left: 600}},
		IDSQuarantineMac:  []nft.Timed{{Member: "aa:bb:cc:dd:ee:01", Left: 600}},
		Ztna: []nft.ZtnaSession{{IP: "10.73.1.20", MAC: "aa:bb:cc:dd:ee:02", Left: 600},
			{IP: "2001:db8:1::20", MAC: "aa:bb:cc:dd:ee:03", Left: 600}},
		IotIsolated: []string{"aa:bb:cc:dd:ee:10"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "ruleset.nft")
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := testServer(t, only(0, Full))
	// Each nft run gets a fresh namespace with the ruleset loaded first.
	s.Env.Nft = func(argv []string) (NftResult, error) {
		return RunNft(append([]string{"unshare", "-n", "sh", "-c", `nft -f "$1" && shift && exec "$@"`, "sh", file}, argv...))
	}
	for cmd, want := range map[string][]string{
		"bruteforce_status":     {"10.73.1.5", "2001:db8:1::5", "2001:db8:2::/64", "52:54:00:12:34:56"},
		"ids_quarantine_status": {"10.73.2.9", "aa:bb:cc:dd:ee:01"},
		"ztna_sessions_status":  {"10.73.1.20 aa:bb:cc:dd:ee:02", "2001:db8:1::20 aa:bb:cc:dd:ee:03"},
		"iot_isolation_status":  {"aa:bb:cc:dd:ee:10"},
	} {
		reply, err := s.Answer(bufio.NewReader(strings.NewReader(`{"cmd": "`+cmd+`"}`+"\n")), 1, 0)
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		if got := members(t, reply); !slices.Equal(got, want) {
			t.Errorf("%s: %s\n got %q\nwant %q", cmd, marshal(t, reply), got, want)
		}
	}
}

// members is the members a status reply lists, and checks the time each
// has left.
func members(t *testing.T, reply any) []string {
	var out []string
	left := func(n interface{ Int64() int64 }) {
		if s := n.Int64(); s <= 0 || s > 600 {
			t.Errorf("%d seconds left, want 1-600", s)
		}
	}
	switch r := reply.(type) {
	case bruteforceReply:
		for _, b := range r.Banned {
			out = append(out, b.IP)
			left(b.ExpiresIn)
		}
	case idsReply:
		for _, q := range r.Quarantined {
			out = append(out, q.IP)
			left(q.ExpiresIn)
		}
		for _, m := range r.MACs {
			out = append(out, m.MAC)
			left(m.ExpiresIn)
		}
	case ztnaReply:
		for _, z := range r.Sessions {
			out = append(out, z.IP+" "+z.MAC)
			left(z.ExpiresIn)
		}
	case iotReply:
		out = r.Isolated
	default:
		t.Fatalf("reply %s", marshal(t, reply))
	}
	return out
}

// TestAnotherUID: a peer running as another user (nobody) is known by
// its own uid, whatever it sends.
func TestAnotherUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3 for the other user's client")
	}
	const nobody = 65534
	for _, c := range []struct {
		policy Policy
		want   string
	}{
		{only(os.Getuid(), Full), `{"ok":false,"message":"command 'ping' is not allowed for uid 65534"}` + "\n"},
		{only(nobody, Sensor), `{"ok":true,"message":"pong"}` + "\n"},
	} {
		s, path := testServer(t, c.policy)
		serve(t, s, path)
		for i, dir := 0, path; i < 4; i, dir = i+1, filepath.Dir(dir) {
			os.Chmod(dir, 0o777) // the socket and the test's directories up to TempDir's own
		}
		client := exec.Command(python, "-c", `import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b'{"cmd": "ping"}\n')
s.shutdown(socket.SHUT_WR)
out = b""
while chunk := s.recv(65536):
    out += chunk
sys.stdout.write(out.decode())`, path)
		client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody}}
		out, err := client.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if string(out) != c.want {
			t.Errorf("got %q want %q", out, c.want)
		}
	}
}
