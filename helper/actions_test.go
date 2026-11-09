package helper

import (
	"bufio"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// TestPyIsIdentifier holds pyIsIdentifier to Python 3.13's
// str.isidentifier, the audit fields' check.
func TestPyIsIdentifier(t *testing.T) {
	// From Python: {c: c.isidentifier() for c in cases}.
	want := map[string]bool{"a": true, "_": true, "_1": true, "a1": true, "1a": false, "": false, "é": true,
		"név": true, "a-b": false, "a b": false, "ǅ": true, "ⅰx": true, "x·y": true,
		"·x": false, "℘x": true, "x℘": true, "á": true, "́a": false, "Ⅸ": true,
		"x٣": true, "a︳": true, "\U0001d518x": true, "ªb": true, "ゝ": true, "゛x": false,
		"x゛": false, "ⸯx": false, "x‌": true, "a·": true, "ͺ": false, "xͺ": false,
		"ﱞ": false, "ﹿ": true, "ำ": false, "xำ": true, "ﾞ": false, "xﾞ": true}
	for s, w := range want {
		if got := pyIsIdentifier(s); got != w {
			t.Errorf("pyIsIdentifier(%+q) = %v, want %v", s, got, w)
		}
	}
}

const actionsYAML = runtimeYAML + `wireguard:
  enabled: true
  address: 10.99.0.1/24
  listen_port: 51820
  zone: lan
`

// TestRealNftCommands loads a ruleset nft.Build wrote into a network
// namespace of its own, has the commands put hosts into its sets there
// with the real nft, and reads them back through the status commands.
func TestRealNftCommands(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	for _, bin := range []string{"nft", "unshare", "nsenter"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skip("needs " + bin)
		}
	}
	holder := exec.Command("unshare", "-n", "sleep", "600")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { holder.Process.Kill(); holder.Wait() }()
	inNS := func(argv []string) []string {
		return append([]string{"nsenter", "-t", strconv.Itoa(holder.Process.Pid), "-n"}, argv...)
	}
	waitForNamespace(t, holder.Process.Pid)

	raw, err := config.LoadYAML(actionsYAML)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	script, err := nft.Build(cfg, nft.Options{Now: time.Now(), Runtime: &nft.RuntimeSets{}})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := testServer(t, only(0, Full))
	if err := os.WriteFile(s.Env.ConfigPath, []byte(actionsYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Env.Nft = func(argv []string) (NftResult, error) { return RunNft(inNS(argv)) }
	s.Env.Sys.Run = func(c apply.Cmd) (apply.Result, error) {
		if c.Argv[0] != "nft" {
			return apply.Result{}, apply.ErrNotFound
		}
		c.Argv = inNS(c.Argv)
		return apply.Run(c)
	}
	if r, err := s.Env.Sys.Run(apply.Cmd{Argv: []string{"nft", "-f", "-"}, Stdin: script}); err != nil || r.Code != 0 {
		t.Fatalf("loading the ruleset: %v %s", err, r.Stderr)
	}
	ask := func(line string) any {
		t.Helper()
		reply, err := s.Answer(bufio.NewReader(strings.NewReader(line+"\n")), 1, 0)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if text := marshal(t, reply); strings.Contains(text, `"ok":false`) {
			t.Fatalf("%s: %s", line, text)
		}
		return reply
	}
	ask(`{"cmd": "ban_ip", "ip": "10.73.1.9", "duration_seconds": 600}`)
	ask(`{"cmd": "ban_ip", "ip": "2001:db8::9", "duration_seconds": 600}`)
	ask(`{"cmd": "quarantine_ip", "ip": "10.73.2.30", "duration_seconds": 600}`)
	ask(`{"cmd": "iot_sync_isolation", "macs": ["AA:BB:CC:DD:EE:20", "aa:bb:cc:dd:ee:21"]}`)
	ask(`{"cmd": "iot_sync_isolation", "macs": ["aa:bb:cc:dd:ee:21"]}`)
	ask(`{"cmd": "authorize_ztna", "ip": "10.99.0.2", "username": "kolos"}`)
	for line, want := range map[string][]string{
		`{"cmd": "bruteforce_status"}`:     {"10.73.1.9", "2001:db8::9"},
		`{"cmd": "ids_quarantine_status"}`: {"10.73.2.30"},
		`{"cmd": "iot_isolation_status"}`:  {"aa:bb:cc:dd:ee:21"},
	} {
		if got := members(t, ask(line)); !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", line, got, want)
		}
	}
	status, ok := ask(`{"cmd": "ztna_status", "ip": "10.99.0.2"}`).(ztnaFound)
	if !ok || status.Username != "kolos" || status.MAC != "" || status.ExpiresIn.Int64() <= 3500 {
		t.Errorf("ztna_status: %s", marshal(t, status))
	}
}

// waitForNamespace waits until pid runs in a network namespace other
// than this process's.
func waitForNamespace(t *testing.T, pid int) {
	self, _ := os.Readlink("/proc/self/ns/net")
	for range 100 {
		if other, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/ns/net"); err == nil && other != self {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the namespace holder did not start")
}
