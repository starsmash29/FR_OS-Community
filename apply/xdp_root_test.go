//go:build linux

package apply

import (
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// evilTestHello is a frame of the recorded XDP cases
// (testdata/reference/xdp.jsonl): an IPv4 ClientHello for "evil.test",
// which 1.x's program dropped as a blocklist match.
const evilTestHello = "0200000000010200000000020800450000e1123440004006e8030a0000055db8d8229c4001bb000003e8000000005018faf0b0" +
	"00000016030100b4010000b003036465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182832000010203" +
	"0405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f001e130113021303c02bc02fc02cc030cca9cca8c013c0" +
	"14009c009d002f003501000049000a00080006001d0017001800000024002200001f6576696c2e746573742e2e2e2e2e2e2e2e" +
	"2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e002b00050403040303000d00080008040304010503"

// evilTestWholeHello is a whole IPv4 ClientHello for "evil.test", with
// right checksums, that 1.x's TLS fingerprinting parses (evilTestHello's
// extensions run past the frame: 1.x counts a parse error for it). Its
// JA4 and JA3 are what 1.x's frfw.tlsfp.fingerprint gives.
const (
	evilTestWholeHello = "0200000000010200000000020800450000c2123440004006e8220a0000055db8d8229c4001bb000003e8000000005018faf05be6" +
		"00001603010095010000910303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20000102030405" +
		"060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000a130113021303c02bc02f0100003e0000000e000c00000965" +
		"76696c2e74657374000a00080006001d00170018002b00050403040303000d000a00080804040304010503001000050003026832"
	evilTestWholeJA4 = "t13d0505h2_e133e205ac38_a2aeacb3da8a"
	evilTestWholeJA3 = "bb49fd6775cf00d80b60549134e5d127"
)

// skipXdpRoot skips without what a real attach needs; FROS_XDP_REQUIRED=1
// (CI's XDP job) makes that a failure instead.
func skipXdpRoot(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("FROS_XDP_REQUIRED") == "1" {
		t.Fatal(why)
	}
	t.Skip(why)
}

// xdpRig is what a real attach needs, as root: a veth pair (the
// filter goes on a, frames are sent on b) and a System whose fr-xdp is
// the one built here, with pins of the test's own; systemctl does
// nothing (the readers aren't installed here). Skipped without them.
func xdpRig(t *testing.T) (sys *System, a, b string) {
	t.Helper()
	if os.Geteuid() != 0 {
		skipXdpRoot(t, "needs root")
	}
	var fs syscall.Statfs_t
	if syscall.Statfs("/sys/fs/bpf", &fs) != nil || fs.Type != 0xcafe4a11 {
		skipXdpRoot(t, "no bpffs at /sys/fs/bpf")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		skipXdpRoot(t, "no ip")
	}
	object := envOr("FROS_XDP_OBJECT", "../crates/fros-xdp-ebpf/target/bpfel-unknown-none/release/fros-xdp")
	tool := envOr("FROS_XDP_TOOL", "../target/debug/fr-xdp")
	for _, p := range []string{object, tool} {
		if _, err := os.Stat(p); err != nil {
			skipXdpRoot(t, fmt.Sprintf("%s not built", p))
		}
	}
	tool, _ = filepath.Abs(tool)
	object, _ = filepath.Abs(object)

	a, b = fmt.Sprintf("frxa%d", os.Getpid()%10000), fmt.Sprintf("frxb%d", os.Getpid()%10000)
	link := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(ip, args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	link("link", "add", a, "type", "veth", "peer", "name", b)
	t.Cleanup(func() { _ = exec.Command(ip, "link", "del", a).Run() })
	link("link", "set", a, "up")
	link("link", "set", b, "up")

	pins := fmt.Sprintf("/sys/fs/bpf/fr_os_xdp_test_%d", os.Getpid())
	t.Cleanup(func() { _ = removePinTree(pins) })
	sys = DefaultSystem()
	sys.Paths.XdpPins = pins
	sys.Paths.XdpObject = object
	sys.Paths.XdpState = filepath.Join(t.TempDir(), "xdp_state.json")
	run := sys.Run
	sys.Run = func(c Cmd) (Result, error) {
		switch c.Argv[0] {
		case XdpTool:
			c.Argv = append([]string{tool}, c.Argv[1:]...)
		case "systemctl": // the readers aren't installed here
			return Result{}, nil
		}
		return run(c)
	}
	return sys, a, b
}

// TestXdpRealAttach applies the filter for real, as root: the object
// built from crates/fros-xdp-ebpf is loaded and pinned by fr-xdp, attached
// to a veth with ip, a ClientHello for a blocked name sent through the
// pair is dropped and counted, and turning the filter off detaches it
// and removes the pins.
func TestXdpRealAttach(t *testing.T) {
	sys, a, b := xdpRig(t)

	conf := func(enabled bool) *config.Config {
		raw, err := config.LoadYAML(fmt.Sprintf(`version: 1
hostname: r
interfaces:
  wan: {device: %s, zone: wan}
  lan: {device: %s, zone: lan, address: 192.168.7.1/24}
zones: {wan: {}, lan: {}}
xdp_sni_filter: {enabled: %t, interfaces: [lan], blocklist: [evil.test]}
`, b, a, enabled))
		if err != nil {
			t.Fatal(err)
		}
		c, err := config.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	on := conf(true)
	blocklist, _, err := sys.xdpBlocklist(on)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := sys.syncXDP(on, blocklist, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)
	mode, id, ok, err := sys.xdpLive(a)
	if err != nil || !ok || mode != xdpNative {
		t.Fatalf("live on %s: %q %v %v, want native", a, mode, ok, err)
	}
	if pinned, ok := sys.xdpPinnedID(); !ok || pinned != id {
		t.Errorf("pinned program %d (%v), attached %d", pinned, ok, id)
	}

	// Sent on the peer, the frame reaches the filter on a.
	frame, _ := hex.DecodeString(evilTestHello)
	send(t, b, frame)
	res, err := sys.xdpTool("", "stats", "--", sys.Paths.xdpMap("stats"))
	if err != nil || res.Code != 0 {
		t.Fatalf("stats: %v %s", err, res.Stderr)
	}
	var stats []struct {
		Key   int    `json:"key"`
		Value uint64 `json:"value"`
	}
	if err := json.Unmarshal([]byte(res.Stdout), &stats); err != nil || len(stats) < 5 {
		t.Fatalf("stats %q: %v", res.Stdout, err)
	}
	if stats[4].Value != 1 { // drop_match
		t.Errorf("drop_match %d, want 1 (%s)", stats[4].Value, res.Stdout)
	}

	// Applied again: kept as it is.
	if _, err := sys.syncXDP(on, blocklist, false); err != nil {
		t.Fatal(err)
	}
	if _, id2, ok, _ := sys.xdpLive(a); !ok || id2 != id {
		t.Errorf("applied again: program %d (%v), want %d kept", id2, ok, id)
	}

	if _, err := sys.syncXDP(conf(false), nil, false); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := sys.xdpLive(a); ok || err != nil {
		t.Errorf("still attached after disabling (%v)", err)
	}
	if _, err := os.Stat(sys.Paths.XdpPins); !os.IsNotExist(err) {
		t.Errorf("pins left at %s: %v", sys.Paths.XdpPins, err)
	}
}

// TestXdpReadersRealAttach runs the two readers of the filter's ring
// buffers, as root, on a real attach: fr-xdp-sni-logger and fr-tls-fp
// open the pinned maps, give up root, and a ClientHello for a blocked
// name sent through the pair is logged as a drop in the event file
// (root's, 0640) and fingerprinted into the inventory.
func TestXdpReadersRealAttach(t *testing.T) {
	sys, a, b := xdpRig(t)
	logger := envOr("FROS_XDP_LOGGER", "../target/debug/fr-xdp-sni-logger")
	tlsfp := envOr("FROS_TLSFP_DAEMON", "../target/debug/fr-tls-fp")
	for _, p := range []string{logger, tlsfp} {
		if _, err := os.Stat(p); err != nil {
			skipXdpRoot(t, fmt.Sprintf("%s not built", p))
		}
	}

	conf := func(enabled bool) (config.Value, *config.Config) {
		raw, err := config.LoadYAML(fmt.Sprintf(`version: 1
hostname: r
interfaces:
  wan: {device: %s, zone: wan}
  lan: {device: %s, zone: lan, address: 192.168.7.1/24}
zones: {wan: {}, lan: {}}
xdp_sni_filter: {enabled: %[3]t, interfaces: [lan], blocklist: [evil.test]}
tls_fingerprint: {enabled: %[3]t}
`, b, a, enabled))
		if err != nil {
			t.Fatal(err)
		}
		c, err := config.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return raw, c
	}
	raw, on := conf(true)
	_, off := conf(false)
	blocklist, _, err := sys.xdpBlocklist(on)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sys.syncXDP(on, blocklist, false); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = sys.syncXDP(off, nil, false) })

	// The readers become fr_os-sensor (nobody here): the inventory's
	// directory is theirs to write, the rest only to read.
	dir, err := os.MkdirTemp("", "fros-readers-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	state := filepath.Join(dir, "sensors")
	for path, mode := range map[string]os.FileMode{dir: 0o755, state: 0o777} {
		if err := os.MkdirAll(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	view := filepath.Join(dir, "sensor-view.json")
	if err := os.WriteFile(view, []byte(SensorView(raw)), 0o644); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events.jsonl")
	inventory := filepath.Join(state, "tls_fingerprints.json")

	start := func(argv ...string) *exec.Cmd {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		out := &strings.Builder{}
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Logf("%s:\n%s", filepath.Base(argv[0]), out)
		})
		return cmd
	}
	loggerCmd := start(logger, "--map", sys.Paths.xdpMap("events"), "--events", events)
	tlsfpCmd := start(tlsfp, "--map", sys.Paths.xdpMap("hello_pkts"), "--view", view, "--state", inventory,
		"--socket", filepath.Join(dir, "apply.sock"), "--flush", "1")

	frame, _ := hex.DecodeString(evilTestWholeHello)
	send(t, b, frame)

	// Up to 15 seconds for the event line and the inventory's first write.
	var logged, written string
	for range 150 {
		if data, err := os.ReadFile(events); err == nil {
			logged = string(data)
		}
		if data, err := os.ReadFile(inventory); err == nil {
			written = string(data)
		}
		if strings.Contains(logged, "\n") && strings.Contains(written, `"hellos": 1`) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, want := range []string{`"action": "drop"`, `"saddr": "10.0.0.5"`, `"sni": "evil.test"`} {
		if !strings.Contains(logged, want) {
			t.Errorf("event file %q: no %s", logged, want)
		}
	}
	for _, want := range []string{`"10.0.0.5"`, evilTestWholeJA4, evilTestWholeJA3, `"hellos": 1`, `"parse_errors": 0`} {
		if !strings.Contains(written, want) {
			t.Errorf("inventory %q: no %s", written, want)
		}
	}
	if fi, err := os.Stat(events); err != nil {
		t.Error(err)
	} else if st := fi.Sys().(*syscall.Stat_t); fi.Mode().Perm() != 0o640 || st.Uid != 0 {
		t.Errorf("event file mode %v uid %d, want 0640 and root's", fi.Mode().Perm(), st.Uid)
	}
	// Neither keeps root once the map is open.
	for name, cmd := range map[string]*exec.Cmd{"fr-xdp-sni-logger": loggerCmd, "fr-tls-fp": tlsfpCmd} {
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		if err != nil {
			t.Errorf("%s: %v (exited?)", name, err)
			continue
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") || strings.HasPrefix(line, "Gid:") {
				for _, id := range strings.Fields(line)[1:] {
					if id == "0" {
						t.Errorf("%s still root: %s", name, line)
					}
				}
			}
		}
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// send writes frame out of device as it is (AF_PACKET).
func send(t *testing.T, device string, frame []byte) {
	t.Helper()
	// Protocol 0: it only sends.
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	iface, err := net.InterfaceByName(device)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: iface.Index}); err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(fd, frame); err != nil {
		t.Fatal(err)
	}
}
