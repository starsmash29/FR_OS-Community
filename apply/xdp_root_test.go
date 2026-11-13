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

// skipXdpRoot skips without what a real attach needs; FROS_XDP_REQUIRED=1
// (CI's XDP job) makes that a failure instead.
func skipXdpRoot(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("FROS_XDP_REQUIRED") == "1" {
		t.Fatal(why)
	}
	t.Skip(why)
}

// TestXdpRealAttach applies the filter for real, as root: the object
// built from crates/fros-xdp-ebpf is loaded and pinned by fr-xdp, attached
// to a veth with ip, a ClientHello for a blocked name sent through the
// pair is dropped and counted, and turning the filter off detaches it
// and removes the pins.
func TestXdpRealAttach(t *testing.T) {
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

	a, b := fmt.Sprintf("frxa%d", os.Getpid()%10000), fmt.Sprintf("frxb%d", os.Getpid()%10000)
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
	sys := DefaultSystem()
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
	if _, err := os.Stat(pins); !os.IsNotExist(err) {
		t.Errorf("pins left at %s: %v", pins, err)
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
