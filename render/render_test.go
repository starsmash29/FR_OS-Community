package render

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// TestPythonJSON: json.dumps(v, indent=2) as Python 3.13 writes it
// (each want was printed by Python).
func TestPythonJSON(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want string
	}{
		{map[string]any{"a": []string{}}, "{\n  \"a\": []\n}"},
		{struct {
			S string `json:"s"`
		}{"a\x01\x7f\b é😀<&>\"\\/\t"}, "{\n  \"s\": \"a\\u0001\\u007f\\b\\u2028\\u00e9\\ud83d\\ude00<&>\\\"\\\\/\\t\"\n}"},
		{[]any{true, int64(1) << 62, "x"}, "[\n  true,\n  4611686018427387904,\n  \"x\"\n]"},
	} {
		got, err := pythonJSON(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("pythonJSON(%#v) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func parse(t *testing.T, yaml string) *config.Config {
	t.Helper()
	raw, err := config.LoadYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const vlanConfig = `
version: 1
hostname: fr-router
zones: {wan: {}, lan: {}, iot: {}}
interfaces:
  wan: {device: eth0, zone: wan}
  lan: {device: eth1, zone: lan, address: 10.73.1.1/24}
  iot: {device: eth1.30, zone: iot, address: 192.168.30.1/24, vlan: {parent: eth1, id: 30}}
nat: {masquerade: [{out_zone: wan}]}
dhcp:
  lan: {range_start: 10.73.1.100, range_end: 10.73.1.199, dns_servers: [9.9.9.9]}
  iot: {range_start: 192.168.30.100, range_end: 192.168.30.199, dns_servers: [9.9.9.9]}
`

// TestKeaListening: the check before the apply leaves out the devices
// that aren't there yet (a VLAN), and keeps every subnet.
func TestKeaListening(t *testing.T) {
	c := parse(t, vlanConfig)
	text, err := KeaListening(c, func(d string) bool { return d != "eth1.30" })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "\"interfaces\": [\n        \"eth1\"\n      ]") || !strings.Contains(text, "192.168.30.0/24") {
		t.Errorf("KeaListening:\n%s", text)
	}
}

// TestULA: the /64s of the /48 and the tunnel's, as Python's ipaddress
// writes them, the zero groups compressed.
func TestULA(t *testing.T) {
	p := netip.MustParsePrefix("fd00:0:1::/48")
	if got := TunnelNetwork6(p).String(); got != "fd00:0:1:ffff::/64" {
		t.Errorf("TunnelNetwork6 = %s", got)
	}
	if got := subnet64(p, 1).String(); got != "fd00:0:1:1::" {
		t.Errorf("subnet64 = %s", got)
	}
	wg := &config.WireguardConfig{Address: "10.99.0.1/24"}
	if got, err := PeerAddress6(wg, "10.99.0.200/32", p); err != nil || got != "fd00:0:1:ffff::c8/128" {
		t.Errorf("PeerAddress6 = %s, %v", got, err)
	}
}

// TestOpenSSLConf: an OpenSSL server configured by the fragment, as the
// webUI's listener is, takes TLS 1.3 and refuses TLS 1.2
// (security-lessons H3).
func TestOpenSSLConf(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	dir := t.TempDir()
	conf := dir + "/openssl.cnf"
	if err := writeFile(conf, OpenSSLConf(false)); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) *exec.Cmd {
		cmd := exec.Command("openssl", args...)
		cmd.Env = []string{"OPENSSL_CONF=" + conf}
		return cmd
	}
	if out, err := run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", dir+"/key.pem", "-out", dir+"/cert.pem", "-subj", "/CN=fr-router", "-days", "1").CombinedOutput(); err != nil {
		t.Fatalf("openssl req: %v\n%s", err, out)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	server := run("s_server", "-accept", "127.0.0.1:"+port, "-cert", dir+"/cert.pem", "-key", dir+"/key.pem", "-www")
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { server.Process.Kill(); server.Wait() }()
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err == nil {
			c.Close()
			break
		}
		if i == 100 {
			t.Fatal("s_server did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	client := func(version string) error {
		cmd := exec.Command("openssl", "s_client", "-connect", "127.0.0.1:"+port, version)
		cmd.Env = []string{"OPENSSL_CONF=/dev/null"}
		cmd.Stdin = strings.NewReader("")
		return cmd.Run()
	}
	if err := client("-tls1_3"); err != nil {
		t.Errorf("TLS 1.3 refused: %v", err)
	}
	if err := client("-tls1_2"); err == nil {
		t.Error("TLS 1.2 taken")
	}
}

func writeFile(path, text string) error { return os.WriteFile(path, []byte(text), 0o600) }
