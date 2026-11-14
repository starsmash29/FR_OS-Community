//go:build linux

package apply

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestDHCPProbeReal sends the DHCP probe out of a real veth, in a network
// namespace of its own, to a responder on the other end that answers on
// a packet socket as a DHCP server would: the probe hears the offer for
// its own xid (after one for another xid, which it must ignore), and
// hears nothing where nothing answers. Needs root, ip and unshare; the
// test binary runs itself again under `unshare -n`.
func TestDHCPProbeReal(t *testing.T) {
	if os.Getenv("FROS_DHCP_NETNS") == "" {
		if os.Geteuid() != 0 {
			t.Skip("needs root")
		}
		for _, bin := range []string{"ip", "unshare"} {
			if _, err := exec.LookPath(bin); err != nil {
				t.Skip("no " + bin)
			}
		}
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestDHCPProbeReal$", "-test.v")
		cmd.Env = append(os.Environ(), "FROS_DHCP_NETNS=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("in its namespace: %v\n%s", err, out)
		}
		t.Logf("%s", out)
		return
	}
	ip := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %q: %v\n%s", args, err, out)
		}
	}
	ip("link", "add", "fr-wan0", "address", "52:54:00:aa:bb:01", "type", "veth", "peer", "name", "fr-dhcp0")
	ip("link", "set", "dev", "fr-dhcp0", "up")

	// The port's sysfs, as the probe reads it (the namespace's own
	// /sys/class/net would need sysfs mounted again).
	sysNet := t.TempDir()
	os.MkdirAll(filepath.Join(sysNet, "fr-wan0"), 0o755)
	os.WriteFile(filepath.Join(sysNet, "fr-wan0", "address"), []byte("52:54:00:aa:bb:01\n"), 0o644)
	os.WriteFile(filepath.Join(sysNet, "fr-wan0", "carrier"), []byte("1\n"), 0o644)
	s := DefaultSystem()
	s.Paths.NetClass = sysNet
	n := byte(0)
	s.Random = func(b []byte) error {
		for i := range b {
			n++
			b[i] = n
		}
		return nil
	}

	// No server yet: no answer, after every attempt.
	if network, ok := s.probeDHCP("fr-wan0", 200*time.Millisecond, 2, time.Second); ok {
		t.Fatalf("offered %q with no server", network)
	}

	done := make(chan error, 1)
	go func() { done <- answerDiscover(t, "fr-dhcp0") }()
	time.Sleep(100 * time.Millisecond) // the responder's socket is bound
	network, ok := s.probeDHCP("fr-wan0", 2*time.Second, 3, time.Second)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !ok || network != "192.168.1.0/24" {
		t.Fatalf("offered %q (%v), want 192.168.1.0/24", network, ok)
	}
	// And DHCPOffer, as first boot asks, with no fake in its place.
	go func() { done <- answerDiscover(t, "fr-dhcp0") }()
	time.Sleep(100 * time.Millisecond)
	network, ok = s.DHCPOffer("fr-wan0")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !ok || network != "192.168.1.0/24" {
		t.Fatalf("DHCPOffer: %q (%v)", network, ok)
	}
	// An interface name the validator refuses is never probed.
	if _, ok := s.probeDHCP("-fr", time.Millisecond, 1, time.Millisecond); ok {
		t.Fatal("probed a refused name")
	}
}

// answerDiscover waits on device for one DHCPDISCOVER and answers it
// twice: an offer for another xid first, then one for its own.
func answerDiscover(t *testing.T, device string) error {
	ifi, err := net.InterfaceByName(device)
	if err != nil {
		return err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: ifi.Index}); err != nil {
		return err
	}
	tv := syscall.NsecToTimeval((5 * time.Second).Nanoseconds())
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		frame := buf[:n]
		// UDP to port 67, a BOOTREQUEST.
		if n < 14+20+8+240 || frame[14+9] != 17 || binary.BigEndian.Uint16(frame[14+20+2:]) != 67 || frame[14+28] != 1 {
			continue
		}
		xid := binary.BigEndian.Uint32(frame[14+28+4:])
		mac := frame[14+28+28 : 14+28+34]
		for _, x := range []uint32{xid + 1, xid} {
			if _, err := syscall.Write(fd, offerFrame(mac, x)); err != nil {
				return err
			}
		}
		return nil
	}
}

// offerFrame is a DHCPOFFER of 192.168.1.57/24 to mac, broadcast.
func offerFrame(mac []byte, xid uint32) []byte {
	bootp := make([]byte, 236)
	bootp[0], bootp[1], bootp[2] = 2, 1, 6
	binary.BigEndian.PutUint32(bootp[4:], xid)
	copy(bootp[16:20], []byte{192, 168, 1, 57})
	copy(bootp[28:34], mac)
	payload := append(bootp, bootpMagic...)
	payload = append(payload, 53, 1, dhcpOffer, 1, 4, 255, 255, 255, 0, 54, 4, 192, 168, 1, 1, 255)
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 67)
	binary.BigEndian.PutUint16(udp[2:], 68)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[8], ip[9] = 64, 17
	copy(ip[12:], []byte{192, 168, 1, 1})
	copy(ip[16:], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))
	frame := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x52, 0x54, 0, 0xaa, 0xbb, 0x02, ethPIP >> 8, ethPIP & 0xff}
	frame = append(frame, ip...)
	return append(frame, udp...)
}
