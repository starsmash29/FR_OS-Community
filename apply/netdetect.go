package apply

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// The router's network ports, read straight from sysfs (frfw.netdetect):
// MAC address, driver, link and speed are plain files under
// /sys/class/net/<port>/, so nothing is run to list them. The one
// exception is first boot's WAN/LAN choice (ChooseWanLan, ROADMAP SEC-8),
// which asks each port whether a DHCP server answers there.

// ignoredInterfaces are virtual or software devices, never a WAN, LAN or
// OPT uplink: left out of the list unless asked for.
var ignoredInterfaces = []string{"veth", "docker", "br-", "virbr", "tun", "tap", "ifb", "bond", "wg"}

// DetectedInterface is one port as sysfs describes it; a nil field is
// one sysfs doesn't tell.
type DetectedInterface struct {
	Name   string
	MAC    *string
	Driver *string
	Link   *bool
	// SpeedMbps is the negotiated speed, 0 when not known.
	SpeedMbps int64
}

// ListInterfaces is the ports under sysNet (/sys/class/net), sorted by
// name; the virtual ones only with includeVirtual.
func ListInterfaces(sysNet string, includeVirtual bool) []DetectedInterface {
	st, err := os.Stat(sysNet)
	if err != nil || !st.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(sysNet)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	var out []DetectedInterface
	for _, name := range names {
		if !includeVirtual && ignoredInterface(name) {
			continue
		}
		out = append(out, readInterface(filepath.Join(sysNet, name)))
	}
	return out
}

func ignoredInterface(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range ignoredInterfaces {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readInterface(dir string) DetectedInterface {
	return DetectedInterface{
		Name:      filepath.Base(dir),
		MAC:       readStripped(filepath.Join(dir, "address")),
		Driver:    readDriver(dir),
		Link:      readCarrier(dir),
		SpeedMbps: readSpeed(dir),
	}
}

// readStripped is Path.read_text().strip(), or nil.
func readStripped(path string) *string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := config.PyStrip(string(data))
	return &s
}

// readDriver is the name the device/driver link points at; none for a
// driverless (virtual) device.
func readDriver(dir string) *string {
	link := filepath.Join(dir, "device", "driver")
	if !exists(link) {
		return nil
	}
	target, err := filepath.EvalSymlinks(link)
	if err != nil {
		return nil
	}
	name := filepath.Base(target)
	return &name
}

func readCarrier(dir string) *bool {
	raw := readStripped(filepath.Join(dir, "carrier"))
	if raw == nil {
		return nil
	}
	up := *raw == "1"
	return &up
}

// readSpeed: the kernel says -1 (or 0) when the speed is unknown, e.g.
// with the link down.
func readSpeed(dir string) int64 {
	raw := readStripped(filepath.Join(dir, "speed"))
	if raw == nil {
		return 0
	}
	n, ok := config.PyInt(*raw)
	if !ok || n.Sign() <= 0 || !n.IsInt64() {
		return 0
	}
	return n.Int64()
}

// HasLink is whether device has a link right now (its carrier).
func HasLink(sysNet, device string) bool {
	if _, err := Ifname(device); err != nil {
		return false
	}
	up := readCarrier(filepath.Join(sysNet, device))
	return up != nil && *up
}

// --- the WAN/LAN choice at first boot (ROADMAP SEC-8, review v0.2.0 R14) ---------
//
// First boot used to make the first port the WAN and the second the
// LAN. Cabled the other way round, the router then served DHCP, as the
// LAN's gateway, onto the upstream network. The upstream side is the one
// where a DHCP server already answers, and the LAN must never be a port
// that already has one: so first boot asks each port, before anything is
// configured on it.

const (
	ethPIP       = 0x0800
	dhcpDiscover = 1
	dhcpOffer    = 2
)

var bootpMagic = []byte{0x63, 0x82, 0x53, 0x63}

func ipChecksum(header []byte) uint16 {
	var total uint32
	for i := 0; i+1 < len(header); i += 2 {
		total += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for total>>16 != 0 {
		total = total&0xFFFF + total>>16
	}
	return ^uint16(total)
}

// DiscoverFrame is a broadcast DHCPDISCOVER from mac, Ethernet header
// included: the port has no address yet, so it goes out on a packet
// socket. ipID is the IPv4 header's identification.
func DiscoverFrame(mac []byte, xid uint32, ipID uint16) []byte {
	bootp := make([]byte, 236)
	bootp[0], bootp[1], bootp[2] = 1, 1, 6
	binary.BigEndian.PutUint32(bootp[4:], xid)
	binary.BigEndian.PutUint16(bootp[10:], 0x8000) // broadcast: we can't take a unicast reply yet
	copy(bootp[28:44], mac)
	payload := append(bootp, bootpMagic...)
	payload = append(payload, 53, 1, dhcpDiscover, 55, 3, 1, 3, 6, 255)
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	binary.BigEndian.PutUint16(ip[4:], ipID)
	ip[8], ip[9] = 64, 17
	copy(ip[16:], []byte{255, 255, 255, 255})
	binary.BigEndian.PutUint16(ip[10:], ipChecksum(ip))
	frame := make([]byte, 0, 14+len(ip)+len(udp))
	frame = append(frame, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	frame = append(frame, mac...)
	frame = append(frame, ethPIP>>8, ethPIP&0xff)
	frame = append(frame, ip...)
	return append(frame, udp...)
}

// OfferedNetwork is the network a DHCPOFFER answering our DISCOVER xid
// offers an address in: the address and its subnet mask (option 1; a
// /24 when the server sends none or one that is no mask), as
// ipaddress.IPv4Network writes it; ok false when frame is no such offer.
func OfferedNetwork(frame []byte, xid uint32) (string, bool) {
	if len(frame) < 14+20+8+240 || frame[12] != ethPIP>>8 || frame[13] != ethPIP&0xff {
		return "", false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0F) * 4
	if ip[9] != 17 || len(ip) < ihl+8+240 {
		return "", false
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[2:4]) != 68 {
		return "", false
	}
	bootp := udp[8:]
	if bootp[0] != 2 || binary.BigEndian.Uint32(bootp[4:8]) != xid || string(bootp[236:240]) != string(bootpMagic) {
		return "", false
	}
	options := bootp[240:]
	isOffer := false
	mask := []byte{255, 255, 255, 0}
	for i := 0; i < len(options) && options[i] != 255; {
		if options[i] == 0 {
			i++
			continue
		}
		if i+1 >= len(options) {
			return "", false
		}
		code, length := options[i], int(options[i+1])
		if i+2+length > len(options) {
			return "", false
		}
		value := options[i+2 : i+2+length]
		switch {
		case code == 53 && length == 1:
			isOffer = value[0] == dhcpOffer
		case code == 1 && length == 4:
			mask = slices.Clone(value)
		}
		i += 2 + length
	}
	if !isOffer {
		return "", false
	}
	addr := binary.BigEndian.Uint32(bootp[16:20])
	prefix, ok := pyNetmaskPrefix(binary.BigEndian.Uint32(mask))
	if !ok {
		prefix = 24 // a mask that isn't one
	}
	network := addr & prefixMask(prefix)
	return fmt.Sprintf("%d.%d.%d.%d/%d", network>>24, network>>16&0xff, network>>8&0xff, network&0xff, prefix), true
}

// pyNetmaskPrefix is ipaddress's reading of a dotted mask: a netmask
// (ones, then zeros), else a host mask (zeros, then ones).
func pyNetmaskPrefix(m uint32) (int, bool) {
	if p, ok := contiguousPrefix(m); ok {
		return p, true
	}
	return contiguousPrefix(^m)
}

func contiguousPrefix(m uint32) (int, bool) {
	zeros := bits.TrailingZeros32(m) // 32 for 0
	prefix := 32 - zeros
	ones := uint64(m) >> zeros
	return prefix, ones == (uint64(1)<<prefix)-1
}

func prefixMask(prefix int) uint32 {
	if prefix == 0 {
		return 0
	}
	return ^uint32(0) << (32 - prefix)
}

// DHCPOffer asks device whether a DHCP server answers a DISCOVER there:
// the network it offers an address in, ok false when none answers
// (frfw.netdetect.dhcp_offer). Sent and heard on a packet socket, so the
// port needs no address and nothing is configured on it; no REQUEST
// follows, so no lease is taken. Needs root (CAP_NET_RAW). Any failure
// counts as no answer.
func (s *System) DHCPOffer(device string) (string, bool) {
	if s.ProbeDHCP != nil {
		return s.ProbeDHCP(device)
	}
	return s.probeDHCP(device, 3*time.Second, 3, 5*time.Second)
}

func (s *System) probeDHCP(device string, timeout time.Duration, attempts int, carrierWait time.Duration) (string, bool) {
	if _, err := Ifname(device); err != nil {
		return "", false
	}
	dir := filepath.Join(s.Paths.NetClass, device)
	macText := readStripped(filepath.Join(dir, "address"))
	if macText == nil {
		return "", false
	}
	mac, ok := parseMAC(*macText)
	if !ok {
		return "", false
	}
	// The port may still be down this early in first boot: set it up and
	// give its link a moment.
	s.Run(Cmd{Argv: []string{"ip", "link", "set", "dev", device, "up"}})
	deadline := time.Now().Add(carrierWait)
	for time.Now().Before(deadline) {
		if up := readCarrier(dir); up != nil && *up {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return packetProbe(device, mac, timeout, attempts, s.Random)
}

// parseMAC is bytes.fromhex(text.replace(":", "")), six bytes.
func parseMAC(text string) ([]byte, bool) {
	hex := strings.ReplaceAll(text, ":", "")
	var out []byte
	digits := 0
	var cur byte
	for _, r := range hex {
		if r == ' ' && digits%2 == 0 { // fromhex skips spaces between bytes
			continue
		}
		var v byte
		switch {
		case r >= '0' && r <= '9':
			v = byte(r - '0')
		case r >= 'a' && r <= 'f':
			v = byte(r - 'a' + 10)
		case r >= 'A' && r <= 'F':
			v = byte(r - 'A' + 10)
		default:
			return nil, false
		}
		cur = cur<<4 | v
		digits++
		if digits%2 == 0 {
			out = append(out, cur)
			cur = 0
		}
	}
	if digits%2 != 0 || len(out) != 6 {
		return nil, false
	}
	return out, true
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// packetProbe sends a DISCOVER out of device and waits for the offer
// answering it, attempts times.
func packetProbe(device string, mac []byte, timeout time.Duration, attempts int, random func([]byte) error) (string, bool) {
	ifi, err := net.InterfaceByName(device)
	if err != nil {
		return "", false
	}
	iface := ifi.Index
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, int(htons(ethPIP)))
	if err != nil {
		return "", false
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(ethPIP), Ifindex: iface}); err != nil {
		return "", false
	}
	buf := make([]byte, 4096)
	for range attempts {
		var r [6]byte
		if random(r[:]) != nil {
			return "", false
		}
		xid := binary.BigEndian.Uint32(r[:4])
		frame := DiscoverFrame(mac, xid, binary.BigEndian.Uint16(r[4:]))
		if _, err := syscall.Write(fd, frame); err != nil {
			return "", false
		}
		deadline := time.Now().Add(timeout)
		for {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			tv := syscall.NsecToTimeval(remaining.Nanoseconds())
			if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
				return "", false
			}
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				continue
			}
			if err != nil {
				return "", false
			}
			if network, ok := OfferedNetwork(buf[:n], xid); ok {
				return network, true
			}
		}
	}
	return "", false
}

// WanLanChoice is first boot's pick, and why, in a sentence the console
// and the first-boot log show. WanNetwork is the network the WAN's DHCP
// server offered an address in, when it did: the LAN must not overlap
// it (ROADMAP NET-12).
type WanLanChoice struct {
	Wan, Lan, Basis, WanNetwork string
}

// ChooseWanLan is which port is the WAN and which the LAN:
//
//   - exactly one port has a DHCP server answering: that one is the WAN
//     (the upstream network hands out addresses); the LAN is another
//     port, one with a link if there is one;
//   - several do: no choice. FR_OS serves DHCP on its LAN, and doing so
//     on a network that already has a server is the mistake this exists
//     to prevent; the admin assigns the ports;
//   - none does (a static or PPPoE upstream, a modem still booting): the
//     ports with a link first, then port order, said plainly, so the
//     console tells the admin to check the cabling.
//
// offer asks a port (DHCPOffer); link says whether a port has a link,
// asked after every port was probed, which is what sets them up
// (ROADMAP NET-13). The ports are asked one after the other.
func ChooseWanLan(ifaces []DetectedInterface, offer func(string) (string, bool), link func(string) bool) WanLanChoice {
	if len(ifaces) < 2 {
		return WanLanChoice{Basis: fmt.Sprintf("%d network port(s): nothing to choose", len(ifaces))}
	}
	names := make([]string, len(ifaces))
	offered := map[string]string{}
	answered := map[string]bool{}
	for i, iface := range ifaces {
		names[i] = iface.Name
	}
	// Every port at once, as 1.x's thread pool: a probe that hears
	// nothing waits its whole timeout, port after port otherwise.
	type answer struct {
		network string
		ok      bool
	}
	answers := make([]answer, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Go(func() {
			network, ok := offer(name)
			answers[i] = answer{network, ok}
		})
	}
	wg.Wait()
	for i, name := range names {
		offered[name], answered[name] = answers[i].network, answers[i].ok
	}
	linked := map[string]bool{}
	for _, name := range names {
		linked[name] = link(name)
	}
	var parts []string
	for _, name := range names {
		state := "no link"
		if linked[name] {
			state = "link"
		}
		parts = append(parts, name+" "+state)
	}
	ports := "ports: " + strings.Join(parts, ", ")
	var offering []string
	for _, name := range names {
		if answered[name] {
			offering = append(offering, name)
		}
	}
	switch {
	case len(offering) == 1:
		wan := offering[0]
		var others, withLink []string
		for _, name := range names {
			if name != wan {
				others = append(others, name)
				if linked[name] {
					withLink = append(withLink, name)
				}
			}
		}
		lan := others[0]
		why := "by port order: no other port has a link -- check the cabling"
		if len(withLink) > 0 {
			lan = withLink[0]
			why = fmt.Sprintf("the first of %d ports with a link", len(withLink))
			if len(withLink) == 1 {
				why = "the port with a link"
			}
		}
		return WanLanChoice{Wan: wan, Lan: lan, WanNetwork: offered[wan],
			Basis: "a DHCP server answered on " + wan + " only; the LAN is " + lan + ", " + why + " (" + ports + ")"}
	case len(offering) > 1:
		return WanLanChoice{Basis: "DHCP servers answered on " + strings.Join(offering, ", ") +
			": not putting the LAN where one already runs (" + ports + ")"}
	}
	var ordered []string
	for _, name := range names {
		if linked[name] {
			ordered = append(ordered, name)
		}
	}
	for _, name := range names {
		if !linked[name] {
			ordered = append(ordered, name)
		}
	}
	return WanLanChoice{Wan: ordered[0], Lan: ordered[1],
		Basis: "no DHCP server answered on any port: chosen by link, then port order -- check the cabling (" + ports + ")"}
}
