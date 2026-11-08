package apply

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/render"
)

// The VPN tunnel (frfw.wireguard, security-lessons G8): one WireGuard
// device, configured with `wg syncconf` from standard input, so the
// private key is never in a file wg could leave behind, nor on a command
// line other users can read.

// WireguardIface is the tunnel interface.
const WireguardIface = "wg0"

// wgRun is frfw.wireguard._run: a failure is the program's own words.
func (s *System) wgRun(stdin string, check bool, argv ...string) (Result, error) {
	res, err := s.Run(Cmd{Argv: argv, Stdin: stdin, Timeout: 30 * time.Second})
	if errors.Is(err, ErrNotFound) {
		tool := "iproute2"
		if argv[0] == "wg" {
			tool = "wireguard-tools"
		}
		return res, stepErr("%s not found; install the %s package", config.Repr(argv[0]), tool)
	}
	if err != nil {
		return res, err
	}
	if check && res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return res, &StepError{msg}
		}
		return res, stepErr("%s exited with status %d", argv[0], res.Code)
	}
	return res, nil
}

// publicKeyOf is the X25519 public key of a base64 private key, or the
// refusal of something that isn't one.
func publicKeyOf(private string) (string, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(private)
	if err == nil && len(raw) != 32 {
		err = errors.New("length")
	}
	var key *ecdh.PrivateKey
	if err == nil {
		key, err = ecdh.X25519().NewPrivateKey(raw)
	}
	if err != nil {
		return "", &StepError{"not a WireGuard private key"}
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ensureWireguardKey is the router's private key, generated (0600, its
// directory 0700) the first time it is needed.
func (s *System) ensureWireguardKey() (string, error) {
	path := s.Paths.WireguardKey
	data, err := os.ReadFile(path)
	if err == nil {
		key := config.PyStrip(string(data))
		if _, err := publicKeyOf(key); err != nil {
			return "", err
		}
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", pyOSError(err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", pyOSError(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", pyOSError(err)
	}
	raw := make([]byte, 32)
	if err := s.Random(raw); err != nil {
		return "", err
	}
	key := base64.StdEncoding.EncodeToString(raw)
	tmp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := unlinkMissingOK(tmp); err != nil {
		return "", pyOSError(err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", pyOSError(err)
	}
	_, err = f.WriteString(key + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	return key, pyOSError(err)
}

func (s *System) wgLinkExists() (bool, error) {
	res, err := s.wgRun("", false, "ip", "link", "show", "dev", WireguardIface)
	return err == nil && res.Code == 0, err
}

// routerAddress6 is the router's IPv6 address in the tunnel,
// `<ULA>:ffff::1/64`.
func routerAddress6(ula netip.Prefix) netip.Prefix {
	a := render.TunnelNetwork6(ula).Addr().As16()
	a[15] |= 1
	return netip.PrefixFrom(netip.AddrFrom16(a), 64)
}

// syncWireguard brings the tunnel to what config.wireguard says. Only
// behind the loaded ruleset, and before the management sync, which may
// listen on its address.
func (s *System) syncWireguard(c *config.Config, dryRun bool) (string, error) {
	wg := &c.Wireguard
	withIPv6 := s.kernelHasIPv6()
	if !wg.Enabled {
		if dryRun {
			return "WireGuard off (dry-run: nothing checked)", nil
		}
		there, err := s.wgLinkExists()
		if err != nil {
			return "", err
		}
		if !there {
			return "WireGuard off", nil
		}
		if _, err := s.wgRun("", true, "ip", "link", "del", "dev", WireguardIface); err != nil {
			return "", err
		}
		if withIPv6 {
			if err := s.writeSysctls([]sysctlValue{set("ipv6/conf/all/forwarding", onOff(c.IPv6ForwardingWanted()))}); err != nil {
				return "", err
			}
		}
		return "WireGuard off: " + WireguardIface + " removed", nil
	}
	summary := WireguardIface + " " + wg.Address + ", UDP " + strconv.Itoa(wg.ListenPort) + ", " +
		strconv.Itoa(len(wg.Peers)) + " peer(s)"
	if dryRun {
		return "WireGuard: would bring up " + summary, nil
	}
	key, err := s.ensureWireguardKey()
	if err != nil {
		return "", err
	}
	// ROADMAP FND-1d: the tunnel's IPv6, whatever the router's own IPv6
	// setting: a client's IPv6 is refused rather than lost.
	var ula *netip.Prefix
	if withIPv6 {
		if ula, err = s.ensureULA(c); err != nil {
			return "", err
		}
	}
	there, err := s.wgLinkExists()
	if err != nil {
		return "", err
	}
	if !there {
		if _, err := s.wgRun("", true, "ip", "link", "add", "dev", WireguardIface, "type", "wireguard"); err != nil {
			return "", err
		}
	}
	conf, err := render.WireGuard(wg, key, ula)
	if err != nil {
		return "", err
	}
	if _, err := s.wgRun(conf, true, "wg", "syncconf", WireguardIface, "/dev/stdin"); err != nil {
		return "", err
	}
	wanted, err := netip.ParsePrefix(wg.Address)
	if err != nil {
		return "", err
	}
	if err := s.dropOtherAddresses("-4", "inet", wanted, "ip", "addr", "del"); err != nil {
		return "", err
	}
	if _, err := s.wgRun("", true, "ip", "addr", "replace", wanted.String(), "dev", WireguardIface); err != nil {
		return "", err
	}
	if ula != nil {
		if err := s.writeSysctls([]sysctlValue{set("ipv6/conf/"+WireguardIface+"/disable_ipv6", "0"),
			set("ipv6/conf/all/forwarding", "1")}); err != nil {
			return "", err
		}
		wanted6 := routerAddress6(*ula)
		if err := s.dropOtherAddresses("-6", "inet6", wanted6, "ip", "-6", "addr", "del"); err != nil {
			return "", err
		}
		// No duplicate address detection: nothing else is on a tunnel,
		// and a tentative address can't be used.
		if _, err := s.wgRun("", true, "ip", "-6", "addr", "replace", wanted6.String(), "dev", WireguardIface, "nodad"); err != nil {
			return "", err
		}
		summary += "; IPv6 " + wanted6.String() + " in the tunnel"
	}
	if _, err := s.wgRun("", true, "ip", "link", "set", "dev", WireguardIface, "up"); err != nil {
		return "", err
	}
	return "WireGuard up: " + summary, nil
}

// dropOtherAddresses takes every address of the family off wg0 that
// isn't wanted (`ip -o addr show` lists them).
func (s *System) dropOtherAddresses(family, word string, wanted netip.Prefix, del ...string) error {
	argv := []string{"ip", "-o", family, "addr", "show", "dev", WireguardIface}
	if family == "-6" {
		argv = append(argv, "scope", "global")
	}
	res, err := s.wgRun("", true, argv...)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		parts := strings.Fields(line)
		i := slices.Index(parts, word)
		if i < 0 || i+1 >= len(parts) {
			continue
		}
		current := parts[i+1]
		p, err := netip.ParsePrefix(current)
		if err != nil {
			return stepErr("%s does not appear to be an IPv4 or IPv6 interface", config.Repr(current))
		}
		if p != wanted {
			if _, err := s.wgRun("", true, append(append([]string{}, del...), current, "dev", WireguardIface)...); err != nil {
				return err
			}
		}
	}
	return nil
}

// wireguardOff is c with the tunnel off: what the step is undone to
// when no config was recorded as applied and there was no tunnel.
func wireguardOff(c *config.Config) *config.Config {
	off := *c
	off.Wireguard.Enabled = false
	return &off
}
