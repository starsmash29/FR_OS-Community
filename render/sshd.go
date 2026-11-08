package render

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

const sshdHead = `# Managed by FR_OS (frfw.management) -- regenerated on every ` + "`apply`" + `, do
# not edit by hand. Where sshd listens -- the management zones only
# (management.* in /etc/fr_os/config.yaml) -- and how it authenticates:
# keys only, members of the SSH group only (security-lessons F2/F3).`

// sshdHardening (security-lessons F3): keys only, no root, only members
// of the SSH group, few tries, a short grace time. sshd keeps the first
// value it reads and this drop-in sorts before the distribution's, so
// these win.
var sshdHardening = []string{
	"PermitRootLogin no",
	"PasswordAuthentication no",
	"KbdInteractiveAuthentication no",
	"PermitEmptyPasswords no",
	"PubkeyAuthentication yes",
	"AuthenticationMethods publickey",
	"AllowGroups " + SSHGroup,
	"MaxAuthTries 3",
	"LoginGraceTime 30",
	"X11Forwarding no",
}

// Security-lessons H3: only strong key exchange, ciphers and MACs, all
// known to Debian bookworm's OpenSSH 9.2.
var (
	sshdKex     = []string{"sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org", "diffie-hellman-group18-sha512", "diffie-hellman-group16-sha512"}
	sshdCiphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"}
	sshdMACs    = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"}
)

// The webUI and sshd listen on these besides the management addresses.
const (
	Loopback = "127.0.0.1"
	Any      = "0.0.0.0"
)

// SSHD is sshd's management drop-in (frfw.management.sshd_dropin): where
// it listens and how it authenticates. With PQC on, the PQC drop-in owns
// KexAlgorithms (sshd keeps the first value it reads). ula is the
// router's ULA prefix (ULAPrefix).
func SSHD(c *config.Config, ula *netip.Prefix) string {
	lines := []string{sshdHead}
	for _, a := range ListenAddresses(c, ula) {
		lines = append(lines, "ListenAddress "+a)
	}
	lines = append(lines, sshdHardening...)
	if !c.Pqc.Enabled {
		lines = append(lines, "KexAlgorithms "+strings.Join(sshdKex, ","))
	}
	lines = append(lines, "Ciphers "+strings.Join(sshdCiphers, ","), "MACs "+strings.Join(sshdMACs, ","))
	return strings.Join(lines, "\n") + "\n"
}

// ListenAddresses are where the webUI and sshd listen
// (frfw.management.listen_addresses): loopback and management.addresses
// (ROADMAP SEC-27), or everything with allow_wan; for a config from
// before SEC-27, every management interface's static address but not the
// VPN's (security-lessons K5). Then, with management.ipv6, the router's
// ULA address on each management LAN device (FND-1c).
func ListenAddresses(c *config.Config, ula *netip.Prefix) []string {
	var stable []string
	if c.Management.IPv6 && c.IPv6.Enabled {
		zones := c.ManagementZones()
		for _, a := range ULAAddresses(c, ula) {
			if zones[a.Zone] {
				stable = append(stable, strings.TrimSuffix(a.Address, "/64"))
			}
		}
	}
	switch {
	case c.Management.AllowWan:
		return append([]string{Any}, stable...)
	case len(c.Management.Addresses) > 0:
		return append(append([]string{Loopback}, c.Management.Addresses...), stable...)
	}
	out := []string{Loopback}
	for _, a := range interfaceAddresses(c) {
		out = append(out, a)
	}
	return append(out, stable...)
}

// interfaceAddresses are the static addresses of the management zones'
// interfaces, by interface name, each once.
func interfaceAddresses(c *config.Config) []string {
	zones := c.ManagementZones()
	ifaces := c.Interfaces.Values()
	slices.SortStableFunc(ifaces, func(a, b config.Interface) int { return strings.Compare(a.Name, b.Name) })
	var found []string
	for _, i := range ifaces {
		if !zones[i.Zone] || i.Address == "" {
			continue
		}
		p, err := netip.ParsePrefix(i.Address)
		if err != nil {
			continue
		}
		if ip := p.Addr().String(); !slices.Contains(found, ip) {
			found = append(found, ip)
		}
	}
	return found
}
