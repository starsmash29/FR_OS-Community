package render

import (
	"fmt"
	"math/big"
	"net/netip"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// WireGuard is the tunnel's `wg syncconf` text
// (frfw.wireguard.render_conf): the router's key and port, and each peer
// with its addresses: its IPv4 one and, once the ULA prefix is known,
// its IPv6 one (FND-1d), since WireGuard takes from a key only the
// addresses listed for it. The private key is only copied: the apply
// hands this to wg on standard input, never in a file or an argv.
func WireGuard(wg *config.WireguardConfig, privateKey string, ula *netip.Prefix) (string, error) {
	lines := []string{"[Interface]", "PrivateKey = " + privateKey, "ListenPort = " + strconv.Itoa(wg.ListenPort)}
	for _, p := range wg.Peers {
		allowed := p.Address
		if ula != nil {
			a6, err := PeerAddress6(wg, p.Address, *ula)
			if err != nil {
				return "", err
			}
			allowed += ", " + a6
		}
		lines = append(lines, "", "# "+p.Name, "[Peer]", "PublicKey = "+p.PublicKey, "AllowedIPs = "+allowed)
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// PeerAddress6 is a client's IPv6 address in the tunnel,
// `<ULA>:ffff::<n>/128` (frfw.wireguard.peer_address6): the same host
// number n as its IPv4 address there, so it needs no setting of its own.
func PeerAddress6(wg *config.WireguardConfig, address string, ula netip.Prefix) (string, error) {
	tunnel, err := netip.ParsePrefix(wg.Address)
	if err != nil || !tunnel.Addr().Is4() {
		return "", fmt.Errorf("wireguard.address %q", wg.Address)
	}
	peer, err := netip.ParsePrefix(address)
	if err != nil || !peer.Addr().Is4() {
		return "", fmt.Errorf("wireguard peer address %q", address)
	}
	host := new(big.Int).Sub(addrInt(peer.Addr()), addrInt(tunnel.Masked().Addr()))
	n := host.Add(host, addrInt(TunnelNetwork6(ula).Addr()))
	if n.Sign() < 0 || n.BitLen() > 128 {
		return "", fmt.Errorf("wireguard peer address %q: out of the tunnel's IPv6 range", address)
	}
	var b [16]byte
	n.FillBytes(b[:])
	return netip.AddrFrom16(b).String() + "/128", nil
}

func addrInt(a netip.Addr) *big.Int {
	b := a.AsSlice()
	return new(big.Int).SetBytes(b)
}
