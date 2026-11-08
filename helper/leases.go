package helper

import (
	"errors"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// Active DHCPv4 leases from Kea's memfile lease database
// (frfw.iot.leases): an append-only CSV whose columns are looked up by
// header name, so a Kea that adds columns doesn't matter. A renewed lease
// is a new row for the same address, so the last row wins; state 0 is a
// live lease (1 declined, 2 expired-reclaimed). Kea's state directory is
// its own user's, so the IoT scanner reads it through here.

type lease struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname string   `json:"hostname"`
	Expire   *big.Int `json:"expire"`
}

type leasesReply struct {
	OK     bool    `json:"ok"`
	Leases []lease `json:"leases"`
	Count  int     `json:"count"`
}

func (s *Server) dhcpLeases() (any, error) {
	leases, err := readLeases(s.Env.KeaLeasesPath, s.Env.Now())
	if err != nil {
		return nil, err
	}
	return leasesReply{OK: true, Leases: leases, Count: len(leases)}, nil
}

// readLeases is the leases valid at now, one per address, by address. A
// missing file means no DHCP server has handed anything out yet. Any
// other read error, like a field over csv's limit, 1.x doesn't catch:
// no reply.
func readLeases(path string, now float64) ([]lease, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []lease{}, nil
	}
	if err != nil {
		return nil, errNoReply
	}
	rows, err := csvDictRows(decodeReplace(data))
	if err != nil {
		return nil, errNoReply
	}
	nowF := new(big.Float).SetFloat64(now)
	byAddress := map[string]*lease{}
	for _, row := range rows {
		address := config.PyStrip(row["address"])
		if _, err := config.IPv4Address(address); err != nil {
			continue
		}
		mac, macOK := normalizeMAC(row["hwaddr"])
		expire, ok1 := intOrZero(row["expire"])
		state, ok2 := intOrZero(row["state"])
		if !ok1 || !ok2 {
			continue
		}
		if !macOK || state.Sign() != 0 || new(big.Float).SetInt(expire).Cmp(nowF) <= 0 {
			byAddress[address] = nil // a later row can retire an earlier one
			continue
		}
		byAddress[address] = &lease{IP: address, MAC: mac, Hostname: cleanHostname(row["hostname"]), Expire: expire}
	}
	out := []lease{}
	for _, l := range byAddress {
		if l != nil {
			out = append(out, *l)
		}
	}
	slices.SortFunc(out, func(a, b lease) int { return strings.Compare(a.IP, b.IP) })
	return out, nil
}

// intOrZero is int(text or 0).
func intOrZero(text string) (*big.Int, bool) {
	if text == "" {
		return big.NewInt(0), true
	}
	return config.PyInt(text)
}

var macRE = regexp.MustCompile(`\A(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\z`)

// normalizeMAC is frfw.iot.oui.normalize_mac: "AA-BB-CC-DD-EE-FF" and
// "aa:bb:..." as "aa:bb:cc:dd:ee:ff", or false for anything else.
func normalizeMAC(text string) (string, bool) {
	mac := strings.ReplaceAll(config.PyLower(config.PyStrip(text)), "-", ":")
	return mac, macRE.MatchString(mac)
}

// maxHostname is a DNS name's longest.
const maxHostname = 253

// cleanHostname: option 12 comes straight from the client, so only
// printable ASCII is kept, at most 253 characters, to be safe to show in
// the webUI and log. Kea writes a comma as "&#x2c".
func cleanHostname(raw string) string {
	raw = strings.TrimRight(config.PyStrip(strings.ReplaceAll(raw, "&#x2c", ",")), ".")
	var b strings.Builder
	n := 0
	for _, r := range raw {
		if r > 32 && r < 127 && n < maxHostname {
			b.WriteRune(r)
			n++
		}
	}
	return b.String()
}
