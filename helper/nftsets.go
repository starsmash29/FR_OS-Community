package helper

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os/exec"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// NftResult is what one nft run gave.
type NftResult struct {
	Stdout, Stderr string
	Code           int
}

// NftRunner runs nft with argv (argv[0] is "nft"). ErrNoNft says the
// binary isn't there.
type NftRunner func(argv []string) (NftResult, error)

// ErrNoNft is an nft that isn't installed.
var ErrNoNft = errors.New("helper: nft not found")

// maxNftOutput bounds what the helper reads from nft: far more than the
// largest set listing (65536 members of about 100 bytes each).
const maxNftOutput = 64 << 20

// RunNft runs the real nft.
func RunNft(argv []string) (NftResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var stdout, stderr limitedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		return NftResult{}, ErrNoNft
	}
	if stdout.over || stderr.over {
		return NftResult{}, fmt.Errorf("nft wrote more than %d bytes", maxNftOutput)
	}
	res := NftResult{Stdout: stdout.String(), Stderr: stderr.String()}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		res.Code = exit.ExitCode()
	case err != nil:
		return NftResult{}, err
	}
	return res, nil
}

type limitedBuffer struct {
	bytes.Buffer
	over bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxNftOutput {
		b.over = true
		return 0, errors.New("too much output")
	}
	return b.Buffer.Write(p)
}

// nftArgv is frfw.validate.nft_argv: `--` between the leading options
// and everything else, so no later value reads as an option (security
// lessons F1).
func nftArgv(args ...string) []string {
	var options []string
	rest := args
	for len(rest) > 0 && strings.HasPrefix(rest[0], "-") && rest[0] != "-" {
		options = append(options, rest[0])
		rest = rest[1:]
		if options[len(options)-1] == "-f" && len(rest) > 0 {
			options = append(options, rest[0])
			rest = rest[1:]
		}
	}
	argv := append([]string{"nft"}, options...)
	if len(rest) > 0 {
		argv = append(append(argv, "--"), rest...)
	}
	return argv
}

// setEntries is every "elem" entry of `nft -j list set inet fr_os
// <name>`, nil for a set (or table) that isn't loaded: nobody is in it.
// Any other failure is an error the admin sees, not an empty list.
func (s *Server) setEntries(name string) ([]config.Value, error) {
	res, err := s.Env.Nft(nftArgv("-j", "list", "set", "inet", nft.Table, name))
	if errors.Is(err, ErrNoNft) {
		return nil, errors.New("'nft' binary not found; install the nftables package")
	}
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		stderr := config.PyStrip(res.Stderr)
		if strings.Contains(stderr, "No such file or directory") || strings.Contains(stderr, "does not exist") {
			return nil, nil
		}
		if stderr == "" {
			stderr = fmt.Sprintf("nft exited with status %d", res.Code)
		}
		return nil, errors.New(stderr)
	}
	stdout := res.Stdout
	if stdout == "" {
		stdout = "{}"
	}
	data, err := config.ParseJSONLastWins([]byte(stdout))
	if err != nil {
		return nil, errors.New("could not parse nft JSON output: " + err.Error())
	}
	objs, err := pyGet(data, "nftables")
	if err != nil {
		return nil, err
	}
	if objs == nil {
		if m := data.(*config.Map); !m.Has("nftables") {
			objs = []config.Value{}
		}
	}
	items, err := pyIter(objs)
	if err != nil {
		return nil, err
	}
	var out []config.Value
	for _, obj := range items {
		set, err := pyGet(obj, "set")
		if err != nil {
			return nil, err
		}
		if !config.Truthy(set) {
			continue
		}
		elems, err := pyGet(set, "elem")
		if err != nil {
			return nil, err
		}
		if elems == nil && !set.(*config.Map).Has("elem") {
			continue
		}
		entries, err := pyIter(elems)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}

// elemOf is entry["elem"] when both are mappings, else nil.
func elemOf(entry config.Value) *config.Map {
	m, ok := entry.(*config.Map)
	if !ok {
		return nil
	}
	e, _ := m.Get("elem")
	elem, _ := e.(*config.Map)
	return elem
}

// expiresOf is int(elem.get("expires") or 0): the seconds left.
func expiresOf(elem *config.Map) (*big.Int, error) {
	v, _ := elem.Get("expires")
	if !config.Truthy(v) {
		return big.NewInt(0), nil
	}
	return pyInt(v)
}

type timedMember struct {
	member string
	left   *big.Int
}

// timedMembers is frfw.bruteforce's and frfw.ids_quarantine's
// _list_set_elements: (member, seconds left) for each element whose value
// is a string, or with prefixes, also an interval set's prefix as
// "<addr>/<len>".
func (s *Server) timedMembers(name string, prefixes bool) ([]timedMember, error) {
	entries, err := s.setEntries(name)
	if err != nil {
		return nil, err
	}
	var out []timedMember
	for _, entry := range entries {
		elem := elemOf(entry)
		if elem == nil {
			continue
		}
		val, _ := elem.Get("val")
		member, ok := val.(string)
		if !ok && prefixes {
			member, ok = prefixText(val)
		}
		if !ok {
			continue
		}
		left, err := expiresOf(elem)
		if err != nil {
			return nil, err
		}
		out = append(out, timedMember{member, left})
	}
	return out, nil
}

// prefixText is {"prefix": {"addr": "2001:db8::", "len": 64}} as
// "2001:db8::/64" (frfw.bruteforce._element_value).
func prefixText(val config.Value) (string, bool) {
	m, ok := val.(*config.Map)
	if !ok {
		return "", false
	}
	p, _ := m.Get("prefix")
	prefix, ok := p.(*config.Map)
	if !ok {
		return "", false
	}
	a, _ := prefix.Get("addr")
	l, _ := prefix.Get("len")
	addr, ok := a.(string)
	if !ok {
		return "", false
	}
	switch l.(type) {
	case *big.Int, bool: // isinstance(len, int): a bool is an int
		return addr + "/" + config.Str(l), true
	}
	return "", false
}

type ipLeft struct {
	IP        string   `json:"ip"`
	ExpiresIn *big.Int `json:"expires_in"`
}

type macLeft struct {
	MAC       string   `json:"mac"`
	ExpiresIn *big.Int `json:"expires_in"`
}

type bruteforceReply struct {
	OK     bool     `json:"ok"`
	Banned []ipLeft `json:"banned"`
	Count  int      `json:"count"`
}

// bruteforceStatus is every jailed source: an address, a jailed host's
// MAC, or a /64 banned before FND-1d as "<network>/64".
func (s *Server) bruteforceStatus() (any, error) {
	banned := []ipLeft{}
	for _, set := range []string{nft.BruteforceJailSet, nft.BruteforceJail6Set, nft.BruteforceJailMacSet} {
		members, err := s.timedMembers(set, true)
		if err != nil {
			return failed(err)
		}
		for _, m := range members {
			banned = append(banned, ipLeft{m.member, m.left})
		}
	}
	return bruteforceReply{OK: true, Banned: banned, Count: len(banned)}, nil
}

type idsReply struct {
	OK          bool      `json:"ok"`
	Quarantined []ipLeft  `json:"quarantined"`
	Count       int       `json:"count"`
	MACs        []macLeft `json:"macs"`
}

// idsQuarantineStatus is the quarantined addresses and, apart, the hosts
// held by their MAC: an IPv6 host is in no IPv4 list. The count stays the
// addresses' (the dashboard's and /metrics').
func (s *Server) idsQuarantineStatus() (any, error) {
	ips, err := s.timedMembers(nft.IDSQuarantineSet, false)
	if err != nil {
		return failed(err)
	}
	macs, err := s.timedMembers(nft.IDSQuarantineMacSet, false)
	if err != nil {
		return failed(err)
	}
	r := idsReply{OK: true, Quarantined: []ipLeft{}, MACs: []macLeft{}}
	for _, m := range ips {
		r.Quarantined = append(r.Quarantined, ipLeft{m.member, m.left})
	}
	for _, m := range macs {
		r.MACs = append(r.MACs, macLeft{m.member, m.left})
	}
	r.Count = len(r.Quarantined)
	return r, nil
}

type ztnaSession struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac"`
	ExpiresIn *big.Int `json:"expires_in"`
}

type ztnaReply struct {
	OK       bool          `json:"ok"`
	Sessions []ztnaSession `json:"sessions"`
	Count    int           `json:"count"`
}

// ztnaSessionsStatus is every authorized ZTNA client, mac "" for a
// WireGuard client (frfw.ztna.list_authorized). Only the shape a set is
// meant to hold counts: address . MAC pairs in the LAN sets, addresses in
// the tunnel sets.
func (s *Server) ztnaSessionsStatus() (any, error) {
	sessions, err := s.ztnaSessions()
	if err != nil {
		return failed(err)
	}
	return ztnaReply{OK: true, Sessions: sessions, Count: len(sessions)}, nil
}

// ztnaSessions is frfw.ztna._list_elements.
func (s *Server) ztnaSessions() ([]ztnaSession, error) {
	sets := []struct {
		name   string
		paired bool
	}{{nft.ZtnaSet, true}, {nft.ZtnaTunnelSet, false}, {nft.Ztna6Set, true}, {nft.ZtnaTunnel6Set, false}}
	sessions := []ztnaSession{}
	for _, set := range sets {
		entries, err := s.setEntries(set.name)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			elem := elemOf(entry)
			if elem == nil {
				continue
			}
			ip, mac, ok := ztnaMember(elem, set.paired)
			if !ok {
				continue
			}
			left, err := expiresOf(elem)
			if err != nil {
				return nil, err
			}
			sessions = append(sessions, ztnaSession{ip, config.PyLower(mac), left})
		}
	}
	return sessions, nil
}

func ztnaMember(elem *config.Map, paired bool) (ip, mac string, ok bool) {
	val, _ := elem.Get("val")
	if !paired {
		ip, ok = val.(string)
		return ip, "", ok
	}
	m, isMap := val.(*config.Map)
	if !isMap {
		return "", "", false
	}
	c, _ := m.Get("concat")
	concat, isList := c.([]config.Value)
	if !isList || len(concat) != 2 {
		return "", "", false
	}
	mac, ok = concat[1].(string)
	if !ok || mac == "" {
		return "", "", false
	}
	ip, ok = concat[0].(string)
	return ip, mac, ok
}

type iotReply struct {
	OK       bool     `json:"ok"`
	Isolated []string `json:"isolated"`
	Count    int      `json:"count"`
}

// iotIsolationStatus is the isolated devices' MACs. A set without
// `flags timeout` lists plain strings; the dict form counts too.
func (s *Server) iotIsolationStatus() (any, error) {
	entries, err := s.setEntries(nft.IotIsolatedSet)
	if err != nil {
		return failed(err)
	}
	isolated := []string{}
	for _, entry := range entries {
		if m, ok := entry.(*config.Map); ok {
			e, _ := m.Get("elem")
			if !config.Truthy(e) {
				entry = nil
			} else if entry, err = pyGet(e, "val"); err != nil {
				return failed(err)
			}
		}
		if mac, ok := entry.(string); ok {
			isolated = append(isolated, config.PyLower(mac))
		}
	}
	return iotReply{OK: true, Isolated: isolated, Count: len(isolated)}, nil
}

// failed is 1.x's answer to a command that raised: the error's text,
// unless it is one 1.x lets through to the request handler.
func failed(err error) (any, error) {
	var bad invalidRequest
	if errors.As(err, &bad) || errors.Is(err, errNoReply) {
		return nil, err
	}
	return message(false, err.Error()), nil
}
