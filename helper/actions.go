package helper

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// The commands that put a host in, or take it out of, one of the
// ruleset's runtime sets, and the two the parser daemons and the webUI
// report through: the brute-force jail (ban_ip, source_device), the AI
// IDS quarantine (quarantine_ip, conntrack_sample), IoT isolation
// (iot_sync_isolation) and the activity log (audit_append). Held to
// frfw.helper.server and the modules behind it (frfw.bruteforce,
// frfw.ids_quarantine, frfw.iot_isolation, frfw.conntrack,
// frfw.webui.audit). The decision to act is always the unprivileged
// caller's; only the enforcement is root's, and what it acts on (a
// host's MAC) is looked up here, never taken from the request.

// nftDo runs nft with args (after `--`, security-lessons F1); a refusal
// is nft's own text.
func (s *Server) nftDo(args ...string) error {
	res, err := s.Env.Nft(nftArgv(args...))
	if errors.Is(err, ErrNoNft) {
		return errNoNft
	}
	if err != nil {
		return err
	}
	if res.Code != 0 {
		if stderr := config.PyStrip(res.Stderr); stderr != "" {
			return errors.New(stderr)
		}
		return fmt.Errorf("nft exited with status %d", res.Code)
	}
	return nil
}

// addTimed adds one member with its own timeout: the kernel evicts it
// when the timeout elapses, with no userspace timer.
func (s *Server) addTimed(set, member string, seconds *big.Int) error {
	return s.nftDo("add", "element", "inet", nft.Table, set, "{", member+" timeout "+seconds.String()+"s", "}")
}

// requestString is request[key] when it is a non-empty string.
func requestString(request *config.Map, key string) (string, bool) {
	v, _ := request.Get(key)
	s, ok := v.(string)
	return s, ok && s != ""
}

// requestDuration is request.get(key, fallback) when it is an int and
// not a bool.
func requestDuration(request *config.Map, key string, fallback int64) (*big.Int, bool) {
	v, present := request.Get(key)
	if !present {
		return big.NewInt(fallback), true
	}
	n, ok := v.(*big.Int)
	return n, ok
}

// --- the brute-force jail (frfw.bruteforce) ----------------------------------------

// jailKey is what one source address is, for counting and jailing: the
// address itself, an IPv4-mapped IPv6 one as its IPv4.
func jailKey(ip string) (string, error) {
	a, err := config.ParsePyIP(ip)
	if err != nil {
		return "", err
	}
	if a.HasScope() {
		// Any text after a `%` parses as a scope, and str() gives it
		// back, into the nft command.
		return "", errors.New("no scope (%) allowed")
	}
	if m, ok := a.IPv4Mapped(); ok {
		return m.String(), nil
	}
	return a.String(), nil
}

// deviceKey is the MAC of the LAN host behind the IPv6 source ip, or ""
// (an IPv4 source, or a host not on a LAN link): whatever address the
// host picks, its MAC stays, so it counts and is jailed as one (H3).
func (s *Server) deviceKey(ip string, lanDevices map[string]bool) (string, error) {
	key, err := jailKey(ip)
	if err != nil {
		return "", err
	}
	if !strings.Contains(key, ":") {
		return "", nil
	}
	return s.lanNeighbourMAC(key, lanDevices)
}

func (s *Server) cmdBanIP(request *config.Map) (any, error) {
	ip, ok := requestString(request, "ip")
	if !ok {
		return message(false, "'ip' is required"), nil
	}
	seconds, ok := requestDuration(request, "duration_seconds", 3600)
	if !ok {
		return message(false, "'duration_seconds' must be an integer"), nil
	}
	devices := s.lanDevices()
	key, err := jailKey(ip)
	if err != nil {
		return message(false, fmt.Sprintf("invalid IP address %s: %s", config.Repr(ip), err)), nil
	}
	if seconds.Sign() <= 0 {
		return message(false, "duration_seconds must be positive, got "+seconds.String()), nil
	}
	mac, err := s.deviceKey(key, devices)
	if err != nil {
		return failed(err)
	}
	set := nft.BruteforceJailSet
	switch {
	case mac != "":
		set, key = nft.BruteforceJailMacSet, mac
	case strings.Contains(key, ":"):
		set = nft.BruteforceJail6Set
	}
	if err := s.addTimed(set, key, seconds); err != nil {
		return failed(err)
	}
	held := ""
	if mac != "" {
		held = " (by MAC " + mac + ")"
	}
	return message(true, fmt.Sprintf("%s jailed for %ss%s", ip, seconds, held)), nil
}

type deviceReply struct {
	OK     bool    `json:"ok"`
	Device *string `json:"device"`
}

// cmdSourceDevice is the MAC of the LAN host behind an IPv6 source, so
// the webUI counts its failed sign-ins per host, whichever of its
// addresses it uses (FND-1d, H3). The webUI's sandbox has no netlink to
// read the neighbour table itself.
func (s *Server) cmdSourceDevice(request *config.Map) (any, error) {
	ip, ok := requestString(request, "ip")
	if !ok {
		return message(false, "'ip' is required"), nil
	}
	if _, err := jailKey(ip); err != nil {
		return message(false, fmt.Sprintf("invalid IP address %s: %s", config.Repr(ip), err)), nil
	}
	mac, err := s.deviceKey(ip, s.lanDevices())
	if err != nil {
		return failed(err)
	}
	r := deviceReply{OK: true}
	if mac != "" {
		r.Device = &mac
	}
	return r, nil
}

// --- the AI IDS quarantine (frfw.ids_quarantine) ------------------------------------

// maxQuarantineSeconds is the longest quarantine one request may ask
// for: the command is open to the parser daemons, so a bug in one can't
// lock the router out of itself for years (review C-04).
const maxQuarantineSeconds = 7 * 24 * 3600

// checkTarget is ip as an address that may be quarantined.
func checkTarget(ip string, own map[string]bool) (config.PyAddr, error) {
	var a config.PyAddr
	var err error
	family := "IPv4"
	if strings.Contains(ip, ":") {
		family = "IPv6"
		a, err = config.ParsePyIPv6(ip)
	} else {
		a, err = config.ParsePyIPv4(ip)
	}
	if err != nil {
		return a, fmt.Errorf("invalid %s address %s: %s", family, config.Repr(ip), err)
	}
	if a.HasScope() {
		return a, fmt.Errorf("invalid IPv6 address %s: no scope (%%) allowed", config.Repr(ip))
	}
	_, mapped := a.IPv4Mapped()
	if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocal() || a.IsReserved() ||
		(a.Version() == 4 && a.String() == "255.255.255.255") || mapped {
		return a, fmt.Errorf("refusing to quarantine %s: not a host address", ip)
	}
	if own[a.String()] {
		return a, fmt.Errorf("refusing to quarantine %s: it is one of the router's own addresses", ip)
	}
	return a, nil
}

func (s *Server) cmdQuarantineIP(request *config.Map) (any, error) {
	ip, ok := requestString(request, "ip")
	if !ok {
		return message(false, "'ip' is required"), nil
	}
	seconds, ok := requestDuration(request, "duration_seconds", 7200)
	if !ok {
		return message(false, "'duration_seconds' must be an integer"), nil
	}
	own, devices := s.routerAddresses(), s.lanDevices()
	mac, err := s.quarantine(ip, seconds, own, devices)
	if err != nil {
		return failed(err)
	}
	held := ""
	switch {
	case strings.Contains(ip, ":"):
		// FND-1d: an IPv6 host is held by its MAC, with its IPv4.
		held = " by its MAC " + mac + ", with its IPv4 addresses on the LAN"
	case mac != "":
		held = " (and its IPv6, by MAC " + mac + ")"
	}
	return message(true, fmt.Sprintf("%s quarantined for %ss%s", ip, seconds, held)), nil
}

// quarantine adds ip to the quarantine for seconds, and the MAC the
// neighbour table holds for it on the LAN to the MAC set (FND-1b). An
// IPv6 ip is held by its MAC, and the IPv4 addresses that MAC has on the
// LAN; without a MAC it is refused: an IPv6 host can't be held by one
// address it picked itself (FND-1d).
func (s *Server) quarantine(ip string, seconds *big.Int, own, devices map[string]bool) (string, error) {
	a, err := checkTarget(ip, own)
	if err != nil {
		return "", err
	}
	if seconds.Sign() <= 0 {
		return "", errors.New("duration_seconds must be positive, got " + seconds.String())
	}
	if seconds.Cmp(big.NewInt(maxQuarantineSeconds)) > 0 {
		return "", fmt.Errorf("duration_seconds may be at most %d (7 days), got %s", maxQuarantineSeconds, seconds)
	}
	if a.Version() == 6 {
		mac, err := s.lanNeighbourMAC(a.String(), devices)
		if err != nil {
			return "", err
		}
		if mac == "" {
			return "", fmt.Errorf("refusing to quarantine %s: the router has no MAC for it on a LAN link, and an IPv6 "+
				"host can't be held by one address it picked itself", a)
		}
		if err := s.addTimed(nft.IDSQuarantineMacSet, mac, seconds); err != nil {
			return "", err
		}
		ipv4s, err := s.lanIPv4Addresses(mac, devices)
		if err != nil {
			return "", err
		}
		for _, v4 := range ipv4s {
			if _, err := checkTarget(v4, own); err != nil {
				continue
			}
			if err := s.addTimed(nft.IDSQuarantineSet, v4, seconds); err != nil {
				return "", err
			}
		}
		return mac, nil
	}
	if err := s.addTimed(nft.IDSQuarantineSet, ip, seconds); err != nil {
		return "", err
	}
	mac, err := s.lanNeighbourMAC(a.String(), devices)
	if err != nil {
		return "", err
	}
	if mac != "" {
		if err := s.addTimed(nft.IDSQuarantineMacSet, mac, seconds); err != nil {
			return "", err
		}
	}
	return mac, nil
}

// --- the conntrack sample (frfw.conntrack) -------------------------------------------

type flow struct {
	Proto  string   `json:"proto"`
	Src    string   `json:"src"`
	Sport  *big.Int `json:"sport"`
	Dst    string   `json:"dst"`
	Dport  *big.Int `json:"dport"`
	SrcMAC string   `json:"src_mac,omitempty"`
}

type flowsReply struct {
	OK    bool   `json:"ok"`
	Flows []flow `json:"flows"`
}

// readConntrack is every tracked TCP/UDP flow's original-direction
// tuple: the first src=, dst=, sport= and dport= of a line (a TCP line
// has a state token a UDP one doesn't, so positions shift; the original
// direction always comes first). No table is no flows.
func readConntrack(path string) ([]flow, error) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %s", path, osText(err))
	}
	if !utf8.Valid(data) {
		return nil, invalidRequest("'utf-8' codec can't decode " + path)
	}
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	var out []flow
	for _, line := range config.PySplitlines(text) {
		parts := config.PySplit(line)
		if len(parts) < 5 || (parts[2] != "tcp" && parts[2] != "udp") {
			continue
		}
		f := flow{Proto: parts[2]}
		var src, dst bool
		for _, token := range parts {
			switch {
			case !src && strings.HasPrefix(token, "src="):
				f.Src, src = token[4:], true
			case !dst && strings.HasPrefix(token, "dst="):
				f.Dst, dst = token[4:], true
			case f.Sport == nil && strings.HasPrefix(token, "sport="):
				f.Sport = pyIntOrNil(token[6:])
			case f.Dport == nil && strings.HasPrefix(token, "dport="):
				f.Dport = pyIntOrNil(token[6:])
			}
			if src && dst && f.Sport != nil && f.Dport != nil {
				break
			}
		}
		if src && dst && f.Sport != nil && f.Dport != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

func pyIntOrNil(s string) *big.Int {
	n, ok := config.PyInt(s)
	if !ok {
		return nil
	}
	return n
}

// cmdConntrackSample is the conntrack flows, an IPv6 source labelled
// with its MAC where the neighbour table has one for it on a LAN link
// (FND-1d): the AI IDS scores an IPv6 host by its MAC, which its address
// changes don't change, and reading the table needs root it doesn't
// have. A source without one gets no label.
func (s *Server) cmdConntrackSample() (any, error) {
	flows, err := readConntrack(s.sys().Paths.Conntrack)
	if err != nil {
		return failed(err)
	}
	if len(flows) > ConntrackSampleMaxFlows {
		flows = flows[:ConntrackSampleMaxFlows]
	}
	macs := map[string]string{}
	for _, f := range flows {
		if strings.Contains(f.Src, ":") {
			if macs, err = s.lanNeighbours(s.lanDevices(), "-6"); err != nil {
				return failed(err)
			}
			break
		}
	}
	out := flowsReply{OK: true, Flows: []flow{}}
	for _, f := range flows {
		if strings.Contains(f.Src, ":") {
			if a, err := config.ParsePyIP(f.Src); err == nil {
				f.SrcMAC = macs[a.String()]
			}
		}
		out.Flows = append(out.Flows, f)
	}
	return out, nil
}

// osText is an OSError's text as Python writes it.
func osText(err error) string { return apply.OSErrorText(err) }

// --- IoT isolation (frfw.iot_isolation) ----------------------------------------------

// maxIsolated bounds one sync: far above any real network, low enough
// that a bogus request can't build a huge nft script.
const maxIsolated = 4096

var isolationMACRE = regexp.MustCompile(`\A([0-9a-f]{2}:){5}[0-9a-f]{2}\z`)

// normalizeMACs is the MACs lower-cased, de-duplicated and checked; the
// first bad one is refused, so a caller's bug shows.
func normalizeMACs(macs []config.Value) ([]string, error) {
	if len(macs) > maxIsolated {
		return nil, fmt.Errorf("too many MACs (%d > %d)", len(macs), maxIsolated)
	}
	out := []string{}
	for _, v := range macs {
		mac, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("invalid MAC address %s", config.Repr(v))
		}
		mac = config.PyLower(mac)
		if !isolationMACRE.MatchString(mac) {
			return nil, fmt.Errorf("invalid MAC address %s", config.Repr(mac))
		}
		if !contains(out, mac) {
			out = append(out, mac)
		}
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

type isolationReply struct {
	OK             bool     `json:"ok"`
	Message        string   `json:"message"`
	Isolated       []string `json:"isolated"`
	Count          int      `json:"count"`
	SkippedTrusted []string `json:"skipped_trusted"`
}

// cmdIotSyncIsolation makes the isolation set exactly the MACs asked
// for, but the config's trusted ones, in one nft transaction: either the
// whole new membership lands or nothing changes.
func (s *Server) cmdIotSyncIsolation(request *config.Map) (any, error) {
	v, _ := request.Get("macs")
	list, ok := v.([]config.Value)
	if !ok {
		return message(false, "'macs' must be a list"), nil
	}
	macs, err := normalizeMACs(list)
	if err != nil {
		return failed(err)
	}
	c, _, err := apply.ReadConfig(s.sys().Paths.Config)
	if err != nil {
		return commandError(err)
	}
	if !c.Iot.Enabled {
		return message(false, "IoT isolation is disabled in the current config"), nil
	}
	trusted := map[string]bool{}
	for _, m := range c.Iot.TrustedMacs {
		trusted[m] = true
	}
	skipped, isolate := []string{}, []string{}
	for _, m := range macs {
		if trusted[m] {
			skipped = append(skipped, m)
		} else {
			isolate = append(isolate, m)
		}
	}
	script := "flush set inet " + nft.Table + " " + nft.IotIsolatedSet + "\n"
	if len(isolate) > 0 {
		script += "add element inet " + nft.Table + " " + nft.IotIsolatedSet + " { " + strings.Join(isolate, ", ") + " }\n"
	}
	r, err := s.sys().Run(apply.Cmd{Argv: []string{"nft", "-f", "-"}, Stdin: script})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return failed(errNoNft)
	case err != nil:
		return failed(err)
	case r.Code != 0:
		if stderr := config.PyStrip(r.Stderr); stderr != "" {
			return failed(errors.New(stderr))
		}
		return failed(fmt.Errorf("nft exited with status %d", r.Code))
	}
	return isolationReply{OK: true, Message: fmt.Sprintf("%d device(s) isolated", len(isolate)), Isolated: isolate,
		Count: len(isolate), SkippedTrusted: skipped}, nil
}

// --- the activity log (frfw.webui.audit) ---------------------------------------------

// What an audit entry from the webUI may carry (security-lessons G9, E6).
const (
	auditMaxFields = 20
	auditMaxText   = 500
)

type okReply struct {
	OK bool `json:"ok"`
}

// cmdAuditAppend appends the webUI's entry to the root-owned log. The
// webUI can only add: it can't write the file, so it can't rewrite or
// remove what is already there. The time and the origin are set here.
func (s *Server) cmdAuditAppend(request *config.Map) (any, error) {
	v, _ := request.Get("entry")
	entry, ok := v.(*config.Map)
	if !ok || entry.Len() > auditMaxFields {
		return message(false, "'entry' must be a small mapping"), nil
	}
	clean := config.NewMap()
	for i, k := range entry.Keys() {
		key, ok := k.(string)
		if !ok || !pyIsIdentifier(key) || utf8.RuneCountInString(key) > 40 || key == "ts" || key == "via" {
			return message(false, "invalid audit field "+config.Repr(k)), nil
		}
		switch value := entry.Values()[i].(type) {
		case string:
			r := []rune(value)
			if len(r) > auditMaxText {
				r = r[:auditMaxText]
			}
			clean.Set(key, string(r))
		case nil, bool, *big.Int, float64:
			clean.Set(key, value)
		default:
			return message(false, "invalid value for audit field "+config.Repr(key)), nil
		}
	}
	clean.Set("via", "webui")
	sys := s.sys()
	if err := sys.PrepareAudit(); err != nil {
		return nil, errNoReply
	}
	sys.AppendAudit(clean)
	return okReply{OK: true}, nil
}

// pyIsIdentifier is str.isidentifier: an XID_Start character or "_",
// then XID_Continue ones. XID is Unicode's ID with the few characters
// NFKC would turn into something else left out.
func pyIsIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		id := r == '_' || unicode.IsLetter(r) || unicode.Is(unicode.Nl, r) || unicode.Is(unicode.Other_ID_Start, r)
		if unicode.Is(unicode.Pattern_Syntax, r) || unicode.Is(unicode.Pattern_White_Space, r) {
			id = false
		}
		if i == 0 {
			if !id || notXIDStart[r] || notXIDContinue[r] {
				return false
			}
			continue
		}
		cont := id || unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc, unicode.Other_ID_Continue)
		if !cont || notXIDContinue[r] {
			return false
		}
	}
	return true
}

// notXIDContinue are in ID_Continue but not XID_Continue; notXIDStart
// are, besides those, in ID_Start but not XID_Start (UAX #31).
var notXIDContinue = runeSet(0x037a, 0x309b, 0x309c, 0xfc5e, 0xfc5f, 0xfc60, 0xfc61, 0xfc62, 0xfc63, 0xfdfa,
	0xfdfb, 0xfe70, 0xfe72, 0xfe74, 0xfe76, 0xfe78, 0xfe7a, 0xfe7c, 0xfe7e)

var notXIDStart = runeSet(0x0e33, 0x0eb3, 0xff9e, 0xff9f)

func runeSet(rs ...rune) map[rune]bool {
	m := map[rune]bool{}
	for _, r := range rs {
		m[r] = true
	}
	return m
}
