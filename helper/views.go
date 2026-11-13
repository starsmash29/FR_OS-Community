package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"encoding/json/jsontext"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
)

// The commands that only read the system and show it (the webUI's
// dashboards): what the firewall dropped, the WireGuard peers, the XDP
// filter's counters, the IPv6 the provider gave, what listens, the RAM
// modules, and the IoT scan run on demand. Each answers as 1.x's does,
// reading the system the same way.

// pyReply is a reply built as 1.x builds it, a dict in its order, with
// the values it took from a program's output as they came.
func pyReply(m *config.Map) (any, error) {
	text, err := config.PyJSON(m, -1, false)
	if err != nil {
		return nil, errNoReply // json.dumps refused it: 1.x's handler dies
	}
	return jsontext.Value(text), nil
}

func okMap() *config.Map {
	m := config.NewMap()
	m.Set("ok", true)
	return m
}

// orStdout is `(proc.stderr or proc.stdout).strip()`.
func orStdout(r apply.Result) string {
	if r.Stderr != "" {
		return config.PyStrip(r.Stderr)
	}
	return config.PyStrip(r.Stdout)
}

func notFound(program string) string {
	return "[Errno 2] No such file or directory: " + config.Repr(program)
}

// --- iot_scan --------------------------------------------------------------------------

// IotScanService is the IoT scan the webUI's "Scan now" runs: as
// fr_os-sensor, never in the webUI, which must not parse LAN traffic.
const IotScanService = "fr-iot-scan.service"

func (s *Server) cmdIotScan() (any, error) {
	res, err := apply.Systemctl(s.sys().Run, "start", IotScanService, 120*time.Second)
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return message(false, "could not run "+IotScanService+": "+notFound("systemctl")), nil
	case errors.Is(err, apply.ErrTimeout):
		return message(false, "could not run "+IotScanService+": "+err.Error()), nil
	case err != nil:
		return failed(err)
	}
	if res.Code != 0 {
		return message(false, fmt.Sprintf("%s failed: %s (see journalctl -u %s)", IotScanService, orStdout(res),
			IotScanService)), nil
	}
	return message(true, IotScanService+" finished"), nil
}

// --- firewall_drops (security-lessons K6) ------------------------------------------------

// DropLogPrefix starts the kernel log line of every packet the default
// deny drops (nft.Build's `log prefix`).
const DropLogPrefix = "fr_os/drop/"

// dropsLimit is how many of the newest drops the dashboard shows.
const dropsLimit = 50

// dropFields are the kernel log's fields a drop shows, and their names.
var dropFields = map[string]string{"IN": "in", "OUT": "out", "SRC": "src", "DST": "dst", "PROTO": "proto",
	"DPT": "dport", "SPT": "sport"}

// parseDrop is frfw.firewall_log.parse: one kernel log line,
// "fr_os/drop/input: IN=eth0 OUT= ... SRC=... DPT=22", or nil.
func parseDrop(msg string) *config.Map {
	start := strings.Index(msg, DropLogPrefix)
	if start < 0 {
		return nil
	}
	head, rest, _ := strings.Cut(msg[start+len(DropLogPrefix):], ":")
	entry := config.NewMap()
	entry.Set("chain", config.PyStrip(head))
	for _, token := range config.PySplit(rest) {
		key, value, eq := strings.Cut(token, "=")
		if name, ok := dropFields[key]; eq && ok {
			entry.Set(name, value)
		}
	}
	return entry
}

type drop struct {
	entry *config.Map
	ts    float64
}

func (s *Server) cmdFirewallDrops() (any, error) {
	res, err := s.sys().Run(apply.Cmd{Argv: []string{"journalctl", "-k", "--no-pager", "-o", "json", "-n",
		fmt.Sprint(dropsLimit), "-g", DropLogPrefix}, Timeout: 30 * time.Second})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return message(false, notFound("journalctl")), nil
	case err != nil:
		return nil, errNoReply // a timeout: 1.x lets it through
	}
	var drops []drop
	for _, line := range config.PySplitlines(res.Stdout) {
		record, err := config.ParseJSONLastWins([]byte(line))
		if err != nil {
			continue
		}
		m, ok := record.(*config.Map)
		if !ok {
			return nil, errNoReply // record.get: an AttributeError 1.x lets through
		}
		msg, ok := m.Get("MESSAGE")
		if !ok {
			msg = ""
		}
		entry := parseDrop(config.Str(msg))
		if entry == nil {
			continue
		}
		ts, err := journalTime(m)
		if err != nil {
			return nil, err
		}
		if ts == nil {
			entry.Set("ts", big.NewInt(0))
			drops = append(drops, drop{entry, 0})
		} else {
			entry.Set("ts", *ts)
			drops = append(drops, drop{entry, *ts})
		}
	}
	// sort(reverse=True) keeps equal times in the order they came.
	slices.SortStableFunc(drops, func(a, b drop) int {
		switch {
		case a.ts > b.ts:
			return -1
		case a.ts < b.ts:
			return 1
		}
		return 0
	})
	list := []config.Value{}
	for i, d := range drops {
		if i == dropsLimit {
			break
		}
		list = append(list, d.entry)
	}
	m := okMap()
	m.Set("drops", list)
	return pyReply(m)
}

// journalTime is int(record.get("__REALTIME_TIMESTAMP", 0)) / 1e6, nil
// where int() refuses it (1.x shows 0 then). An infinite float, or an
// int too large for a float, is an OverflowError 1.x lets through.
func journalTime(record *config.Map) (*float64, error) {
	v, ok := record.Get("__REALTIME_TIMESTAMP")
	if !ok {
		v = big.NewInt(0)
	}
	n, err := pyInt(v)
	var bad invalidRequest
	switch {
	case errors.As(err, &bad):
		return nil, nil
	case err != nil:
		return nil, err
	}
	f, _ := new(big.Float).SetInt(n).Float64()
	if math.IsInf(f, 0) { // "int too large to convert to float"
		return nil, errNoReply
	}
	ts := f / 1e6
	return &ts, nil
}

// --- hw_ram_info -------------------------------------------------------------------------

// ramModule is one populated memory slot (frfw.hwinfo.RamModule).
type ramModule struct {
	part  string
	speed *big.Int
}

// cmdHwRAMInfo is every populated memory slot's part number and speed,
// from `dmidecode -t memory`: none where dmidecode isn't installed (the
// image doesn't need it), an error where it fails.
func (s *Server) cmdHwRAMInfo() (any, error) {
	res, err := s.sys().Run(apply.Cmd{Argv: []string{"dmidecode", "-t", "memory"}})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		res = apply.Result{}
	case err != nil:
		return failed(err)
	case res.Code != 0:
		text := config.PyStrip(res.Stderr)
		if text == "" {
			text = fmt.Sprintf("dmidecode exited with status %d", res.Code)
		}
		return message(false, text), nil
	}
	modules, err := parseDmidecodeMemory(res.Stdout)
	if err != nil {
		return failed(err)
	}
	list := []config.Value{}
	for _, mod := range modules {
		m := config.NewMap()
		m.Set("part_number", mod.part)
		m.Set("speed_mhz", mod.speed)
		list = append(list, m)
	}
	m := okMap()
	m.Set("modules", list)
	return pyReply(m)
}

// parseDmidecodeMemory is frfw.hwinfo._parse_dmidecode_memory: one
// "Memory Device" record per slot, its tab-indented "Field: value"
// lines; an empty slot ("No Module Installed") is skipped.
func parseDmidecodeMemory(output string) ([]ramModule, error) {
	var modules []ramModule
	current := map[string]string{}
	inDevice := false
	flush := func() error {
		if !inDevice {
			return nil
		}
		size := current["Size"]
		if size == "" || strings.Contains(size, "No Module Installed") {
			return nil
		}
		part := config.PyStrip(current["Part Number"])
		if part == "" {
			part = "unknown"
		}
		// "Configured Memory Speed" is the speed the module runs at, but
		// dmidecode writes "Unknown" there when it can't tell: then the
		// rated "Speed".
		raw := current["Configured Memory Speed"]
		n, err := parseSpeedMHz(raw)
		if err != nil {
			return err
		}
		if n.Sign() == 0 {
			raw = current["Speed"]
		}
		speed, err := parseSpeedMHz(raw)
		if err != nil {
			return err
		}
		modules = append(modules, ramModule{part, speed})
		return nil
	}
	for _, line := range config.PySplitlines(output) {
		if config.PyStrip(line) == "Memory Device" {
			if err := flush(); err != nil {
				return nil, err
			}
			current, inDevice = map[string]string{}, true
			continue
		}
		if line != "" && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			if err := flush(); err != nil {
				return nil, err
			}
			current, inDevice = map[string]string{}, false
			continue
		}
		if inDevice && strings.Contains(line, ":") {
			key, value, _ := strings.Cut(config.PyStrip(line), ":")
			current[config.PyStrip(key)] = config.PyStrip(value)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return modules, nil
}

// parseSpeedMHz is frfw.hwinfo._parse_speed_mhz: "2667 MT/s" is 2667,
// "Unknown" or "" 0. The digits are what str.isdigit() takes; int()
// refuses the ones that aren't decimal (a superscript).
func parseSpeedMHz(raw string) (*big.Int, error) {
	tokens := config.PySplit(raw)
	if len(tokens) == 0 {
		return big.NewInt(0), nil
	}
	var digits strings.Builder
	for _, r := range tokens[0] {
		if pyIsDigit(r) {
			digits.WriteRune(r)
		}
	}
	if digits.Len() == 0 {
		return big.NewInt(0), nil
	}
	n, ok := config.PyInt(digits.String())
	if !ok {
		return nil, invalidRequest("invalid literal for int() with base 10: " + config.Repr(digits.String()))
	}
	return n, nil
}

// --- wireguard_status (security-lessons G8) ----------------------------------------------

// WireguardIface is the VPN's interface.
const WireguardIface = "wg0"

// cmdWireguardStatus is the router's public key and each peer's last
// handshake and traffic (`wg show wg0 dump`).
func (s *Server) cmdWireguardStatus() (any, error) {
	sys := s.sys()
	key, err := routerPublicKey(sys.Paths.WireguardKey)
	if err != nil {
		return nil, err
	}
	m := okMap()
	if key == "" {
		m.Set("public_key", nil)
	} else {
		m.Set("public_key", key)
	}
	m.Set("up", false)
	peers := config.NewMap()
	m.Set("peers", peers)
	res, err := sys.Run(apply.Cmd{Argv: []string{"wg", "show", WireguardIface, "dump"}, Timeout: 30 * time.Second})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return message(false, "'wg' not found; install the wireguard-tools package"), nil
	case err != nil:
		return nil, errNoReply
	}
	if res.Code != 0 {
		return pyReply(m)
	}
	m.Set("up", true)
	lines := config.PySplitlines(res.Stdout)
	for i, line := range lines {
		if i == 0 { // the interface's own line
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue
		}
		peer := config.NewMap()
		endpoint := fields[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		peer.Set("endpoint", endpoint)
		for _, f := range []struct {
			name string
			i    int
		}{{"latest_handshake", 4}, {"rx_bytes", 5}, {"tx_bytes", 6}} {
			n, ok := intOrZero(fields[f.i])
			if !ok {
				return nil, invalidRequest("invalid literal for int() with base 10: " + config.Repr(fields[f.i]))
			}
			peer.Set(f.name, n)
		}
		peers.Set(fields[0], peer)
	}
	return pyReply(m)
}

// routerPublicKey is frfw.wireguard.router_public_key: "" before the
// first apply made a key, or when the file holds none. A file that isn't
// UTF-8 is the UnicodeDecodeError 1.x lets through.
func routerPublicKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	if !utf8.Valid(data) {
		return "", invalidRequest("'utf-8' codec can't decode " + path)
	}
	key, err := apply.PublicKeyOf(config.PyStrip(string(data)))
	if err != nil {
		return "", nil
	}
	return key, nil
}

// --- xdp_stats (ROADMAP P4-1) ------------------------------------------------------------

// XdpStatNames are the XDP SNI filter's counters, by their index in its
// stats map (bpf/xdp_sni_filter.c).
var XdpStatNames = []string{"pass_not_tls", "pass_truncated", "pass_no_sni", "pass_no_match", "drop_match",
	"drop_reordered", "drop_bad_checksum", "drop_unfollowed", "drop_fragment", "drop_ipv6_headers"}

// cmdXdpStats is the filter's packet counters: all zero while it was
// never loaded. fr-xdp reads the pinned map (where 1.x ran bpftool, whose
// dump of an array map was this same JSON).
func (s *Server) cmdXdpStats() (any, error) {
	counts := config.NewMap()
	for _, name := range XdpStatNames {
		counts.Set(name, big.NewInt(0))
	}
	m := okMap()
	m.Set("stats", counts)
	path := s.sys().Paths.XdpStats
	pinned, err := pathExists(path)
	if errors.Is(err, fs.ErrPermission) {
		return message(false, filepath.Dir(path)+" can't be read by this process (bpffs is root's)"), nil
	}
	if err != nil {
		return nil, errNoReply
	}
	if !pinned {
		return pyReply(m)
	}
	res, err := s.sys().Run(apply.Cmd{Argv: []string{apply.XdpTool, "stats", "--", path}})
	switch {
	case errors.Is(err, apply.ErrNotFound):
		return message(false, "'"+apply.XdpTool+"' not found; this FR_OS installation is incomplete"), nil
	case err != nil:
		return failed(err)
	}
	if res.Code != 0 {
		return message(false, "Dumping stats failed:\n"+res.Stderr), nil
	}
	stdout := res.Stdout
	if stdout == "" {
		stdout = "[]"
	}
	v, err := config.ParseJSONLastWins([]byte(stdout))
	if err != nil {
		return nil, invalidRequest(err.Error())
	}
	entries, err := pyIter(v)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		idx, err := pySubscript(entry, "key")
		if err != nil {
			return nil, err
		}
		value, err := pySubscript(entry, "value")
		if err != nil {
			return nil, err
		}
		i, err := statIndex(idx)
		if err != nil {
			return nil, err
		}
		if i >= 0 {
			counts.Set(XdpStatNames[i], value)
		}
	}
	return pyReply(m)
}

// statIndex is `0 <= idx < len(STAT_NAMES)` and then the index it takes
// STAT_NAMES[idx] at, -1 outside; what Python can't compare with an int,
// or use as an index, is a TypeError.
func statIndex(idx config.Value) (int, error) {
	n := len(XdpStatNames)
	switch x := idx.(type) {
	case bool:
		if x {
			return 1, nil
		}
		return 0, nil
	case *big.Int:
		if x.Sign() >= 0 && x.Cmp(big.NewInt(int64(n))) < 0 {
			return int(x.Int64()), nil
		}
		return -1, nil
	case float64:
		if x >= 0 && x < float64(n) {
			return 0, invalidRequest("list indices must be integers or slices, not float")
		}
		return -1, nil
	}
	return 0, invalidRequest(fmt.Sprintf("'<=' not supported between instances of 'int' and '%s'", pyTypeName(idx)))
}

// pySubscript is v[key] for a str key: a dict's value (a missing key is
// the KeyError 1.x lets through), a TypeError for anything else.
func pySubscript(v config.Value, key string) (config.Value, error) {
	switch x := v.(type) {
	case *config.Map:
		got, ok := x.Get(key)
		if !ok {
			return nil, keyError(key)
		}
		return got, nil
	case []config.Value:
		return nil, invalidRequest("list indices must be integers or slices, not str")
	case string:
		return nil, invalidRequest("string indices must be integers, not 'str'")
	}
	return nil, invalidRequest(fmt.Sprintf("'%s' object is not subscriptable", pyTypeName(v)))
}

// keyError is a KeyError: where 1.x catches it, its text is the key's
// repr; where it doesn't, the request gets no reply.
type keyError string

func (e keyError) Error() string { return config.Repr(string(e)) }

// pathExists is Path.exists(): false for a path that isn't there (or
// whose parent isn't a directory), an error for one it can't look at.
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	var no syscall.Errno
	if errors.As(err, &no) && (no == syscall.ENOENT || no == syscall.ENOTDIR || no == syscall.EBADF ||
		no == syscall.ELOOP) {
		return false, nil
	}
	return false, err
}
