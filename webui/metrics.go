package webui

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/appid"
	"github.com/starsmash29/fr_os-community/config"
)

// GET /metrics: the Prometheus text exposition format (1.x's
// frfw.metrics and routes/metrics.py). No sign-in: a scrape carries a
// bearer token, whose SHA-256 (metrics.token_sha256) is what turns the
// endpoint on; without one it answers 404, as a feature that is off
// (ROADMAP SEC-3, review v0.2.0 R11, security-lessons I1, K7). Neither
// an unconfigured nor an unauthenticated request does any work: the
// answer comes before anything is gathered.
//
// Every family is gathered on its own and one that fails is left out,
// so a missing /proc file or a helper hiccup never turns the answer
// into a 500. A value that isn't a number does fail the answer, as in
// 1.x, where the rendering is outside that boundary.

const (
	metricsOffText    = "metrics are off: generate a token (System screen, or firewall-cli metrics-token --generate)\n"
	metricsDeniedText = "bearer token required\n"
	metricsType       = "text/plain; version=0.0.4; charset=utf-8"
	// metricsCacheSeconds is CACHE_SECONDS: an authenticated scrape's
	// text is served again for this long, so no number of scrapers
	// makes the helper work more than once per window.
	metricsCacheSeconds = 15.0
	// cpuSample is _CPU_SAMPLE_INTERVAL_SECONDS.
	cpuSample = 100 * time.Millisecond
)

// virtualFSTypes are _VIRTUAL_FSTYPES: never a storage device.
var virtualFSTypes = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "bpf": true, "tracefs": true, "debugfs": true, "mqueue": true, "hugetlbfs": true,
	"securityfs": true, "autofs": true, "configfs": true, "fusectl": true, "overlay": true, "squashfs": true,
}

type metricsCache struct {
	mu          sync.Mutex
	key, text   string
	until, from float64
}

type metricLabel struct {
	name  string
	value config.Value
}

type metricSample struct {
	value  config.Value
	labels []metricLabel
}

// metricFamily is one # HELP / # TYPE block and its samples.
type metricFamily struct {
	name, help, kind string
	samples          []metricSample
}

func newFamily(name, help, kind string) *metricFamily {
	return &metricFamily{name: name, help: help, kind: kind}
}

// add is MetricFamily.add: a value and its labels, as name, value pairs.
func (f *metricFamily) add(value config.Value, labels ...any) {
	s := metricSample{value: value}
	for i := 0; i+1 < len(labels); i += 2 {
		s.labels = append(s.labels, metricLabel{labels[i].(string), labels[i+1]})
	}
	f.samples = append(f.samples, s)
}

// errMetricValue is a sample value float() refuses: the whole answer
// fails (a 500), as in 1.x.
var errMetricValue = errors.New("metrics: a value is not a number")

// renderMetrics is frfw.metrics.render.
func renderMetrics(families []*metricFamily) (string, error) {
	var lines []string
	for _, f := range families {
		lines = append(lines, "# HELP "+f.name+" "+f.help, "# TYPE "+f.name+" "+f.kind)
		for _, s := range f.samples {
			value, err := formatMetricValue(s.value)
			if err != nil {
				return "", err
			}
			lines = append(lines, f.name+formatLabels(s.labels)+" "+value)
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func formatLabels(labels []metricLabel) string {
	if len(labels) == 0 {
		return ""
	}
	parts := make([]string, len(labels))
	for i, l := range labels {
		parts[i] = l.name + `="` + escapeLabelValue(pyStr(l.value)) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// escapeLabelValue escapes a backslash, a double quote and a newline,
// as the exposition format requires.
func escapeLabelValue(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

// formatMetricValue is _format_value: a bool is 1 or 0, an int its
// digits, anything else repr(float(value)).
func formatMetricValue(v config.Value) (string, error) {
	switch x := v.(type) {
	case bool:
		if x {
			return "1", nil
		}
		return "0", nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case *big.Int:
		return x.String(), nil
	case float64:
		return config.FloatRepr(x), nil
	case string:
		if f, ok := config.PyFloat(x); ok {
			return config.FloatRepr(f), nil
		}
	}
	return "", errMetricValue
}

// pyRound is round(x, digits) for a float.
func pyRound(x float64, digits int) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return x
	}
	f, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', digits, 64), 64)
	return f
}

// -- who may scrape -----------------------------------------------------------------------

type metricsAccessResult int

const (
	metricsOK metricsAccessResult = iota
	metricsOff
	metricsDenied
)

// latin1 is a header value as Starlette decodes it: one character per
// byte.
func latin1(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteRune(rune(s[i]))
	}
	return b.String()
}

// metricsAccess is frfw.metrics.metrics_access. It reads the digest
// from the raw config on purpose: a config that doesn't validate must
// not turn a protected endpoint public, and a present but malformed
// digest fails closed.
func metricsAccess(raw *config.Map, authorization string) (metricsAccessResult, error) {
	var expected config.Value
	if section, ok := field(raw, "metrics").(*config.Map); ok {
		expected = field(section, "token_sha256")
	}
	if expected == nil {
		return metricsOff, nil
	}
	digest, ok := expected.(string)
	if !ok || utf8.RuneCountInString(digest) != 64 {
		return metricsDenied, nil
	}
	scheme, token, _ := strings.Cut(latin1(authorization), " ")
	if config.PyLower(scheme) != "bearer" || token == "" {
		return metricsDenied, nil
	}
	want := config.PyLower(digest)
	for i := 0; i < len(want); i++ {
		if want[i] >= 0x80 {
			return 0, errInternal // hmac.compare_digest refuses a str that isn't ASCII
		}
	}
	sum := sha256.Sum256([]byte(config.PyStrip(token)))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) != 1 {
		return metricsDenied, nil
	}
	return metricsOK, nil
}

func plainAnswer(status int, contentType, body string) *answer {
	a := &answer{status: status, body: []byte(body)}
	a.header("content-type", contentType)
	return a
}

func (s *Server) showMetrics(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	access, err := metricsAccess(raw, q.r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	switch access {
	case metricsOff:
		return plainAnswer(404, "text/plain; charset=utf-8", metricsOffText), nil
	case metricsDenied:
		a := &answer{status: 401, body: []byte(metricsDeniedText)}
		a.header("www-authenticate", `Bearer realm="fr_os metrics"`)
		a.header("content-type", "text/plain; charset=utf-8")
		return a, nil
	}
	// The cache is keyed by the config: a change shows at once. 1.x keys
	// it by json.dumps(sort_keys=True); repr is as good a fingerprint and
	// can't fail (decisions.md, 3c-2).
	key := config.Repr(raw)
	now := s.env.Now()
	s.metrics.mu.Lock()
	if s.metrics.key == key && s.metrics.from <= now && now < s.metrics.until {
		text := s.metrics.text
		s.metrics.mu.Unlock()
		return plainAnswer(200, metricsType, text), nil
	}
	s.metrics.mu.Unlock()
	c, perr := config.Parse(raw)
	if perr != nil {
		// A config that doesn't validate still gets the families that
		// need none, as the dashboard degrades.
		c = nil
	}
	text, err := renderMetrics(s.metricFamilies(c))
	if err != nil {
		return nil, errInternal
	}
	now = s.env.Now()
	s.metrics.mu.Lock()
	s.metrics.key, s.metrics.text, s.metrics.from, s.metrics.until = key, text, now, now+metricsCacheSeconds
	s.metrics.mu.Unlock()
	return plainAnswer(200, metricsType, text), nil
}

// metricFamilies is generate_metrics_text's gathering, in its order;
// a family whose builder fails is left out.
func (s *Server) metricFamilies(c *config.Config) []*metricFamily {
	var families []*metricFamily
	collect := func(fams []*metricFamily, err error) {
		if err == nil {
			families = append(families, fams...)
		}
	}
	one := func(f *metricFamily, err error) ([]*metricFamily, error) { return []*metricFamily{f}, err }
	collect(s.infoFamilies(c), nil)
	if c != nil {
		collect(one(s.interfaceBytesFamily(c)))
		collect(one(s.xdpStatusFamily(c)))
		collect(s.iotFamilies(c))
		collect(one(s.dnsCategoryFamily(c)))
		collect(s.appidFamilies(c))
		collect(s.tlsFamilies(c))
	}
	collect(one(s.xdpBlockedFamily()))
	collect(one(s.adblockFamily()))
	collect(one(s.helperCountFamily(s.helper.ZTNASessionsStatus, "fros_ztna_active_sessions",
		"Number of currently authorized ZTNA client sessions.")))
	collect(one(s.helperCountFamily(s.helper.BruteforceStatus, "fros_bruteforce_banned_ips",
		"Number of source IPs currently banned in the brute-force jail.")))
	collect(one(s.helperCountFamily(s.helper.IDSQuarantineStatus, "fros_ai_ids_quarantined_hosts",
		"Number of hosts currently quarantined by the AI IDS/IPS engine.")))
	collect(s.cpuFamilies())
	collect(s.ramFamilies())
	collect(s.storageFamilies())
	return families
}

// -- the families -------------------------------------------------------------------------

func (s *Server) infoFamilies(c *config.Config) []*metricFamily {
	info := newFamily("fros_info",
		"Constant 1; labels identify this router (site name, hostname, version, release codename).", "gauge")
	valid := newFamily("fros_config_valid", "1 if the on-disk config.yaml passes validation, else 0.", "gauge")
	if c == nil {
		info.add(1, "site_name", "unknown", "hostname", "unknown", "version", s.version, "codename", s.codename)
		valid.add(0)
	} else {
		site := c.Hostname
		if c.Metrics.Site != nil && *c.Metrics.Site != "" {
			site = *c.Metrics.Site
		}
		info.add(1, "site_name", site, "hostname", c.Hostname, "version", s.version, "codename", s.codename)
		valid.add(1)
	}
	return []*metricFamily{info, valid}
}

func (s *Server) interfaceBytesFamily(c *config.Config) (*metricFamily, error) {
	f := newFamily("fros_interface_bytes_total", "Total bytes transferred per network interface and direction.",
		"counter")
	for _, iface := range c.Interfaces.Values() {
		for _, d := range [][2]string{{"rx", "rx_bytes"}, {"tx", "tx_bytes"}} {
			text, err := readText(s.env.Paths.at("/sys/class/net/" + iface.Device + "/statistics/" + d[1]))
			if err != nil {
				continue // OSError, or a ValueError of the decoding
			}
			n, ok := config.PyInt(config.PyStrip(text))
			if !ok {
				continue
			}
			f.add(n, "device", iface.Device, "direction", d[0])
		}
	}
	return f, nil
}

func (s *Server) xdpStatusFamily(c *config.Config) (*metricFamily, error) {
	f := newFamily("fros_xdp_status",
		"XDP TLS SNI filter attach status per interface (0=disabled/not attached, 1=native, 2=generic).", "gauge")
	if !c.XdpSniFilter.Enabled || len(c.XdpSniFilter.Interfaces) == 0 {
		return f, nil
	}
	attached, err := s.attachedXDP()
	if err != nil {
		return nil, err
	}
	modes := map[string]int{"xdpdrv": 1, "xdpgeneric": 2}
	for _, name := range c.XdpSniFilter.Interfaces {
		iface, _ := c.Interfaces.Get(name)
		f.add(modes[attached[iface.Device]], "device", iface.Device)
	}
	return f, nil
}

// pyIterate is `for x in v`: a list's items, a dict's keys, a str's
// characters; anything else raises TypeError.
func pyIterate(v config.Value) ([]config.Value, error) {
	switch x := v.(type) {
	case []config.Value:
		return x, nil
	case *config.Map:
		return x.Keys(), nil
	case string:
		var out []config.Value
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	}
	return nil, errInternal
}

// unhashable is whether `x in some_dict` raises TypeError for x.
func unhashable(v config.Value) bool {
	switch v.(type) {
	case []config.Value, *config.Map:
		return true
	}
	return false
}

func (s *Server) iotFamilies(c *config.Config) ([]*metricFamily, error) {
	if !c.Iot.Enabled {
		return nil, nil
	}
	devices := newFamily("fros_iot_devices", "Devices found by the last IoT scan, by classification.", "gauge")
	categories := []string{"iot", "general", "unknown"}
	counts := map[string]int{}
	// json.loads(read_text()), its OSError, ValueError and AttributeError
	// caught: the counts stay where they got to.
	inventory, ok, err := readJSONState(s.env.Paths.sensorState("iot_inventory.json"))
	if m, isMap := inventory.(*config.Map); err == nil && ok && isMap {
		list, err := pyIterate(pyGet(m, "devices", []config.Value{}))
		if err != nil {
			return nil, err // TypeError: not caught
		}
		for _, d := range list {
			device, isMap := d.(*config.Map)
			if !isMap {
				break // AttributeError
			}
			category := field(device, "category")
			if unhashable(category) {
				return nil, errInternal
			}
			if name, isStr := category.(string); isStr && slices.Contains(categories, name) {
				counts[name]++
			}
		}
	}
	for _, name := range categories {
		devices.add(counts[name], "category", name)
	}
	isolated := newFamily("fros_iot_isolated_devices",
		"Devices currently isolated by MAC address in the kernel iot_isolated set.", "gauge")
	status, err := s.helper.IoTIsolationStatus()
	if err != nil {
		return nil, err
	}
	if config.Truthy(field(status, "ok")) {
		isolated.add(pyGet(status, "count", 0))
	}
	return []*metricFamily{devices, isolated}, nil
}

func (s *Server) adblockHosts() string { return s.env.Paths.at("/etc/fr_os/adblock.hosts") }

func (s *Server) dnsCategoryFamily(c *config.Config) (*metricFamily, error) {
	f := newFamily("fros_dns_blocked_domains",
		"Domains currently loaded into the DNS resolver, per blocklist category.", "gauge")
	// category_counts: {"ads": base list, name: its list, ...}, a dict
	// (a category named "ads" takes the base list's place).
	names := []string{"ads"}
	counts := map[string]int{}
	n, err := countBlockedDomains(s.adblockHosts())
	if err != nil {
		return nil, err
	}
	counts["ads"] = n
	for _, name := range c.Adblocker.Categories.Keys {
		n, err := countBlockedDomains(s.env.Paths.categoryFile(name))
		if err != nil {
			return nil, err
		}
		if _, seen := counts[name]; !seen {
			names = append(names, name)
		}
		counts[name] = n
	}
	for _, name := range names {
		f.add(counts[name], "category", name)
	}
	return f, nil
}

func (s *Server) appidFamilies(c *config.Config) ([]*metricFamily, error) {
	if !c.AppControl.Enabled {
		return nil, nil
	}
	catalog, err := appid.Load()
	if err != nil {
		return nil, err
	}
	active := newFamily("fros_app_active_clients",
		"Clients that used the app in the last 15 minutes (DNS lookups / TLS SNIs).", "gauge")
	hits := newFamily("fros_app_hits_24h",
		"DNS lookups and TLS connections attributed to the app in the last 24 hours.", "gauge")
	// load_usage: {"apps": {}} unless the file is an object whose "apps"
	// is one; a decoding error isn't caught.
	data, ok, err := readJSONState(s.env.Paths.sensorState("appid_usage.json"))
	if err != nil {
		return nil, err
	}
	apps := config.NewMap()
	if m, isMap := data.(*config.Map); ok && isMap {
		if a, isMap := field(m, "apps").(*config.Map); isMap {
			apps = a
		}
	}
	ids := make([]string, 0, apps.Len())
	for _, k := range apps.Keys() {
		ids = append(ids, k.(string)) // JSON names are strings
	}
	slices.Sort(ids)
	for _, id := range ids {
		stats, isMap := field(apps, id).(*config.Map)
		if !isMap {
			return nil, errInternal // AttributeError
		}
		category := "unknown"
		if app := catalog.App(id); app != nil {
			category = app.Category
		}
		active.add(pyGet(stats, "active_clients", 0), "app", id, "category", category)
		hits.add(pyGet(stats, "hits_24h", 0), "app", id, "category", category)
	}
	blocked := newFamily("fros_app_blocked", "Apps currently on the blocked list (1 per blocked app).", "gauge")
	for _, id := range c.AppControl.BlockedApps {
		blocked.add(1, "app", id)
	}
	return []*metricFamily{active, hits, blocked}, nil
}

// setKey is what makes two values one member of a Python set: 1, 1.0
// and True are one; json.loads gives every NaN the same object.
func setKey(v config.Value) (string, error) {
	switch x := v.(type) {
	case nil:
		return "none", nil
	case bool:
		if x {
			return "n1", nil
		}
		return "n0", nil
	case *big.Int:
		return "n" + x.String(), nil
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan", nil
		case !math.IsInf(x, 0) && x == math.Trunc(x):
			n, _ := big.NewFloat(x).Int(nil)
			return "n" + n.String(), nil
		}
		return "f" + config.FloatRepr(x), nil
	case string:
		return "s" + x, nil
	}
	return "", errInternal // unhashable
}

func (s *Server) tlsFamilies(c *config.Config) ([]*metricFamily, error) {
	if !c.TlsFingerprint.Enabled {
		return nil, nil
	}
	data, ok, err := readJSONState(s.env.Paths.sensorState("tls_fingerprints.json"))
	if err != nil {
		return nil, err // UnicodeDecodeError: not caught
	}
	state, isMap := data.(*config.Map)
	if !ok || !isMap {
		state = config.NewMap()
	}
	clients := config.NewMap()
	if v := field(state, "clients"); config.Truthy(v) {
		m, isMap := v.(*config.Map)
		if !isMap {
			return nil, errInternal // .values() of a list
		}
		clients = m
	}
	distinct := map[string]bool{}
	for _, fps := range clients.Values() {
		items, err := pyIterate(fps)
		if err != nil {
			return nil, err
		}
		for _, ja4 := range items {
			key, err := setKey(ja4)
			if err != nil {
				return nil, err
			}
			distinct[key] = true
		}
	}
	now := s.env.Now()
	types := []string{"new_fingerprint", "blocklist"}
	counts := map[string]int{}
	var events []config.Value
	if v := field(state, "events"); config.Truthy(v) {
		if events, err = pyIterate(v); err != nil {
			return nil, err
		}
	}
	for _, e := range events {
		event, isMap := e.(*config.Map)
		if !isMap {
			return nil, errInternal // AttributeError
		}
		typ := field(event, "type")
		if unhashable(typ) {
			return nil, errInternal
		}
		name, isStr := typ.(string)
		if !isStr || !slices.Contains(types, name) {
			continue
		}
		ts, err := pyFloatOf(pyGet(event, "ts", big.NewInt(0)))
		if err != nil {
			return nil, err
		}
		if now-ts <= 24*3600 {
			counts[name]++
		}
	}
	fClients := newFamily("fros_tls_fingerprinted_clients", "Clients with at least one TLS fingerprint recorded.",
		"gauge")
	fClients.add(clients.Len())
	fDistinct := newFamily("fros_tls_distinct_fingerprints", "Distinct JA4 fingerprints recorded across all clients.",
		"gauge")
	fDistinct.add(len(distinct))
	fEvents := newFamily("fros_tls_fingerprint_events_24h", "TLS fingerprint events in the last 24 hours, by type.",
		"gauge")
	for _, name := range types {
		fEvents.add(counts[name], "type", name)
	}
	return []*metricFamily{fClients, fDistinct, fEvents}, nil
}

// xdpBlockedFamily goes through the apply-helper: the counters live on
// bpffs, which is root's (ROADMAP P4-1).
func (s *Server) xdpBlockedFamily() (*metricFamily, error) {
	f := newFamily("fros_xdp_blocked_connections_total",
		"Total connections dropped by the XDP TLS SNI filter for matching the blocklist.", "counter")
	status, err := s.helper.XDPStats()
	if err != nil {
		return nil, err
	}
	if config.Truthy(field(status, "ok")) {
		v, has := status.Get("stats")
		stats, isMap := v.(*config.Map)
		if !has || !isMap {
			return nil, errInternal // KeyError, AttributeError
		}
		f.add(pyGet(stats, "drop_match", 0))
	}
	return f, nil
}

func (s *Server) adblockFamily() (*metricFamily, error) {
	f := newFamily("fros_adblock_total_domains", "Number of unique domains currently in the ad-block hosts list.",
		"gauge")
	n, err := countBlockedDomains(s.adblockHosts())
	if err != nil {
		return nil, err
	}
	f.add(n)
	return f, nil
}

// helperCountFamily is the families that are one helper status's count.
func (s *Server) helperCountFamily(status func() (*config.Map, error), name, help string) (*metricFamily, error) {
	f := newFamily(name, help, "gauge")
	reply, err := status()
	if err != nil {
		return nil, err
	}
	if config.Truthy(field(reply, "ok")) {
		f.add(pyGet(reply, "count", 0))
	}
	return f, nil
}

// -- the hardware -------------------------------------------------------------------------

// readProc is a read whose OSError 1.x catches (ok false); a decoding
// error is not caught and drops the family.
func readProc(path string) (string, bool, error) { return readOptional(path) }

// afterColon is line.split(":", 1)[1].strip(); IndexError without one.
func afterColon(line string) (string, error) {
	_, rest, ok := strings.Cut(line, ":")
	if !ok {
		return "", errInternal
	}
	return config.PyStrip(rest), nil
}

func (s *Server) cpuModel() (string, error) {
	text, ok, err := readProc(s.env.Paths.at("/proc/cpuinfo"))
	if err != nil || !ok {
		return "", err
	}
	for _, line := range config.PySplitlines(text) {
		if strings.HasPrefix(line, "model name") {
			return afterColon(line)
		}
	}
	return "", nil
}

// cpuMHz prefers the live scaling frequency, else /proc/cpuinfo's
// static "cpu MHz".
func (s *Server) cpuMHz() (float64, bool, error) {
	if text, err := readText(s.env.Paths.at("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")); err == nil {
		if khz, ok := config.PyInt(config.PyStrip(text)); ok {
			f, _ := new(big.Rat).SetFrac(khz, big.NewInt(1000)).Float64()
			return f, true, nil
		}
	}
	text, ok, err := readProc(s.env.Paths.at("/proc/cpuinfo"))
	if err != nil || !ok {
		return 0, false, err
	}
	for _, line := range config.PySplitlines(text) {
		if strings.HasPrefix(line, "cpu MHz") {
			value, err := afterColon(line)
			if err != nil {
				return 0, false, err
			}
			f, ok := config.PyFloat(value)
			return f, ok, nil
		}
	}
	return 0, false, nil
}

// cpuTotals is (busy, total) jiffies from /proc/stat's "cpu" line.
func (s *Server) cpuTotals() (busy, total *big.Int, ok bool, err error) {
	text, ok, err := readProc(s.env.Paths.at("/proc/stat"))
	if err != nil || !ok {
		return nil, nil, false, err
	}
	for _, line := range config.PySplitlines(text) {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		var values []*big.Int
		for _, field := range config.PySplit(line)[1:] {
			n, ok := config.PyInt(field)
			if !ok {
				return nil, nil, false, errInternal
			}
			values = append(values, n)
		}
		if len(values) < 4 {
			return nil, nil, false, errInternal // IndexError
		}
		idle := new(big.Int).Set(values[3])
		if len(values) > 4 {
			idle.Add(idle, values[4])
		}
		total = new(big.Int)
		for _, v := range values {
			total.Add(total, v)
		}
		return new(big.Int).Sub(total, idle), total, true, nil
	}
	return nil, nil, false, nil
}

func (s *Server) cpuUsage() (float64, bool, error) {
	busy1, total1, ok, err := s.cpuTotals()
	if err != nil || !ok {
		return 0, false, err
	}
	time.Sleep(cpuSample)
	busy2, total2, ok, err := s.cpuTotals()
	if err != nil || !ok {
		return 0, false, err
	}
	dTotal := new(big.Int).Sub(total2, total1)
	if dTotal.Sign() <= 0 {
		return 0, true, nil
	}
	ratio, _ := new(big.Rat).SetFrac(new(big.Int).Sub(busy2, busy1), dTotal).Float64()
	return math.Max(0, math.Min(1, ratio)), true, nil
}

func (s *Server) cpuFamilies() ([]*metricFamily, error) {
	info := newFamily("fros_hw_cpu_info", "CPU model identification (value is always 1).", "gauge")
	model, err := s.cpuModel()
	if err != nil {
		return nil, err
	}
	if model != "" {
		info.add(1, "model", model)
	}
	usage := newFamily("fros_hw_cpu_usage_ratio",
		"Current CPU utilization ratio (0-1), sampled over a short interval.", "gauge")
	ratio, ok, err := s.cpuUsage()
	if err != nil {
		return nil, err
	}
	if ok {
		usage.add(pyRound(ratio, 4))
	}
	mhzFamily := newFamily("fros_hw_cpu_mhz", "Current CPU clock speed in MHz.", "gauge")
	mhz, ok, err := s.cpuMHz()
	if err != nil {
		return nil, err
	}
	if ok {
		mhzFamily.add(pyRound(mhz, 1))
	}
	return []*metricFamily{info, usage, mhzFamily}, nil
}

// ramTotals is (MemTotal - MemAvailable, MemTotal) in bytes.
func (s *Server) ramTotals() (used, total *big.Int, ok bool, err error) {
	text, ok, err := readProc(s.env.Paths.at("/proc/meminfo"))
	if err != nil || !ok {
		return nil, nil, false, err
	}
	values := map[string]*big.Int{}
	for _, line := range config.PySplitlines(text) {
		key, rest, sep := strings.Cut(line, ":")
		if !sep {
			continue
		}
		rest = config.PyStrip(rest)
		if !strings.HasSuffix(rest, "kB") {
			continue
		}
		n, ok := config.PyInt(config.PyStrip(strings.TrimSuffix(rest, "kB")))
		if !ok {
			continue
		}
		values[config.PyStrip(key)] = n.Mul(n, big.NewInt(1024))
	}
	total, available := values["MemTotal"], values["MemAvailable"]
	if total == nil || available == nil {
		return nil, nil, false, nil
	}
	used = new(big.Int).Sub(total, available)
	if used.Sign() < 0 {
		used.SetInt64(0)
	}
	return used, total, true, nil
}

func (s *Server) ramFamilies() ([]*metricFamily, error) {
	info := newFamily("fros_hw_ram_info",
		"Installed RAM module identification (value is always 1); requires root via dmidecode.", "gauge")
	status, err := s.helper.HWRamInfo()
	if err != nil {
		return nil, err
	}
	if config.Truthy(field(status, "ok")) {
		modules, err := pyIterate(pyGet(status, "modules", []config.Value{}))
		if err != nil {
			return nil, err
		}
		for _, m := range modules {
			module, isMap := m.(*config.Map)
			if !isMap {
				return nil, errInternal // AttributeError
			}
			info.add(1, "model", pyGet(module, "part_number", "unknown"),
				"speed_mhz", pyStr(pyGet(module, "speed_mhz", big.NewInt(0))))
		}
	}
	usage := newFamily("fros_hw_ram_usage_bytes", "Currently used RAM in bytes (MemTotal - MemAvailable).", "gauge")
	totalFamily := newFamily("fros_hw_ram_total_bytes", "Total installed RAM in bytes.", "gauge")
	used, total, ok, err := s.ramTotals()
	if err != nil {
		return nil, err
	}
	if ok {
		usage.add(used)
		totalFamily.add(total)
	}
	return []*metricFamily{info, usage, totalFamily}, nil
}

// storageMounts are the mounts of real block devices, each mount point
// once, as df shows them.
func (s *Server) storageMounts() ([][2]string, error) {
	text, ok, err := readProc(s.env.Paths.at("/proc/mounts"))
	if err != nil || !ok {
		return nil, err
	}
	var mounts [][2]string
	seen := map[string]bool{}
	for _, line := range config.PySplitlines(text) {
		parts := config.PySplit(line)
		if len(parts) < 3 {
			continue
		}
		device, mount, fstype := parts[0], parts[1], parts[2]
		if virtualFSTypes[fstype] || !strings.HasPrefix(device, "/dev/") || seen[mount] {
			continue
		}
		seen[mount] = true
		mounts = append(mounts, [2]string{mount, device})
	}
	return mounts, nil
}

func (s *Server) storageFamilies() ([]*metricFamily, error) {
	info := newFamily("fros_hw_storage_info", "Mounted storage device identification (value is always 1).", "gauge")
	usage := newFamily("fros_hw_storage_usage_bytes", "Used storage space in bytes for this mount.", "gauge")
	total := newFamily("fros_hw_storage_total_bytes", "Total storage space in bytes for this mount.", "gauge")
	mounts, err := s.storageMounts()
	if err != nil {
		return nil, err
	}
	for _, m := range mounts {
		info.add(1, "mount", m[0], "device_name", m[1])
		used, size, ok := s.env.Disk(m[0])
		if !ok {
			continue
		}
		usage.add(used, "mount", m[0])
		total.add(size, "mount", m[0])
	}
	return []*metricFamily{info, usage, total}, nil
}
