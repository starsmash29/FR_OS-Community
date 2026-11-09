package webui

import (
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The ad-block and DNS filtering screen (1.x's routes/adblock.py): the
// resolver's state and the domains loaded per category (counted here,
// unprivileged), the adblocker settings, the local names (ROADMAP DNS-1)
// and "Refresh now", which the apply-helper does (it downloads and
// writes under /etc/fr_os, which this process never does).

// baseCategory is frfw.adblock.BASE_CATEGORY.
const baseCategory = "ads"

const defaultSourceURL = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

type categoryPreset struct {
	Name, Title string
	URLs        []string
	Note        string
}

const stevenBlack = "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates"

// categoryPresets is frfw.adblock.categories.PRESETS, in its order.
var categoryPresets = []categoryPreset{
	{"malware", "Malware distribution sites", []string{"https://urlhaus.abuse.ch/downloads/hostfile/"},
		"abuse.ch URLhaus host file; terms of use at urlhaus.abuse.ch/api/"},
	{"phishing", "Phishing", []string{"https://phishing.army/download/phishing_army_blocklist.txt"},
		"Phishing Army; CC BY-NC 4.0 -- non-commercial use only"},
	{"doh-bypass", "Public DNS-over-HTTPS resolvers",
		[]string{"https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt"},
		"stops browsers and apps from bypassing this resolver via DoH; dibdot/DoH-IP-blocklists"},
	{"gambling", "Gambling", []string{stevenBlack + "/gambling-only/hosts"}, "StevenBlack/hosts extension"},
	{"adult", "Adult content", []string{stevenBlack + "/porn-only/hosts"}, "StevenBlack/hosts extension"},
	{"social", "Social networks", []string{stevenBlack + "/social-only/hosts"}, "StevenBlack/hosts extension"},
	{"fakenews", "Fake news", []string{stevenBlack + "/fakenews-only/hosts"}, "StevenBlack/hosts extension"},
}

func presetNamed(name config.Value) *categoryPreset {
	for i := range categoryPresets {
		if strEq(name, categoryPresets[i].Name) {
			return &categoryPresets[i]
		}
	}
	return nil
}

// localKinds is _LOCAL_KINDS, in its order.
var localKinds = []struct{ Kind, Label string }{
	{"hosts", "Host"}, {"overrides", "Override (with subdomains)"},
}

func knownLocalKind(kind string) bool { return kind == "hosts" || kind == "overrides" }

type categoryCount struct {
	Name  string
	Count int
}

type presetRow struct {
	Name, Title, Note string
	Selected          bool
}

type customCategory struct{ Name, URLs string }

type localRow struct{ Kind, Label, Name, Address string }

type adblockData struct {
	Enabled                          bool
	SourceURLsText, DefaultSourceURL string
	XDPCriticalLimit                 string
	DomainCount                      int
	Counts                           []categoryCount
	BaseCategory                     string
	Presets                          []presetRow
	Custom                           []customCategory
	AllowlistText                    string
	ServeLAN, ForceDNS, QueryLogging bool
	LocalDNS                         []localRow
	LocalDomain                      string
	StatusLabel, BadgeClass          string
}

// configInt is int(v) for a config value.
func configInt(v config.Value) (*big.Int, error) {
	switch x := v.(type) {
	case *big.Int:
		return x, nil
	case bool:
		if x {
			return big.NewInt(1), nil
		}
		return big.NewInt(0), nil
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return nil, errInternal
		}
		n, _ := big.NewFloat(math.Trunc(x)).Int(nil)
		return n, nil
	case string:
		if n, ok := config.PyInt(x); ok {
			return n, nil
		}
	}
	return nil, errInternal
}

// categoryFile is category_path: <dir>/<name>.hosts (an absolute name
// replaces the directory, as pathlib's / does).
func (p Paths) categoryFile(name string) string {
	if strings.HasPrefix(name, "/") {
		return p.at(name + ".hosts")
	}
	return p.at("/etc/fr_os/adblock.d/" + name + ".hosts")
}

// sortedPairs is sorted(mapping.items()) for a table of names: string
// keys (mixed types can't be sorted).
func sortedPairs(m *config.Map) ([]string, []config.Value, error) {
	type pair struct {
		k string
		v config.Value
	}
	var pairs []pair
	for i, k := range m.Keys() {
		s, ok := k.(string)
		if !ok {
			return nil, nil, errInternal
		}
		pairs = append(pairs, pair{s, m.Values()[i]})
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })
	keys, vals := make([]string, len(pairs)), make([]config.Value, len(pairs))
	for i, p := range pairs {
		keys[i], vals[i] = p.k, p.v
	}
	return keys, vals, nil
}

func (s *Server) showAdblock(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	section, err := getMapOr(raw, "adblocker")
	if err != nil {
		return nil, err
	}
	d := &adblockData{DefaultSourceURL: defaultSourceURL, BaseCategory: baseCategory}
	d.Enabled = config.Truthy(pyGet(section, "enabled", false))
	sources, err := pyStrList(field(section, "source_urls"))
	if err != nil {
		return nil, err
	}
	d.SourceURLsText = strings.Join(sources, "\n")
	limitV := pyGet(section, "xdp_critical_limit", pyInt(0))
	if !config.Truthy(limitV) {
		limitV = pyInt(0)
	}
	limit, err := configInt(limitV)
	if err != nil {
		return nil, err
	}
	d.XDPCriticalLimit = limit.String()
	categories, err := getMapOr(section, "categories")
	if err != nil {
		return nil, err
	}
	base, err := countBlockedDomains(s.env.Paths.at("/etc/fr_os/adblock.hosts"))
	if err != nil {
		return nil, err
	}
	d.Counts = []categoryCount{{baseCategory, base}}
	for _, k := range categories.Keys() {
		name := pyStr(k)
		n, err := countBlockedDomains(s.env.Paths.categoryFile(name))
		if err != nil {
			return nil, err
		}
		replaced := false
		for i := range d.Counts {
			if d.Counts[i].Name == name {
				d.Counts[i].Count, replaced = n, true
			}
		}
		if !replaced {
			d.Counts = append(d.Counts, categoryCount{name, n})
		}
	}
	for _, c := range d.Counts {
		d.DomainCount += c.Count
	}
	active := s.daemonActive("fr-adblock-dns")
	switch {
	case active:
		d.StatusLabel, d.BadgeClass = "Active", "badge-green"
	case d.Enabled:
		d.StatusLabel, d.BadgeClass = "Enabled, not yet applied -- run Apply", "badge-yellow"
	default:
		d.StatusLabel, d.BadgeClass = "Disabled", "badge-red"
	}
	for _, p := range categoryPresets {
		d.Presets = append(d.Presets, presetRow{p.Name, p.Title, p.Note, categories.Has(p.Name)})
	}
	for i, k := range categories.Keys() {
		if presetNamed(k) != nil {
			continue
		}
		urls, err := jinjaJoin(categories.Values()[i], ", ")
		if err != nil {
			return nil, err
		}
		d.Custom = append(d.Custom, customCategory{pyStr(k), urls})
	}
	allow, err := pyStrList(field(section, "allowlist"))
	if err != nil {
		return nil, err
	}
	d.AllowlistText = strings.Join(allow, "\n")
	d.ServeLAN = config.Truthy(pyGet(section, "serve_lan", false))
	d.ForceDNS = config.Truthy(pyGet(section, "force_dns", false))
	d.QueryLogging = config.Truthy(pyGet(section, "query_logging", false))
	local, err := getMapOr(raw, "local_dns")
	if err != nil {
		return nil, err
	}
	for _, kind := range localKinds {
		table, err := getMapOr(local, kind.Kind)
		if err != nil {
			return nil, err
		}
		names, addresses, err := sortedPairs(table)
		if err != nil {
			return nil, err
		}
		for i, name := range names {
			d.LocalDNS = append(d.LocalDNS, localRow{kind.Kind, kind.Label, name, pyStr(addresses[i])})
		}
	}
	if v := field(local, "domain"); config.Truthy(v) {
		d.LocalDomain = pyStr(v)
	}
	return s.render(q, "adblock", flash(q, &page{Username: q.user.Username, Data: d}))
}

// localName is _local_name: stripped, lower-cased, without the root dot.
func localName(name string) string {
	return strings.TrimRight(config.PyLower(pyStripped(name)), ".")
}

// saveLocalDNS is _save_local_dns: the section without its empty parts
// (none at all when every part is empty).
func (s *Server) saveLocalDNS(raw, local *config.Map, success string) (*answer, error) {
	out := config.NewMap()
	for i, k := range local.Keys() {
		if v := local.Values()[i]; config.Truthy(v) {
			out.SetKey(k, v)
		}
	}
	raw.Set("local_dns", out)
	if out.Len() == 0 {
		raw.Delete("local_dns")
	}
	return s.saved(raw, "/adblock", success+" -- Apply on the dashboard to use it")
}

func (s *Server) addLocalName(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var kind, name, address string
	if err = q.fields(func(p *formParams) { kind, name, address = p.str("kind"), p.str("name"), p.str("address") }); err != nil {
		return nil, err
	}
	if !knownLocalKind(kind) {
		return errorRedirect("/adblock", fmt.Sprintf("unknown kind %s", config.Repr(kind))), nil
	}
	name = localName(name)
	previous, err := getMapOr(raw, "local_dns")
	if err != nil {
		return nil, err
	}
	local := copyMap(previous)
	tableV, err := getMapOr(local, kind)
	if err != nil {
		return nil, err
	}
	table := copyMap(tableV)
	if table.Has(name) {
		return errorRedirect("/adblock", name+" is already listed; remove it first"), nil
	}
	table.Set(name, pyStripped(address))
	local.Set(kind, table)
	return s.saveLocalDNS(raw, local, name+" added")
}

func (s *Server) removeLocalName(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var kind, name string
	if err = q.fields(func(p *formParams) { kind, name = p.str("kind"), p.str("name") }); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "local_dns")
	if err != nil {
		return nil, err
	}
	local := copyMap(previous)
	table := config.NewMap()
	if knownLocalKind(kind) {
		t, err := getMapOr(local, kind)
		if err != nil {
			return nil, err
		}
		table = copyMap(t)
	}
	if !table.Has(name) {
		return errorRedirect("/adblock", name+" is not listed"), nil
	}
	table.Delete(name)
	local.Set(kind, table)
	return s.saveLocalDNS(raw, local, name+" removed")
}

func (s *Server) saveLocalDomain(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var domain string
	if err = q.fields(func(p *formParams) { domain = p.strOr("domain", "") }); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "local_dns")
	if err != nil {
		return nil, err
	}
	local := copyMap(previous)
	local.Set("domain", localName(domain))
	return s.saveLocalDNS(raw, local, "Local domain saved")
}

// textLines is _lines: one item per line or comma, stripped, without
// repeats.
func textLines(text string) []config.Value {
	out := []config.Value{}
	seen := map[string]bool{}
	for _, line := range config.PySplitlines(strings.ReplaceAll(text, ",", "\n")) {
		if item := pyStripped(line); item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func (s *Server) saveAdblock(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled, serveLAN, forceDNS, queryLogging bool
	var sources, allowlist string
	var limit *big.Int
	var chosen []string
	if err = q.fields(func(p *formParams) {
		enabled, sources, limit = p.boolOr("enabled", false), p.strOr("source_urls", ""), p.intOr("xdp_critical_limit", pyInt(0))
		chosen, allowlist = p.list("categories"), p.strOr("allowlist", "")
		serveLAN, forceDNS, queryLogging = p.boolOr("serve_lan", false), p.boolOr("force_dns", false),
			p.boolOr("query_logging", false)
	}); err != nil {
		return nil, err
	}
	previous, err := getMapOr(raw, "adblocker")
	if err != nil {
		return nil, err
	}
	previousCategories, err := getMapOr(previous, "categories")
	if err != nil {
		return nil, err
	}
	// Presets come from the form; hand-added categories are carried over.
	categories := config.NewMap()
	for i, k := range previousCategories.Keys() {
		if presetNamed(k) == nil {
			categories.SetKey(k, previousCategories.Values()[i])
		}
	}
	for _, name := range chosen {
		preset := presetNamed(name)
		if preset == nil {
			return errorRedirect("/adblock", fmt.Sprintf("unknown category %s", config.Repr(name))), nil
		}
		// Keep an admin's own edited URL list for a preset they already had.
		urls, _ := previousCategories.Get(name)
		if !config.Truthy(urls) {
			urls = stringList(preset.URLs)
		}
		categories.Set(name, urls)
	}
	allow := textLines(allowlist)
	for i, a := range allow {
		allow[i] = config.PyLower(a.(string))
	}
	raw.Set("adblocker", cmdMap("enabled", enabled, "source_urls", textLines(sources), "xdp_critical_limit", limit,
		"categories", categories, "allowlist", allow, "serve_lan", serveLAN, "force_dns", forceDNS,
		"query_logging", queryLogging))
	return s.saved(raw, "/adblock", "Ad-block settings saved -- click Refresh now to download new categories, "+
		"then Apply on the dashboard")
}

func (s *Server) refreshAdblock(q *request) (*answer, error) {
	result, err := s.helper.RefreshAdblock()
	if err != nil {
		return nil, err // a HelperError isn't caught here in 1.x
	}
	if config.Truthy(field(result, "ok")) {
		return successRedirect("/adblock", pyStr(pyGet(result, "message", "Refreshed"))), nil
	}
	msg := field(result, "message")
	if !config.Truthy(msg) {
		msg = "Refresh failed"
	}
	return errorRedirect("/adblock", pyStr(msg)), nil
}
