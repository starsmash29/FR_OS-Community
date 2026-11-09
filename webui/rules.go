package webui

import (
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// The rules screen (1.x's routes/rules.py): the list with the rule
// check (security-lessons K2), schedules and temporary rules, adding a
// rule where it takes effect (ROADMAP SEC-30), moving and deleting one,
// and the schedules' time zone.

var weekdayKeys = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}

// describeSchedule is frfw.nft.schedule.describe: "Mon-Fri 21:30-06:30".
func describeSchedule(days []int, start, end int) string {
	set := map[int]bool{}
	for _, d := range days {
		set[d] = true
	}
	same := func(want ...int) bool {
		if len(set) != len(want) {
			return false
		}
		for _, d := range want {
			if !set[d] {
				return false
			}
		}
		return true
	}
	var text string
	switch {
	case same(0, 1, 2, 3, 4, 5, 6):
		text = "Daily"
	case same(0, 1, 2, 3, 4):
		text = "Mon-Fri"
	case same(5, 6):
		text = "Sat-Sun"
	default:
		sorted := make([]int, 0, len(set))
		for d := range set {
			sorted = append(sorted, d)
		}
		sort.Ints(sorted)
		names := make([]string, len(sorted))
		for i, d := range sorted {
			names[i] = nft.WeekdayNames[d][:3]
		}
		text = strings.Join(names, ", ")
	}
	hm := func(m int) string { return fmt.Sprintf("%02d:%02d", m/60, m%60) }
	return text + " " + hm(start) + "-" + hm(end)
}

// zoneOf is `ZoneInfo(tz) if tz else <the router's zone>` for a config
// value; ok is false where ZoneInfo would refuse the name.
func (s *Server) zoneOf(tz config.Value) (*time.Location, bool, error) {
	if !config.Truthy(tz) {
		return s.env.Local, true, nil
	}
	name, isStr := tz.(string)
	if !isStr {
		return nil, false, errInternal // ZoneInfo(5) is a TypeError, which 1.x doesn't catch
	}
	if !config.ValidZoneName(name) {
		return nil, false, nil
	}
	loc, err := time.LoadLocation(name)
	return loc, err == nil, nil
}

// ruleTime is the rules screen's _local: a moment as "2026-11-01 09:00"
// in the zone, or the router's when the zone is unset or unknown.
func (s *Server) ruleTime(ts float64, tz config.Value) (string, error) {
	loc, ok, err := s.zoneOf(tz)
	if err != nil {
		return "", err
	}
	if !ok {
		loc = s.env.Local
	}
	return unixTime(ts).In(loc).Format("2006-01-02 15:04"), nil
}

func unixTime(ts float64) time.Time {
	sec := int64(ts)
	if float64(sec) > ts {
		sec--
	}
	return time.Unix(sec, int64((ts-float64(sec))*1e9))
}

func localMinuteOfWeek(t time.Time) int {
	return (int(t.Weekday())+6)%7*24*60 + t.Hour()*60 + t.Minute()
}

// chainGroup is rule_order._chain_group: a rule only shadows another in
// the same chain and group.
func chainGroup(r *config.Rule) [2]bool {
	return [2]bool{r.ToZone == config.SelfZone, r.Schedule != nil && r.Schedule.CutEstablished}
}

// earliestShadower is rule_order.earliest_shadower: the first rule in the
// new rule's chain that matches all of it and stops it from taking
// effect (it decides the other way, or is an accept without the ZTNA
// gate the new rule asks for).
func earliestShadower(rules []config.Rule, added *config.Rule) *config.Rule {
	for i := range rules {
		r := &rules[i]
		if r.Name == added.Name || chainGroup(r) != chainGroup(added) {
			continue
		}
		if covers(r, added) && (r.Action != added.Action || added.RequireZtna && !r.RequireZtna) {
			return r
		}
	}
	return nil
}

// placeRule is rule_order.place: the just-added rule moved to just before
// the rule that would otherwise shadow it; the shadower's name, or "".
func placeRule(raw []*config.Map, name string, c *config.Config) ([]*config.Map, string) {
	var added *config.Rule
	for i := range c.Rules {
		if c.Rules[i].Name == name {
			added = &c.Rules[i]
			break
		}
	}
	if added == nil {
		return raw, ""
	}
	shadower := earliestShadower(c.Rules, added)
	if shadower == nil {
		return raw, ""
	}
	index := func(n string) int {
		return slices.IndexFunc(raw, func(m *config.Map) bool { return strEq(field(m, "name"), n) })
	}
	src, dst := index(name), index(shadower.Name)
	if src < 0 || dst < 0 || src < dst {
		return raw, ""
	}
	entry := raw[src]
	out := slices.Delete(slices.Clone(raw), src, src+1)
	return slices.Insert(out, dst, entry), shadower.Name
}

type ruleSchedule struct {
	Text        string
	Active, Cut bool
}

type ruleExpiry struct {
	Text string
	Past bool
}

type ruleRow struct {
	Name                  string
	Flag                  *finding
	Action, ActionClass   string
	From, To, Proto, Port string
	Mac                   string
	Schedule              *ruleSchedule
	Expiry                *ruleExpiry
	LastHit, Log, Ztna    string
	First, Last           bool
}

// weekday is a day's form value and its label (`day|capitalize`).
type weekday struct{ Key, Label string }

type rulesData struct {
	Rules      []ruleRow
	Findings   []finding
	HasExpired bool
	Timezone   string
	RouterTime string
	Weekdays   []weekday
	Zones      []string
}

// jinjaGet is `item.key` in a template for a raw config item: its value
// and whether it is defined (a mapping with that key).
func jinjaGet(item config.Value, key string) (config.Value, bool) {
	m, ok := item.(*config.Map)
	if !ok {
		return nil, false
	}
	return m.Get(key)
}

// jinjaText is how `{{ item.key }}` renders: undefined is empty.
func jinjaText(item config.Value, key string) string {
	v, ok := jinjaGet(item, key)
	if !ok {
		return ""
	}
	return pyStr(v)
}

// jinjaOr is `{{ item.key or alt }}`.
func jinjaOr(item config.Value, key, alt string) string {
	v, ok := jinjaGet(item, key)
	if !ok || !config.Truthy(v) {
		return alt
	}
	return pyStr(v)
}

// pyIter is iterating `v or []` in Python: a list's items, a mapping's
// keys, a string's characters; anything else raises.
func pyIter(v config.Value) ([]config.Value, error) {
	if !config.Truthy(v) {
		return nil, nil
	}
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

func (s *Server) listRules(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	tz := field(raw, "timezone")
	hits := loadRuleHits(s.env.Paths.at("/etc/fr_os/rule_hits.json"))
	now := s.env.Now()
	var findings []finding
	schedules := map[string]*ruleSchedule{}
	expiry := map[string]*ruleExpiry{}
	if c, err := config.Parse(raw); err == nil {
		if findings, err = lintRules(c, hits, now); err != nil {
			return nil, err
		}
		for i := range c.Rules {
			r := &c.Rules[i]
			if r.Expires != nil {
				text, err := s.ruleTime(float64(*r.Expires), c.Timezone)
				if err != nil {
					return nil, err
				}
				expiry[r.Name] = &ruleExpiry{text, float64(*r.Expires) <= now}
			}
		}
		loc, _, err := s.zoneOf(c.Timezone)
		if err != nil {
			return nil, err
		}
		minute := localMinuteOfWeek(unixTime(now).In(loc))
		for i := range c.Rules {
			if sc := c.Rules[i].Schedule; sc != nil {
				schedules[c.Rules[i].Name] = &ruleSchedule{describeSchedule(sc.Days, sc.Start, sc.End),
					nft.IsActive(sc.Days, sc.Start, sc.End, minute), sc.CutEstablished}
			}
		}
	}
	d := &rulesData{Findings: findings}
	for _, day := range weekdayKeys {
		d.Weekdays = append(d.Weekdays, weekday{day, strings.ToUpper(day[:1]) + day[1:]})
	}
	if config.Truthy(tz) {
		d.Timezone = pyStr(tz)
	}
	if loc, ok, err := s.zoneOf(tz); err != nil {
		return nil, err
	} else if ok {
		d.RouterTime = unixTime(now).In(loc).Format("Mon 2006-01-02 15:04 MST")
	}
	lastHit := map[string]string{}
	for i, k := range hits.Keys() {
		e, ok := hits.Values()[i].(*config.Map)
		if !ok {
			return nil, errInternal
		}
		if v := field(e, "last_hit"); config.Truthy(v) {
			f, ok := number(v)
			if !ok {
				return nil, errInternal
			}
			text, err := s.ruleTime(f, tz)
			if err != nil {
				return nil, err
			}
			if name, ok := k.(string); ok {
				lastHit[name] = text
			}
		}
	}
	flagged := map[string]*finding{}
	for i := range findings {
		flagged[findings[i].Rule] = &findings[i] // {f.rule: f for f in findings}: the last one shows
		if findings[i].Kind == "expired" {
			d.HasExpired = true
		}
	}
	items, err := pyIter(field(raw, "rules"))
	if err != nil {
		return nil, err
	}
	for i, item := range items {
		row := ruleRow{Name: jinjaText(item, "name"), From: jinjaOr(item, "from_zone", "any"),
			To: jinjaOr(item, "to_zone", "any"), Proto: jinjaOr(item, "proto", "any"),
			Port: jinjaOr(item, "dst_port", "-"), Mac: jinjaOr(item, "src_mac", ""),
			LastHit: "-", Log: "-", Ztna: "-", First: i == 0, Last: i == len(items)-1}
		action, _ := jinjaGet(item, "action")
		row.Action = jinjaText(item, "action")
		switch {
		case strEq(action, "accept"):
			row.ActionClass = "badge-green"
		case strEq(action, "drop"):
			row.ActionClass = "badge-red"
		default:
			row.ActionClass = "badge-yellow"
		}
		if v, ok := jinjaGet(item, "log"); ok && config.Truthy(v) {
			row.Log = "yes"
		}
		if v, ok := jinjaGet(item, "require_ztna"); ok && config.Truthy(v) {
			row.Ztna = "yes"
		}
		if name, ok := jinjaGet(item, "name"); ok {
			if n, ok := name.(string); ok {
				row.Flag, row.Schedule, row.Expiry = flagged[n], schedules[n], expiry[n]
				if t, ok := lastHit[n]; ok {
					row.LastHit = t
				}
			}
		}
		d.Rules = append(d.Rules, row)
	}
	if d.Zones, err = sortedZoneKeys(raw); err != nil {
		return nil, err
	}
	return s.render(q, "rules", flash(q, &page{Username: q.user.Username, Data: d}))
}

// pyStripped is str.strip().
func pyStripped(s string) string { return config.PyStrip(s) }

// networksField is a rule's src_address/dst_address from the form:
// comma-separated networks, a list when there are several, else one
// string, else nothing (ROADMAP FND-1d).
func networksField(text string) config.Value {
	var nets []config.Value
	for _, n := range strings.Split(text, ",") {
		if n = pyStripped(n); n != "" {
			nets = append(nets, n)
		}
	}
	switch len(nets) {
	case 0:
		return nil
	case 1:
		return nets[0]
	}
	return nets
}

// pyDecimalInt is int(s) for a string str.isdigit() accepted: Unicode
// decimal digits, as Python reads them.
func pyDecimalInt(s string) (*big.Int, bool) {
	if s == "" {
		return nil, false
	}
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return nil, false
		}
		b.WriteByte(byte('0' + digitValue(r)))
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return n, ok
}

// digitValue is a decimal digit's value (Unicode Nd digits come in
// contiguous runs of ten starting at a zero).
func digitValue(r rune) int {
	for z := r; z >= r-9; z-- {
		if !unicode.IsDigit(z - 1) {
			return int(r - z)
		}
	}
	return int(r-'0') % 10
}

func (s *Server) addRule(q *request) (*answer, error) {
	var name, action, fromZone, toZone, proto, dstPort, srcAddress, dstAddress, srcMac string
	var start, end, expires string
	var days []string
	var log, ztna, cut bool
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	if err = q.fields(func(p *formParams) {
		name, action = p.str("name"), p.str("action")
		fromZone, toZone, proto = p.strOr("from_zone", ""), p.strOr("to_zone", ""), p.strOr("proto", "any")
		dstPort, srcAddress, dstAddress = p.strOr("dst_port", ""), p.strOr("src_address", ""), p.strOr("dst_address", "")
		log, ztna = p.boolOr("log", false), p.boolOr("require_ztna", false)
		srcMac, days = p.strOr("src_mac", ""), p.list("schedule_days")
		start, end = p.strOr("schedule_start", ""), p.strOr("schedule_end", "")
		cut, expires = p.boolOr("cut_established", false), p.strOr("expires", "")
	}); err != nil {
		return nil, err
	}
	rule := cmdMap("name", name, "action", action)
	if v := pyStripped(fromZone); v != "" {
		rule.Set("from_zone", v)
	}
	if v := pyStripped(toZone); v != "" {
		rule.Set("to_zone", v)
	}
	if proto != "" && proto != "any" {
		rule.Set("proto", proto)
	}
	if v := pyStripped(dstPort); v != "" {
		if n, ok := pyDecimalInt(v); ok {
			rule.Set("dst_port", n)
		} else {
			rule.Set("dst_port", v)
		}
	}
	for _, kv := range [][2]string{{"src_address", srcAddress}, {"dst_address", dstAddress}} {
		if nets := networksField(kv[1]); nets != nil {
			rule.Set(kv[0], nets)
		}
	}
	if log {
		rule.Set("log", true)
	}
	if ztna {
		rule.Set("require_ztna", true)
	}
	if v := pyStripped(srcMac); v != "" {
		rule.Set("src_mac", config.PyLower(v))
	}
	if pyStripped(start) != "" || pyStripped(end) != "" {
		dayList := []config.Value{"daily"}
		if len(days) > 0 {
			dayList = make([]config.Value, len(days))
			for i, d := range days {
				dayList[i] = d
			}
		}
		schedule := cmdMap("days", dayList, "start", pyStripped(start), "end", pyStripped(end))
		if cut {
			schedule.Set("cut_established", true)
		}
		rule.Set("schedule", schedule)
	}
	if v := pyStripped(expires); v != "" {
		rule.Set("expires", v)
	}

	rules, err := getList(raw, "rules", false)
	if err != nil {
		return nil, err
	}
	rules = slices.DeleteFunc(rules, func(m *config.Map) bool { return strEq(field(m, "name"), name) })
	rules = append(rules, rule)
	raw.Set("rules", values(rules))

	// SEC-30: put the new rule where it takes effect, just before the rule
	// that would otherwise match all of it first and decide the other way.
	placedBefore := ""
	if c, err := config.Parse(raw); err == nil {
		var placed []*config.Map
		if placed, placedBefore = placeRule(rules, name, c); placedBefore != "" {
			raw.Set("rules", values(placed))
		}
	}
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/rules", message), nil
	}
	if placedBefore != "" {
		return successRedirect("/rules", fmt.Sprintf("Rule %s saved, placed above %s, which would have matched it first",
			config.Repr(name), config.Repr(placedBefore))), nil
	}
	// Say it right away if the new rule still trips the rule check (K2).
	c, err := config.Parse(raw)
	if err != nil {
		return nil, errInternal
	}
	found, err := lintRules(c, config.NewMap(), s.env.Now())
	if err != nil {
		return nil, err
	}
	var warnings []string
	for _, f := range found {
		if f.Rule == name && f.Severity == severityWarning {
			warnings = append(warnings, f.Message)
		}
	}
	if len(warnings) > 0 {
		return errorRedirect("/rules", fmt.Sprintf("Rule %s saved, but it %s", config.Repr(name),
			strings.Join(warnings, "; "))), nil
	}
	return successRedirect("/rules", fmt.Sprintf("Rule %s saved", config.Repr(name))), nil
}

// moveRule is SEC-30's move: a rule one step up or down the list.
func (s *Server) moveRule(q *request) (*answer, error) {
	var direction string
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	if err = q.fields(func(p *formParams) { direction = p.str("direction") }); err != nil {
		return nil, err
	}
	name := q.params["name"]
	if direction != "up" && direction != "down" {
		return errorRedirect("/rules", "direction must be 'up' or 'down'"), nil
	}
	rules, err := getList(raw, "rules", true)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(rules, func(m *config.Map) bool { return strEq(field(m, "name"), name) })
	if i < 0 {
		return errorRedirect("/rules", fmt.Sprintf("No such rule %s", config.Repr(name))), nil
	}
	j := i + 1
	if direction == "up" {
		j = i - 1
	}
	if j < 0 || j >= len(rules) {
		edge := "bottom"
		if direction == "up" {
			edge = "top"
		}
		return errorRedirect("/rules", fmt.Sprintf("Rule %s is already at the %s of the list", config.Repr(name), edge)), nil
	}
	moved := slices.Clone(rules)
	moved[i], moved[j] = moved[j], moved[i]
	raw.Set("rules", values(moved))
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if ok {
		return successRedirect("/rules", fmt.Sprintf("Rule %s moved %s", config.Repr(name), direction)), nil
	}
	return errorRedirect("/rules", message), nil
}

// removeExpired tidies temporary rules past their expiry (K2): the
// kernel already ignores them.
func (s *Server) removeExpired(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	c, err := config.Parse(raw)
	if err != nil {
		return errorRedirect("/rules", err.Error()), nil
	}
	now := s.env.Now()
	gone := map[string]bool{}
	for _, r := range c.Rules {
		if r.Expires != nil && float64(*r.Expires) <= now {
			gone[r.Name] = true
		}
	}
	if len(gone) == 0 {
		return successRedirect("/rules", "No expired rules"), nil
	}
	rules, err := getList(raw, "rules", true)
	if err != nil {
		return nil, err
	}
	rules = slices.DeleteFunc(slices.Clone(rules), func(m *config.Map) bool {
		n, ok := field(m, "name").(string)
		return ok && gone[n]
	})
	raw.Set("rules", values(rules))
	names := make([]string, 0, len(gone))
	for n := range gone {
		names = append(names, n)
	}
	sort.Strings(names)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if ok {
		return successRedirect("/rules", fmt.Sprintf("Removed %d expired rule(s): %s", len(gone),
			strings.Join(names, ", "))), nil
	}
	return errorRedirect("/rules", message), nil
}

func (s *Server) deleteRule(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	name := q.params["name"]
	rules, err := getList(raw, "rules", true)
	if err != nil {
		return nil, err
	}
	remaining := slices.DeleteFunc(slices.Clone(rules), func(m *config.Map) bool { return strEq(field(m, "name"), name) })
	if len(remaining) == len(rules) {
		return errorRedirect("/rules", fmt.Sprintf("No such rule %s", config.Repr(name))), nil
	}
	raw.Set("rules", values(remaining))
	return s.saved(raw, "/rules", fmt.Sprintf("Rule %s deleted", config.Repr(name)))
}

func (s *Server) setTimezone(q *request) (*answer, error) {
	var tz string
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	if err = q.fields(func(p *formParams) { tz = p.strOr("timezone", "") }); err != nil {
		return nil, err
	}
	if v := pyStripped(tz); v != "" {
		raw.Set("timezone", v)
	} else {
		raw.Delete("timezone")
	}
	return s.saved(raw, "/rules", "Time zone saved -- click Apply on the dashboard to re-render scheduled rules")
}
