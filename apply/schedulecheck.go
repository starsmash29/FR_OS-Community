package apply

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// --- when each rule last matched (frfw.rule_hits, security-lessons K2) --------------

// ReadCounters is the packets per rule name in the loaded ruleset, summed
// over the rule's lines (a scheduled rule has one per window). The error
// is 1.x's text.
func (s *System) ReadCounters() (map[string]*big.Int, error) {
	argv := []string{"nft", "-j", "list", "table", "inet", nft.Table}
	res, err := s.Run(Cmd{Argv: argv, Timeout: 30 * time.Second})
	var te *TimeoutError
	switch {
	case errors.Is(err, ErrNotFound):
		return nil, errors.New("[Errno 2] No such file or directory: 'nft'")
	case errors.As(err, &te):
		return nil, errors.New("Command '" + reprArgv(argv) + "' timed out after 30 seconds")
	case err != nil:
		return nil, err
	case res.Code != 0:
		return nil, errors.New("Command '" + reprArgv(argv) + "' returned non-zero exit status " +
			big.NewInt(int64(res.Code)).String() + ".")
	}
	v, err := config.ParseJSON([]byte(res.Stdout))
	if err != nil {
		return nil, err
	}
	counts := map[string]*big.Int{}
	top, _ := v.(*config.Map)
	if top == nil {
		return counts, nil
	}
	items, _ := top.Get("nftables")
	list, _ := items.([]config.Value)
	for _, item := range list {
		m, _ := item.(*config.Map)
		if m == nil {
			continue
		}
		r, _ := m.Get("rule")
		rule, _ := r.(*config.Map)
		if rule == nil {
			continue
		}
		c, _ := rule.Get("comment")
		comment, _ := c.(string)
		if !strings.HasPrefix(comment, "rule:") {
			continue
		}
		name := strings.TrimPrefix(comment, "rule:")
		exprs, _ := rule.Get("expr")
		el, _ := exprs.([]config.Value)
		for _, e := range el {
			em, _ := e.(*config.Map)
			if em == nil {
				continue
			}
			cv, ok := em.Get("counter")
			if !ok {
				continue
			}
			counter, _ := cv.(*config.Map)
			n := big.NewInt(0)
			if counter != nil {
				if p, ok := counter.Get("packets"); ok {
					if pi, ok := p.(*big.Int); ok {
						n = pi
					}
				}
			}
			if counts[name] == nil {
				counts[name] = big.NewInt(0)
			}
			counts[name] = new(big.Int).Add(counts[name], n)
		}
	}
	return counts, nil
}

func reprArgv(argv []string) string {
	list := make([]config.Value, len(argv))
	for i, a := range argv {
		list[i] = a
	}
	return config.Repr(list)
}

// loadRuleHits is the record's rules, or none.
func loadRuleHits(path string) *config.Map {
	data, err := os.ReadFile(path)
	if err != nil {
		return config.NewMap()
	}
	v, err := config.ParseJSON(data)
	if err != nil {
		return config.NewMap()
	}
	top, _ := v.(*config.Map)
	if top == nil {
		return config.NewMap()
	}
	r, _ := top.Get("rules")
	rules, _ := r.(*config.Map)
	if rules == nil {
		return config.NewMap()
	}
	return rules
}

// RecordRuleHits folds the kernel's counters into the record the rule
// check reads: when FR_OS first saw each rule and when its counter last
// went up. A counter lower than last time means a reload in between, so
// any packets since count as a hit. Rules no longer in the config are
// forgotten. 0644: rule names and times.
func (s *System) RecordRuleHits(counters map[string]*big.Int, names []string) error {
	path := s.Paths.RuleHits
	now := NowSeconds(s.Now())
	old := loadRuleHits(path)
	rules := config.NewMap()
	for _, name := range names {
		entry := config.NewMap()
		if o, ok := old.Get(name); ok {
			if m, _ := o.(*config.Map); m != nil && m.Len() > 0 {
				for i, k := range m.Keys() {
					entry.SetKey(k, m.Values()[i])
				}
			}
		}
		if entry.Len() == 0 {
			entry.Set("since", now)
			entry.Set("last_hit", nil)
			entry.Set("packets", big.NewInt(0))
		}
		if packets := counters[name]; packets != nil {
			before := big.NewInt(0)
			if p, _ := entry.Get("packets"); p != nil {
				if pi, ok := p.(*big.Int); ok {
					before = pi
				}
			}
			if packets.Cmp(before) > 0 || (packets.Cmp(before) < 0 && packets.Sign() > 0) {
				entry.Set("last_hit", now)
			}
			entry.Set("packets", packets)
		}
		rules.Set(name, entry)
	}
	top := config.NewMap()
	top.Set("rules", rules)
	text, err := config.PyJSON(top, -1, false)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)) + ".tmp"
	return pyOSError(replaceFile(path, name, text, 0o644))
}

// --- scheduled rules across DST and zone changes (frfw.schedule_refresh) ------------

// The outcomes of CheckSchedule.
const (
	ScheduleNone          = "no_schedules"
	ScheduleNotRecorded   = "not_recorded"
	ScheduleUpToDate      = "up_to_date"
	ScheduleRefresh       = "refresh"
	ScheduleConfigChanged = "config_changed"
)

// CheckSchedule is the hourly check (fr-schedule-check.timer): scheduled
// rules are rendered with the UTC offset in effect at the apply, so
// after a DST change, or a change of the kernel's zone, they are off
// until applied again. It compares the offset recorded at the last apply
// with today's; only the config that was applied may be re-applied
// (refresh), never edits saved since (config_changed).
func (s *System) CheckSchedule(c *config.Config) (status, message string, err error) {
	if !hasSchedules(c) {
		return ScheduleNone, "No scheduled rules; nothing to check", nil
	}
	clock, err := nft.CurrentClock(c.Timezone, s.Now())
	if err != nil {
		return "", "", err
	}
	record := loadMap(s.Paths.ScheduleState)
	if record == nil {
		return ScheduleNotRecorded, "No record of an applied schedule; apply the config once to start tracking it", nil
	}
	now := DescribeClock(clock)
	rc, _ := record.Get("clock")
	recorded, _ := rc.(*config.Map)
	if recorded != nil && sameClock(recorded, clock) {
		return ScheduleUpToDate, "Scheduled rules are current (" + now + ")", nil
	}
	before := "unknown"
	if b, ok := clockOf(recorded); ok {
		before = DescribeClock(b)
	}
	fp, err := ConfigFingerprint(c)
	if err != nil {
		return "", "", err
	}
	if f, _ := record.Get("config_fingerprint"); f != fp {
		return ScheduleConfigChanged, "Time offset changed (" + before + " -> " + now + "), but config.yaml differs " +
			"from the last applied config; not applying unapplied edits automatically -- " +
			"apply the config to bring the scheduled rules up to date", nil
	}
	return ScheduleRefresh, "Time offset changed (" + before + " -> " + now + "); re-applying scheduled rules", nil
}

// loadMap is a JSON object file, or nil.
func loadMap(path string) *config.Map {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v, err := config.ParseJSON(data)
	if err != nil {
		return nil
	}
	m, _ := v.(*config.Map)
	return m
}

// sameClock is record["clock"] == clock.as_dict(): the same two keys,
// equal as Python compares them.
func sameClock(m *config.Map, c nft.Clock) bool {
	if m.Len() != 2 {
		return false
	}
	return pyEqualInt(m, "utc_offset_minutes", c.UTCOffsetMinutes) &&
		pyEqualInt(m, "kernel_minuteswest", c.KernelMinutesWest)
}

func pyEqualInt(m *config.Map, key string, want int) bool {
	v, ok := m.Get(key)
	if !ok {
		return false
	}
	switch x := v.(type) {
	case *big.Int:
		return x.Cmp(big.NewInt(int64(want))) == 0
	case float64:
		return x == float64(want)
	case bool:
		return (x && want == 1) || (!x && want == 0)
	}
	return false
}

// clockOf is ScheduleClock(**record["clock"]): exactly its two keys, as
// integers.
func clockOf(m *config.Map) (nft.Clock, bool) {
	if m == nil || m.Len() != 2 {
		return nft.Clock{}, false
	}
	a, ok1 := m.Get("utc_offset_minutes")
	b, ok2 := m.Get("kernel_minuteswest")
	ai, ok3 := a.(*big.Int)
	bi, ok4 := b.(*big.Int)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ai.IsInt64() || !bi.IsInt64() {
		return nft.Clock{}, false
	}
	return nft.Clock{UTCOffsetMinutes: int(ai.Int64()), KernelMinutesWest: int(bi.Int64())}, true
}

// --- the resolver's query log (frfw.adblock.dns_service) ------------------------------

// QueryLogMaxBytes is where fr-dns-log-trim.timer empties the query log.
const QueryLogMaxBytes = 16 * 1024 * 1024

// TrimQueryLog empties the query log once it is past QueryLogMaxBytes
// and says whether it did. dnsmasq appends (O_APPEND), so it carries on
// at the new end, and the readers' `tail -F` notices. A symlink is never
// followed.
func (s *System) TrimQueryLog() (bool, error) {
	f, err := os.OpenFile(s.Paths.DNSQueryLog, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, pyOSError(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return false, pyOSError(err)
	}
	if st.Size() <= QueryLogMaxBytes {
		return false, nil
	}
	return true, pyOSError(f.Truncate(0))
}
