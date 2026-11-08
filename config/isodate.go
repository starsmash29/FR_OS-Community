package config

import (
	"errors"
	"strings"
	"time"
)

// A rule's `expires` is read with Python's datetime.fromisoformat (1.x,
// frfw.config.loader.parse_expiry), which takes much more than one
// format: a date as YYYY-MM-DD, YYYYMMDD or an ISO week (YYYY-Www-D),
// any single character between date and time, the time as HH, HH:MM,
// HHMM, HH:MM:SS with a fraction after "." or ",", and an offset (Z,
// +HH, +HH:MM, ...). This is a port of CPython's own parser
// (Lib/_pydatetime.py), so the same strings are accepted.

var errISO = errors.New("invalid isoformat string")

type isoMoment struct {
	year, month, day           int
	hour, minute, second, usec int
	hasOffset                  bool
	offsetUsec                 int64
}

func isoDigit(c rune) bool { return c >= '0' && c <= '9' }

func isASCII(r []rune) bool {
	for _, c := range r {
		if c > 0x7f {
			return false
		}
	}
	return true
}

func readComponent(r []rune, from, n int) (int, error) {
	if from+n > len(r) {
		return 0, errISO
	}
	v := 0
	for _, c := range r[from : from+n] {
		if !isoDigit(c) {
			return 0, errISO
		}
		v = v*10 + int(c-'0')
	}
	return v, nil
}

func findSeparator(s []rune) (int, error) {
	n := len(s)
	if n == 7 {
		return 7, nil
	}
	if s[4] == '-' {
		if s[5] == 'W' {
			if n < 8 {
				return 0, errISO
			}
			if n > 8 && s[8] == '-' {
				if n == 9 {
					return 0, errISO
				}
				if n > 10 && isoDigit(s[10]) {
					return 8, nil
				}
				return 10, nil
			}
			return 8, nil
		}
		return 10, nil
	}
	if s[4] == 'W' {
		idx := 7
		for idx < n && isoDigit(s[idx]) {
			idx++
		}
		if idx < 9 {
			return idx, nil
		}
		if idx%2 == 0 {
			return 7, nil
		}
		return 8, nil
	}
	return 8, nil
}

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }

func daysInMonth(y, m int) int {
	return time.Date(y, time.Month(m)+1, 0, 0, 0, 0, 0, time.UTC).Day()
}

// isoWeekToGregorian is _isoweek_to_gregorian.
func isoWeekToGregorian(year, week, day int) (int, int, int, error) {
	if year < 1 || year > 9999 {
		return 0, 0, 0, errISO
	}
	if week <= 0 || week >= 53 {
		ok := false
		if week == 53 {
			// Python's ordinal of Jan 1 mod 7: 0 is Sunday.
			first := int(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC).Weekday())
			ok = first == 4 || (first == 3 && isLeap(year))
		}
		if !ok {
			return 0, 0, 0, errISO
		}
	}
	if day <= 0 || day >= 8 {
		return 0, 0, 0, errISO
	}
	// Monday of ISO week 1: the week with the year's first Thursday.
	jan4 := time.Date(year, 1, 4, 0, 0, 0, 0, time.UTC)
	monday := jan4.AddDate(0, 0, -((int(jan4.Weekday()) + 6) % 7))
	d := monday.AddDate(0, 0, (week-1)*7+(day-1))
	return d.Year(), int(d.Month()), d.Day(), nil
}

func parseISODate(s []rune) (y, m, d int, err error) {
	if (len(s) != 7 && len(s) != 8 && len(s) != 10) || !isASCII(s) {
		return 0, 0, 0, errISO
	}
	if y, err = readComponent(s, 0, 4); err != nil {
		return
	}
	hasSep := s[4] == '-'
	pos := 4
	if hasSep {
		pos++
	}
	at := func(i int) rune {
		if i < len(s) {
			return s[i]
		}
		return 0
	}
	if at(pos) == 'W' {
		pos++
		week, err := readComponent(s, pos, 2)
		if err != nil {
			return 0, 0, 0, err
		}
		pos += 2
		day := 1
		if len(s) > pos {
			if (at(pos) == '-') != hasSep {
				return 0, 0, 0, errISO
			}
			if hasSep {
				pos++
			}
			if day, err = readComponent(s, pos, 1); err != nil {
				return 0, 0, 0, err
			}
		}
		return isoWeekToGregorian(y, week, day)
	}
	if m, err = readComponent(s, pos, 2); err != nil {
		return
	}
	pos += 2
	if (at(pos) == '-') != hasSep {
		return 0, 0, 0, errISO
	}
	if hasSep {
		pos++
	}
	d, err = readComponent(s, pos, 2)
	return
}

// parseHHMMSSFF is _parse_hh_mm_ss_ff.
func parseHHMMSSFF(t []rune) ([4]int, error) {
	var comps [4]int
	pos := 0
	hasSep := false
	for comp := 0; comp < 3; comp++ {
		v, err := readComponent(t, pos, 2)
		if err != nil {
			return comps, err
		}
		comps[comp] = v
		pos += 2
		if comp == 0 {
			hasSep = pos < len(t) && t[pos] == ':'
		}
		if pos >= len(t) || comp >= 2 {
			break
		}
		next := t[pos]
		if hasSep && next != ':' {
			return comps, errISO
		}
		if hasSep {
			pos++
		}
	}
	if pos < len(t) {
		if t[pos] != '.' && t[pos] != ',' {
			return comps, errISO
		}
		pos++
		rest := t[pos:]
		if len(rest) == 0 {
			return comps, errISO
		}
		for _, c := range rest {
			if !isoDigit(c) {
				return comps, errISO
			}
		}
		n := min(len(rest), 6)
		v, _ := readComponent(rest, 0, n)
		for i := n; i < 6; i++ {
			v *= 10
		}
		comps[3] = v
	}
	return comps, nil
}

func indexRune(t []rune, c rune) int {
	for i, x := range t {
		if x == c {
			return i
		}
	}
	return -1
}

// parseISOTime is _parse_isoformat_time.
func parseISOTime(t []rune, m *isoMoment) error {
	if len(t) < 2 || !isASCII(t) {
		return errISO
	}
	tzPos := indexRune(t, '-') + 1
	if tzPos == 0 {
		tzPos = indexRune(t, '+') + 1
	}
	if tzPos == 0 {
		tzPos = indexRune(t, 'Z') + 1
	}
	timeStr := t
	if tzPos > 0 {
		timeStr = t[:tzPos-1]
	}
	c, err := parseHHMMSSFF(timeStr)
	if err != nil {
		return err
	}
	m.hour, m.minute, m.second, m.usec = c[0], c[1], c[2], c[3]
	if tzPos == len(t) && t[len(t)-1] == 'Z' {
		m.hasOffset = true
	} else if tzPos > 0 {
		tz := t[tzPos:]
		if len(tz) == 0 || len(tz) == 1 || len(tz) == 3 {
			return errISO
		}
		z, err := parseHHMMSSFF(tz)
		if err != nil {
			return err
		}
		off := ((int64(z[0])*60+int64(z[1]))*60+int64(z[2]))*1e6 + int64(z[3])
		if t[tzPos-1] == '-' {
			off = -off
		}
		if off <= -86400e6 || off >= 86400e6 {
			return errISO
		}
		m.hasOffset, m.offsetUsec = true, off
	}
	return nil
}

// fromISOFormat is datetime.fromisoformat.
func fromISOFormat(s string) (isoMoment, error) {
	var m isoMoment
	r := []rune(s)
	if len(r) < 7 {
		return m, errISO
	}
	sep, err := findSeparator(r)
	if err != nil {
		return m, err
	}
	dstr := r[:sep]
	var tstr []rune
	if sep+1 < len(r) {
		tstr = r[sep+1:]
	}
	if m.year, m.month, m.day, err = parseISODate(dstr); err != nil {
		return m, err
	}
	if len(tstr) > 0 {
		if err := parseISOTime(tstr, &m); err != nil {
			return m, err
		}
	}
	// The datetime constructor's own checks.
	if m.year < 1 || m.year > 9999 || m.month < 1 || m.month > 12 ||
		m.day < 1 || m.day > daysInMonth(m.year, m.month) ||
		m.hour > 23 || m.minute > 59 || m.second > 59 {
		return m, errISO
	}
	return m, nil
}

// wallSeconds is the moment's wall-clock time as seconds since the
// epoch, read as if it were UTC.
func (m isoMoment) wallSeconds() int64 {
	return time.Date(m.year, time.Month(m.month), m.day, m.hour, m.minute, m.second, 0, time.UTC).Unix()
}

// pythonOffset is the UTC offset Python's zoneinfo (and astimezone, for
// the local zone) gives a naive wall time in loc, with fold=0: inside a
// gap or an overlap, the offset from before the transition. Go's
// time.Date leaves that choice open, and picks the later one in an
// overlap.
func pythonOffset(wall int64, loc *time.Location) int64 {
	// Python finds the last transition T with T + max(before, after) <=
	// wall; its offset is the one after T. Offsets are under a day, so
	// the zones in effect within two days of wall decide.
	t := time.Unix(wall-2*86400, 0).In(loc)
	_, off := t.Zone()
	offset := int64(off)
	for {
		_, end := t.ZoneBounds()
		if end.IsZero() || end.Unix() > wall+2*86400 {
			return offset
		}
		next := end.In(loc)
		_, after := next.Zone()
		before := offset
		if end.Unix()+max(before, int64(after)) <= wall {
			offset = int64(after)
		}
		t = next
	}
}

// unix is int(moment.timestamp()): an offset from the text wins, else
// the moment is read in loc. Python truncates toward zero.
func (m isoMoment) unix(loc *time.Location) int64 {
	wall := m.wallSeconds()
	var offUsec int64
	if m.hasOffset {
		offUsec = m.offsetUsec
	} else {
		offUsec = pythonOffset(wall, loc) * 1e6
	}
	total := wall*1e6 + int64(m.usec) - offUsec
	if total < 0 {
		return -((-total) / 1e6)
	}
	return total / 1e6
}

// validZoneName is zoneinfo.ZoneInfo(name) succeeding.
func validZoneName(name string) bool {
	// zoneinfo takes only a normalized relative path inside TZPATH; Go's
	// LoadLocation also knows "Local" and "" (UTC), which Python doesn't.
	if name == "" || name == "Local" || strings.HasPrefix(name, "/") || strings.Contains(name, "\x00") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	_, err := time.LoadLocation(name)
	return err == nil
}
