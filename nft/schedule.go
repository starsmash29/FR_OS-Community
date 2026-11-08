package nft

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Time-based rule schedules as nftables `meta day` / `meta hour`
// matches: frfw.nft.schedule in 1.x (phase 17).
//
// An admin writes a schedule in local time ("weekdays 22:00-06:00"). The
// kernel compares `meta hour` against UTC seconds since midnight, and
// computes `meta day` from UTC shifted by its own time zone (sys_tz,
// which systemd sets to the local offset when the RTC keeps local time),
// so the two clocks disagree near midnight. Each local weekly interval
// is therefore moved to UTC with the zone's current offset, cut wherever
// either clock crosses midnight, and each piece rendered with the
// kernel's day name and a UTC hour range. The script is loaded with
// TZ=UTC so nft leaves the hours alone; when the offset changes (DST)
// the hourly schedule check re-applies.

const (
	minutesPerDay  = 24 * 60
	minutesPerWeek = 7 * minutesPerDay
)

// WeekdayNames: index 0 is Monday, as everywhere in FR_OS.
var WeekdayNames = [7]string{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}

// Clock is what rendering a schedule needs to know about now: the
// configured zone's offset from UTC, and the kernel's own zone
// (settimeofday's tz_minuteswest: minutes west of Greenwich, so UTC+2
// is -120).
type Clock struct {
	UTCOffsetMinutes  int
	KernelMinutesWest int
}

// CurrentClock is the clock for zone tz ("" for the system's local
// zone) at now.
func CurrentClock(tz string, now time.Time) (Clock, error) {
	loc := time.Local
	if tz != "" {
		var err error
		if loc, err = time.LoadLocation(tz); err != nil {
			return Clock{}, err
		}
	}
	_, offset := now.In(loc).Zone()
	return Clock{UTCOffsetMinutes: floorDiv(offset, 60), KernelMinutesWest: kernelMinutesWest()}, nil
}

// Segment is one rendered piece: the kernel day names it applies to (nil
// for every day) and a UTC seconds-of-day range, inclusive (nil for the
// whole day).
type Segment struct {
	Days  []string
	Hours *[2]int
}

func (s Segment) render() string {
	var parts []string
	if s.Days != nil {
		names := make([]string, len(s.Days))
		for i, d := range s.Days {
			names[i] = `"` + d + `"`
		}
		if len(names) == 1 {
			parts = append(parts, "meta day "+names[0])
		} else {
			parts = append(parts, "meta day { "+strings.Join(names, ", ")+" }")
		}
	}
	if s.Hours != nil {
		parts = append(parts, fmt.Sprintf(`meta hour "%s"-"%s"`, hms(s.Hours[0]), hms(s.Hours[1])))
	}
	return strings.Join(parts, " ")
}

func hms(seconds int) string {
	return fmt.Sprintf("%02d:%02d:%02d", seconds/3600, seconds%3600/60, seconds%60)
}

// floorDiv and floorMod are Python's // and %.
func floorDiv(a, b int) int {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func floorMod(a, b int) int { return a - floorDiv(a, b)*b }

// localIntervals is the schedule as [a, b) minutes of the week in local
// time (Monday 00:00 is 0). end <= start runs past midnight into the
// next day: Fri 22:00-06:00 ends Sat 06:00.
func localIntervals(days []int, start, end int) [][2]int {
	length := end - start
	if end <= start {
		length = minutesPerDay - start + end
	}
	sorted := slices.Sorted(slices.Values(days))
	out := make([][2]int, 0, len(sorted))
	for _, d := range sorted {
		out = append(out, [2]int{d*minutesPerDay + start, d*minutesPerDay + start + length})
	}
	return out
}

// IsActive reports whether the schedule covers a local minute of the
// week: the meaning the rendered segments are tested against.
func IsActive(days []int, start, end, localMinuteOfWeek int) bool {
	t := floorMod(localMinuteOfWeek, minutesPerWeek)
	for _, iv := range localIntervals(days, start, end) {
		if (iv[0] <= t && t < iv[1]) || (iv[0] <= t+minutesPerWeek && t+minutesPerWeek < iv[1]) {
			return true
		}
	}
	return false
}

// Segments renders a schedule for clock.
func Segments(days []int, start, end int, clock Clock) []Segment {
	kernelShift := -clock.KernelMinutesWest // kernel-day clock = UTC + shift

	var pieces [][2]int
	for _, iv := range localIntervals(days, start, end) {
		a := iv[0] - clock.UTCOffsetMinutes
		b := iv[1] - clock.UTCOffsetMinutes
		// Cut at every UTC midnight and every kernel-day midnight.
		cuts := append(midnights(a, b, 0), midnights(a, b, kernelShift)...)
		slices.Sort(cuts)
		cuts = slices.Compact(cuts)
		bounds := append(append([]int{a}, cuts...), b)
		for i := 0; i+1 < len(bounds); i++ {
			pieces = append(pieces, [2]int{bounds[i], bounds[i+1]})
		}
	}

	// Group identical UTC hour ranges by kernel day, then merge adjacent
	// ranges that apply to the same days (a whole-day schedule cut at UTC
	// midnight comes back together). Both groupings keep first-seen
	// order, as Python's dicts do.
	type hourGroup struct {
		hours [2]int
		days  [7]bool
	}
	var byHours []*hourGroup
	for _, p := range pieces {
		kernelDay := floorMod(floorDiv(p[0]+kernelShift, minutesPerDay), 7)
		dayStart := p[0] - floorMod(p[0], minutesPerDay)
		hours := [2]int{(p[0] - dayStart) * 60, (p[1]-dayStart)*60 - 1}
		i := slices.IndexFunc(byHours, func(g *hourGroup) bool { return g.hours == hours })
		if i < 0 {
			byHours = append(byHours, &hourGroup{hours: hours})
			i = len(byHours) - 1
		}
		byHours[i].days[kernelDay] = true
	}
	type dayGroup struct {
		days   [7]bool
		ranges [][2]int
	}
	var byDays []*dayGroup
	for _, g := range byHours {
		i := slices.IndexFunc(byDays, func(d *dayGroup) bool { return d.days == g.days })
		if i < 0 {
			byDays = append(byDays, &dayGroup{days: g.days})
			i = len(byDays) - 1
		}
		byDays[i].ranges = append(byDays[i].ranges, g.hours)
	}

	var out []Segment
	for _, g := range byDays {
		ranges := slices.Clone(g.ranges)
		slices.SortFunc(ranges, func(x, y [2]int) int { return cmpPair(x, y) })
		var merged [][2]int
		for _, r := range ranges {
			if n := len(merged); n > 0 && r[0] <= merged[n-1][1]+1 {
				merged[n-1][1] = max(merged[n-1][1], r[1])
			} else {
				merged = append(merged, r)
			}
		}
		var names []string
		count := 0
		for d, on := range g.days {
			if on {
				names = append(names, WeekdayNames[d])
				count++
			}
		}
		if count == 7 {
			names = nil
		}
		for _, r := range merged {
			seg := Segment{Days: names}
			if r != [2]int{0, minutesPerDay*60 - 1} {
				hours := r
				seg.Hours = &hours
			}
			out = append(out, seg)
		}
	}
	// sorted(key=(hours or (0, 0), days or ())): stable, as Python's.
	slices.SortStableFunc(out, func(x, y Segment) int {
		hx, hy := [2]int{}, [2]int{}
		if x.Hours != nil {
			hx = *x.Hours
		}
		if y.Hours != nil {
			hy = *y.Hours
		}
		if c := cmpPair(hx, hy); c != 0 {
			return c
		}
		return slices.Compare(x.Days, y.Days)
	})
	return out
}

func cmpPair(x, y [2]int) int {
	if c := x[0] - y[0]; c != 0 {
		return c
	}
	return x[1] - y[1]
}

// midnights are the minutes t with a < t < b where the clock UTC + shift
// reads 00:00.
func midnights(a, b, shift int) []int {
	var out []int
	for t := (floorDiv(a+shift, minutesPerDay)+1)*minutesPerDay - shift; t < b; t += minutesPerDay {
		out = append(out, t)
	}
	return out
}

// SegmentMatches is what the kernel decides for one segment at a UTC
// minute of the week (nft_meta_weekday, nft_meta_hour). For tests.
func SegmentMatches(s Segment, utcMinuteOfWeek int, clock Clock) bool {
	t := floorMod(utcMinuteOfWeek, minutesPerWeek)
	if s.Days != nil {
		kernelDay := floorMod(floorDiv(t-clock.KernelMinutesWest, minutesPerDay), 7)
		if !slices.Contains(s.Days, WeekdayNames[kernelDay]) {
			return false
		}
	}
	if s.Hours != nil {
		second := floorMod(t, minutesPerDay) * 60
		if second < s.Hours[0] || second > s.Hours[1] {
			return false
		}
	}
	return true
}
