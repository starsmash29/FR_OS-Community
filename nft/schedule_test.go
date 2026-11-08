package nft

import (
	"math/rand/v2"
	"testing"
)

// TestSegmentsCoverTheSchedule checks the rendered segments against the
// schedule's meaning, minute by minute over a week: the kernel matches a
// segment (SegmentMatches) exactly when the schedule is on in local time
// (IsActive), whatever the zone's offset and the kernel's own zone.
func TestSegmentsCoverTheSchedule(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	clocks := []Clock{{0, 0}, {120, -120}, {60, 0}, {-300, 300}, {330, 0}, {345, -345}, {-570, 570}, {840, -840}, {0, -120}}
	for n := 0; n < 300; n++ {
		var days []int
		for d := 0; d < 7; d++ {
			if rng.IntN(2) == 0 {
				days = append(days, d)
			}
		}
		if len(days) == 0 {
			days = []int{rng.IntN(7)}
		}
		start := rng.IntN(1440)
		end := rng.IntN(1441)
		if end == start {
			end = 1440
		}
		clock := clocks[rng.IntN(len(clocks))]
		segs := Segments(days, start, end, clock)
		for utc := 0; utc < minutesPerWeek; utc++ {
			want := IsActive(days, start, end, utc+clock.UTCOffsetMinutes)
			got := false
			for _, s := range segs {
				got = got || SegmentMatches(s, utc, clock)
			}
			if got != want {
				t.Fatalf("days %v %d-%d, clock %+v: UTC minute %d of the week: kernel %v, schedule %v (%v)",
					days, start, end, clock, utc, got, want, segs)
			}
		}
	}
}

func TestSegmentRender(t *testing.T) {
	// Every day, 22:00-06:00 at UTC+1: one piece either side of midnight.
	segs := Segments([]int{0, 1, 2, 3, 4, 5, 6}, 22*60, 6*60, Clock{UTCOffsetMinutes: 60})
	var got []string
	for _, s := range segs {
		got = append(got, s.render())
	}
	want := []string{`meta hour "00:00:00"-"04:59:59"`, `meta hour "21:00:00"-"23:59:59"`}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q", got)
	}
	// The whole week is no match at all.
	if s := Segments([]int{0, 1, 2, 3, 4, 5, 6}, 0, 1440, Clock{}); len(s) != 1 || s[0].render() != "" {
		t.Fatalf("got %+v", s)
	}
	if s := Segments([]int{0}, 0, 1440, Clock{}); len(s) != 1 || s[0].render() != `meta day "Monday"` {
		t.Fatalf("got %+v", s)
	}
}

func TestFloor(t *testing.T) {
	for _, c := range [][4]int{{7, 2, 3, 1}, {-7, 2, -4, 1}, {7, -2, -4, -1}, {-7, -2, 3, -1}, {-6, 3, -2, 0}} {
		if floorDiv(c[0], c[1]) != c[2] || floorMod(c[0], c[1]) != c[3] {
			t.Errorf("%d, %d: %d %d", c[0], c[1], floorDiv(c[0], c[1]), floorMod(c[0], c[1]))
		}
	}
}
