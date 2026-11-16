package version

import (
	"regexp"
	"strings"
)

// The versions a release can have: 1.x's MAJOR.MINOR.PATCH (with or
// without a leading "v"), and FR_OS 2's beta form MAJOR.MINOR.PATCH-beta.N,
// which 1.x has no word for (decisions.md, "phase 4f-4b"). Only ASCII
// digits: a version names directories the updater creates and removes as
// root (security-lessons F1).
var releaseFormRE = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-beta\.([0-9]+))?$`)

// Release is a parsed release version. Beta is "" for a final release.
type Release struct {
	Major, Minor, Patch, Beta string
}

// ParseRelease reads a release version, ok false for anything else (no
// spaces or newlines around it: 1.x's parse_version doesn't strip).
func ParseRelease(text string) (Release, bool) {
	m := releaseFormRE.FindStringSubmatch(text)
	if m == nil {
		return Release{}, false
	}
	r := Release{trimZeros(m[1]), trimZeros(m[2]), trimZeros(m[3]), ""}
	if m[4] != "" {
		r.Beta = trimZeros(m[4])
	}
	return r, true
}

// IsBeta is whether r is a beta of its MAJOR.MINOR.PATCH.
func (r Release) IsBeta() bool { return r.Beta != "" }

// Compare orders releases as numbers (1.x's tuples of ints): -1 when r
// comes before o, 0 for the same release, 1 after. A beta comes before
// its final release, and the betas of one release in their numbers'
// order: 2.0.0-beta.1 < 2.0.0-beta.2 < 2.0.0 < 2.0.1.
func (r Release) Compare(o Release) int {
	for _, d := range [][2]string{{r.Major, o.Major}, {r.Minor, o.Minor}, {r.Patch, o.Patch}} {
		if c := compareDigits(d[0], d[1]); c != 0 {
			return c
		}
	}
	switch {
	case r.Beta == o.Beta:
		return 0
	case r.Beta == "":
		return 1
	case o.Beta == "":
		return -1
	}
	return compareDigits(r.Beta, o.Beta)
}

// compareDigits compares two decimal numbers without leading zeros, of
// any length (Python's ints have no limit).
func compareDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
