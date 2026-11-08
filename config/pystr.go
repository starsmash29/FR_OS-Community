package config

import (
	"strings"
	"unicode"
)

// Python's own idea of a few string operations, where it differs from
// Go's: 1.x's checks are written with them.

// pyIsSpace is str.isspace() for one character: Go's unicode.IsSpace
// plus the four ASCII separators \x1c-\x1f, which Python counts.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyStrip is str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

// pyLower is str.lower(). Go's ToLower maps one character to one; Python
// also applies the one unconditional multi-character mapping, U+0130
// (capital I with dot) to "i" + U+0307, so "İ" never becomes a plain "i".
func pyLower(s string) string {
	if !strings.ContainsRune(s, 'İ') {
		return strings.ToLower(s)
	}
	var b strings.Builder
	for _, r := range s {
		if r == 'İ' {
			b.WriteString("i̇")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// decimalValue is the value of a Unicode decimal digit (category Nd),
// which Python's `\d` matches and int() reads: digits come in runs of
// ten from zero, so it is the offset into its run.
func decimalValue(r rune) (int, bool) {
	for _, rg := range unicode.Nd.R16 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); r >= lo && r <= hi && rg.Stride == 1 {
			return int(r-lo) % 10, true
		}
	}
	for _, rg := range unicode.Nd.R32 {
		if lo, hi := rune(rg.Lo), rune(rg.Hi); r >= lo && r <= hi && rg.Stride == 1 {
			return int(r-lo) % 10, true
		}
	}
	return 0, false
}

// pyDecimal reads s, all decimal digits (`\d+`), as int() would.
func pyDecimal(s string) (int, bool) {
	n := 0
	for _, r := range s {
		d, ok := decimalValue(r)
		if !ok {
			return 0, false
		}
		n = n*10 + d
		if n > 1<<40 {
			n = 1 << 40 // far beyond any bound a caller checks
		}
	}
	return n, s != ""
}

func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
