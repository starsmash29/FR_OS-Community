package config

import (
	"math"
	"math/big"
	"strconv"
	"strings"
)

// Python's builtins for the other packages of this module: the
// apply-helper answers with 1.x's messages and reads 1.x's files (the
// pending-apply record, Kea's leases) as 1.x reads them.

// Repr is repr(v).
func Repr(v Value) string { return repr(v) }

// Str is str(v).
func Str(v Value) string { return pyStr(v) }

// PyStrip is str.strip().
func PyStrip(s string) string { return pyStrip(s) }

// PyLower is str.lower().
func PyLower(s string) string { return pyLower(s) }

// Truthy is bool(v).
func Truthy(v Value) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case *big.Int:
		return x.Sign() != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []Value:
		return len(x) > 0
	case *Map:
		return x.Len() > 0
	}
	return true
}

// numberSpace is the whitespace int() and float() skip around a number:
// str.isspace() but for the ASCII separators \x1c-\x1f.
func numberSpace(r rune) bool { return pyIsSpace(r) && (r < 0x1c || r > 0x1f) }

// PyInt is int(s) for a str: surrounding whitespace, a sign, decimal
// digits of any script, and single underscores between digits.
func PyInt(s string) (*big.Int, bool) {
	s = strings.TrimFunc(s, numberSpace)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg, s = s[0] == '-', s[1:]
	}
	var digits strings.Builder
	prevDigit := false
	for _, r := range s {
		if r == '_' {
			if !prevDigit {
				return nil, false
			}
			prevDigit = false
			continue
		}
		d, ok := decimalValue(r)
		if !ok {
			return nil, false
		}
		digits.WriteByte(byte('0' + d))
		prevDigit = true
	}
	if !prevDigit {
		return nil, false // empty, or ends in "_"
	}
	n, _ := new(big.Int).SetString(digits.String(), 10)
	if neg {
		n.Neg(n)
	}
	return n, true
}

// PyFloat is float(s) for a str: a decimal number with an optional
// exponent, or inf, infinity or nan, any case, with a sign, surrounding
// whitespace and single underscores between digits. Digits of other
// scripts count, as in int().
func PyFloat(s string) (float64, bool) {
	s = strings.TrimFunc(s, numberSpace)
	var b strings.Builder
	for _, r := range s {
		if d, ok := decimalValue(r); ok {
			r = rune('0' + d)
		}
		b.WriteRune(r)
	}
	text := b.String()
	body := strings.TrimLeft(text, "+-")
	if len(text)-len(body) > 1 {
		return 0, false
	}
	switch strings.ToLower(body) {
	case "inf", "infinity":
		if strings.HasPrefix(text, "-") {
			return math.Inf(-1), true
		}
		return math.Inf(1), true
	case "nan":
		return math.NaN(), true
	}
	// Python's grammar: digits with single underscores between them, an
	// optional fraction, an optional exponent. Go's ParseFloat also takes
	// hex floats and other forms, so check the shape here first.
	var clean strings.Builder
	digitsSeen, inExp, expDigits := false, false, false
	last := byte(0)
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			if inExp {
				expDigits = true
			} else {
				digitsSeen = true
			}
		case c == '_':
			if last < '0' || last > '9' || i+1 == len(body) || body[i+1] < '0' || body[i+1] > '9' {
				return 0, false
			}
			last = c
			continue
		case c == '.':
			if inExp || strings.Contains(clean.String(), ".") {
				return 0, false
			}
		case c == 'e' || c == 'E':
			if inExp || !digitsSeen {
				return 0, false
			}
			inExp = true
		case (c == '+' || c == '-') && (last == 'e' || last == 'E'):
		default:
			return 0, false
		}
		clean.WriteByte(c)
		last = c
	}
	if !digitsSeen || (inExp && !expDigits) {
		return 0, false
	}
	f, err := strconv.ParseFloat(text[:len(text)-len(body)]+clean.String(), 64)
	if err != nil && !isRangeErr(err) {
		return 0, false
	}
	return f, true
}

// PySplit is str.split(): runs of whitespace separate, none at the ends.
func PySplit(s string) []string { return strings.FieldsFunc(s, pyIsSpace) }

// PySplitlines is str.splitlines(): every line boundary Python knows
// (\n, \r, \r\n, \v, \f, \x1c-\x1e, \x85,  ,  ), the
// boundaries dropped, no empty last line.
func PySplitlines(s string) []string {
	var lines []string
	rs := []rune(s)
	var cur []rune
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch r {
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\u0085', ' ', ' ':
			lines = append(lines, string(cur))
			cur = cur[:0]
		case '\r':
			lines = append(lines, string(cur))
			cur = cur[:0]
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
		default:
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		lines = append(lines, string(cur))
	}
	return lines
}
