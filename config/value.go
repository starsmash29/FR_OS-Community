package config

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// A Value is one node of a raw config, as the YAML or JSON parser hands
// it over, before any checking: nil, bool, *big.Int, float64, string,
// []Value or *Map. 1.x checks the Python objects PyYAML builds, so the
// checks here keep Python's distinctions: an integer is not a float, a
// bool is also an integer unless a check says otherwise, and integers
// have no size limit.
type Value any

// Map is a mapping that keeps its keys in the order they were written:
// 1.x walks zones, interfaces and the rest in that order, and it shows in
// the first error reported and in the order of the ruleset. A key is any
// hashable Value (YAML allows `30:` or `2026-01-01:` as a key), and keys
// equal in Python are one key: 1, 1.0 and True are the same.
type Map struct {
	keys  []Value
	vals  []Value
	index map[string]int
}

// NewMap is an empty Map.
func NewMap() *Map { return &Map{index: map[string]int{}} }

// Set adds a string key, or replaces its value in place (a later
// duplicate wins, as in a Python dict).
func (m *Map) Set(key string, v Value) { m.SetKey(key, v) }

// SetKey is Set for any hashable key: the first key object stays (as in
// a Python dict), the last value wins. It reports false for a key Python
// can't hash (a list or a mapping).
func (m *Map) SetKey(key Value, v Value) bool {
	h, ok := keyOf(key)
	if !ok {
		return false
	}
	if i, ok := m.index[h]; ok {
		m.vals[i] = v
		return true
	}
	m.index[h] = len(m.keys)
	m.keys = append(m.keys, key)
	m.vals = append(m.vals, v)
	return true
}

// Get is the value at a string key, and whether it is there at all (a
// key set to null is there).
func (m *Map) Get(key string) (Value, bool) {
	if i, ok := m.index["s"+key]; ok {
		return m.vals[i], true
	}
	return nil, false
}

// Has is `key in m`.
func (m *Map) Has(key string) bool { _, ok := m.index["s"+key]; return ok }

// Keys are the keys in order.
func (m *Map) Keys() []Value { return m.keys }

// Values are the values, in the order of Keys.
func (m *Map) Values() []Value { return m.vals }

// Len is the number of keys.
func (m *Map) Len() int { return len(m.keys) }

// get is Python's dict.get(key, def).
func (m *Map) get(key string, def Value) Value {
	if v, ok := m.Get(key); ok {
		return v
	}
	return def
}

// getOr is `m.get(key, def) or def`: a falsy value counts as missing.
func (m *Map) getOr(key string, def Value) Value {
	if v := m.get(key, def); truthy(v) {
		return v
	}
	return def
}

// keyOf is a Value's identity as a dict key: equal for values Python
// finds equal (and hashes alike), false for an unhashable one.
func keyOf(v Value) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "n", true
	case bool:
		if x {
			return "i1", true
		}
		return "i0", true
	case *big.Int:
		return "i" + x.String(), true
	case float64:
		switch {
		case math.IsNaN(x):
			// PyYAML returns one NaN object for every .nan, so they are
			// one key.
			return "nan", true
		case math.IsInf(x, 0):
			return "f" + floatRepr(x), true
		case x == math.Trunc(x):
			n, _ := new(big.Float).SetFloat64(x).Int(nil)
			return "i" + n.String(), true
		}
		return "f" + strconv.FormatFloat(x, 'g', -1, 64), true
	case string:
		return "s" + x, true
	case Date:
		return fmt.Sprintf("d%d-%d-%d", x.Year, x.Month, x.Day), true
	case *unsupported:
		return fmt.Sprintf("u%p", x), x.hashable
	case Datetime:
		if x.Aware {
			return fmt.Sprintf("T%d", x.utcMicros()), true
		}
		return fmt.Sprintf("t%d-%d-%d-%d-%d-%d-%d", x.Year, x.Month, x.Day, x.Hour, x.Minute, x.Second, x.Micro), true
	}
	return "", false
}

// ParseJSON reads a raw config from JSON, keeping key order. Numbers
// written without a fraction or exponent are integers, as Python's json
// module reads them.
func ParseJSON(data []byte) (Value, error) {
	dec := jsontext.NewDecoder(bytes.NewReader(data))
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.ReadToken(); err == nil {
		return nil, fmt.Errorf("config: trailing data after the JSON value")
	}
	return v, nil
}

func decodeValue(dec *jsontext.Decoder) (Value, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return nil, err
	}
	switch tok.Kind() {
	case 'n':
		return nil, nil
	case 't':
		return true, nil
	case 'f':
		return false, nil
	case '"':
		return tok.String(), nil
	case '0':
		text := tok.String()
		if !strings.ContainsAny(text, ".eE") {
			n, ok := new(big.Int).SetString(text, 10)
			if !ok {
				return nil, fmt.Errorf("config: bad integer %q", text)
			}
			return n, nil
		}
		f, err := strconv.ParseFloat(text, 64)
		if err != nil {
			return nil, fmt.Errorf("config: bad number %q", text)
		}
		return f, nil
	case '[':
		out := []Value{}
		for dec.PeekKind() != ']' {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		_, err := dec.ReadToken()
		return out, err
	case '{':
		m := NewMap()
		for dec.PeekKind() != '}' {
			k, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			key := k.String() // before the next read voids the token
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			m.Set(key, v)
		}
		_, err := dec.ReadToken()
		return m, err
	}
	return nil, fmt.Errorf("config: unexpected JSON token %v", tok)
}

// Date is a datetime.date: YAML's own timestamp without a time.
type Date struct{ Year, Month, Day int }

// Datetime is a datetime.datetime from YAML's own timestamp: naive, or
// Aware with Offset seconds east of UTC.
type Datetime struct {
	Year, Month, Day            int
	Hour, Minute, Second, Micro int
	Aware                       bool
	Offset                      int
}

func (d Datetime) moment() isoMoment {
	return isoMoment{
		year: d.Year, month: d.Month, day: d.Day, hour: d.Hour, minute: d.Minute, second: d.Second, usec: d.Micro,
		hasOffset: d.Aware, offsetUsec: int64(d.Offset) * 1e6,
	}
}

// utcMicros is an aware Datetime's instant, in microseconds.
func (d Datetime) utcMicros() int64 {
	m := d.moment()
	return m.wallSeconds()*1e6 + int64(d.Micro) - m.offsetUsec
}

// tzRepr is repr(tzinfo) for a fixed offset.
func tzRepr(offset int) string {
	if offset == 0 {
		return "datetime.timezone.utc"
	}
	days, secs := offset/86400, offset%86400
	if secs < 0 {
		days, secs = days-1, secs+86400
	}
	var parts []string
	if days != 0 {
		parts = append(parts, fmt.Sprintf("days=%d", days))
	}
	if secs != 0 {
		parts = append(parts, fmt.Sprintf("seconds=%d", secs))
	}
	return "datetime.timezone(datetime.timedelta(" + strings.Join(parts, ", ") + "))"
}

func (d Date) str() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, d.Month, d.Day) }

// str is str(datetime): isoformat with a space.
func (d Datetime) str() string {
	s := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", d.Year, d.Month, d.Day, d.Hour, d.Minute, d.Second)
	if d.Micro != 0 {
		s += fmt.Sprintf(".%06d", d.Micro)
	}
	if d.Aware {
		sign, off := '+', d.Offset
		if off < 0 {
			sign, off = '-', -off
		}
		s += fmt.Sprintf("%c%02d:%02d", sign, off/3600, off%3600/60)
	}
	return s
}

// truthy is Python's bool(v).
func truthy(v Value) bool {
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

// isInt is isinstance(v, int), which a bool also is.
func isInt(v Value) bool {
	switch v.(type) {
	case *big.Int, bool:
		return true
	}
	return false
}

// strictInt is `isinstance(v, int) and not isinstance(v, bool)`.
func strictInt(v Value) (*big.Int, bool) {
	n, ok := v.(*big.Int)
	return n, ok
}

// intOf is the integer value of an int or a bool.
func intOf(v Value) *big.Int {
	switch x := v.(type) {
	case *big.Int:
		return x
	case bool:
		if x {
			return big.NewInt(1)
		}
		return big.NewInt(0)
	}
	return nil
}

// intIn is lo <= v <= hi for an int or a bool.
func intIn(v Value, lo, hi int64) bool {
	n := intOf(v)
	return n != nil && n.Cmp(big.NewInt(lo)) >= 0 && n.Cmp(big.NewInt(hi)) <= 0
}

// numEq is Python's `v == n` for a number n: 1, 1.0 and True are equal.
func numEq(v Value, n int64) bool {
	switch x := v.(type) {
	case *big.Int, bool:
		return intOf(x).Cmp(big.NewInt(n)) == 0
	case float64:
		return x == float64(n)
	}
	return false
}

// pyStr is Python's str(v) for the values a check prints that way.
func pyStr(v Value) string {
	switch x := v.(type) {
	case string:
		return x
	case Date:
		return x.str()
	case Datetime:
		return x.str()
	}
	return repr(v)
}

// repr is Python's repr(v), for messages: they say what 1.x says.
func repr(v Value) string {
	var b strings.Builder
	writeRepr(&b, v)
	return b.String()
}

func writeRepr(b *strings.Builder, v Value) {
	switch x := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if x {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		b.WriteString(floatRepr(x))
	case string:
		b.WriteString(strRepr(x))
	case []Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			writeRepr(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(strRepr(e))
		}
		b.WriteByte(']')
	case *Map:
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			writeRepr(b, k)
			b.WriteString(": ")
			writeRepr(b, x.vals[i])
		}
		b.WriteByte('}')
	case Date:
		fmt.Fprintf(b, "datetime.date(%d, %d, %d)", x.Year, x.Month, x.Day)
	case Datetime:
		fmt.Fprintf(b, "datetime.datetime(%d, %d, %d, %d, %d", x.Year, x.Month, x.Day, x.Hour, x.Minute)
		if x.Micro != 0 {
			fmt.Fprintf(b, ", %d, %d", x.Second, x.Micro)
		} else if x.Second != 0 {
			fmt.Fprintf(b, ", %d", x.Second)
		}
		if x.Aware {
			b.WriteString(", tzinfo=" + tzRepr(x.Offset))
		}
		b.WriteByte(')')
	default:
		fmt.Fprintf(b, "%v", x)
	}
}

// floatRepr is Python's repr of a float: the shortest digits that read
// back the same, positional between 1e-4 and 1e16, with ".0" on a whole
// number.
func floatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	mant, expText, _ := strings.Cut(s, "e")
	exp, _ := strconv.Atoi(expText)
	neg := strings.HasPrefix(mant, "-")
	mant = strings.TrimPrefix(mant, "-")
	digits := strings.Replace(mant, ".", "", 1)
	decpt := exp + 1
	var out string
	if decpt <= -4 || decpt > 16 {
		out = digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		sign := "+"
		if exp < 0 {
			sign, exp = "-", -exp
		}
		out += fmt.Sprintf("e%s%02d", sign, exp)
	} else if decpt <= 0 {
		out = "0." + strings.Repeat("0", -decpt) + digits
	} else if decpt >= len(digits) {
		out = digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	} else {
		out = digits[:decpt] + "." + digits[decpt:]
	}
	if neg {
		out = "-" + out
	}
	return out
}

// strRepr is Python's repr of a str.
func strRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7f:
			b.WriteRune(r)
		case !strconv.IsPrint(r):
			switch {
			case r <= 0xff:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// pySort is Python's sorted() for dict keys, in place. Distinct keys
// are never equal, so any sort gives Python's order, except with a NaN,
// which Python orders by how its sort happens to compare. Keys Python
// can't compare (a string and a number, a date and a datetime, None and
// anything) make sorted() raise TypeError: they are left as they are,
// and the caller's error stands.
func pySort(vals []Value) bool {
	if len(vals) < 2 {
		return true
	}
	class := func(v Value) string {
		switch x := v.(type) {
		case string:
			return "str"
		case bool, *big.Int, float64:
			return "num"
		case Date:
			return "date"
		case Datetime:
			if x.Aware {
				return "aware"
			}
			return "naive"
		}
		return "other"
	}
	c := class(vals[0])
	for _, v := range vals[1:] {
		if class(v) != c {
			return false
		}
	}
	var less func(a, b Value) bool
	switch c {
	case "str":
		less = func(a, b Value) bool { return a.(string) < b.(string) }
	case "num":
		num := func(v Value) *big.Float {
			if f, ok := v.(float64); ok {
				return new(big.Float).SetFloat64(f)
			}
			return new(big.Float).SetInt(intOf(v))
		}
		less = func(a, b Value) bool {
			fa, fb := a, b
			if x, ok := fa.(float64); ok && math.IsNaN(x) {
				return false
			}
			if x, ok := fb.(float64); ok && math.IsNaN(x) {
				return false
			}
			return num(a).Cmp(num(b)) < 0
		}
	case "date":
		less = func(a, b Value) bool { return a.(Date).str() < b.(Date).str() }
	case "naive":
		less = func(a, b Value) bool {
			x, y := a.(Datetime), b.(Datetime)
			return x.moment().wallSeconds()*1e6+int64(x.Micro) < y.moment().wallSeconds()*1e6+int64(y.Micro)
		}
	case "aware":
		less = func(a, b Value) bool { return a.(Datetime).utcMicros() < b.(Datetime).utcMicros() }
	default:
		return false
	}
	sort.SliceStable(vals, func(i, j int) bool { return less(vals[i], vals[j]) })
	return true
}
