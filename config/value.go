package config

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"math/big"
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
// the first error reported and in the order of the ruleset.
type Map struct {
	keys []string
	vals map[string]Value
}

// NewMap is an empty Map.
func NewMap() *Map { return &Map{vals: map[string]Value{}} }

// Set adds key, or replaces its value in place (a later duplicate wins,
// as in a Python dict).
func (m *Map) Set(key string, v Value) {
	if _, ok := m.vals[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.vals[key] = v
}

// Get is the value at key, and whether it is there at all (a key set to
// null is there).
func (m *Map) Get(key string) (Value, bool) {
	v, ok := m.vals[key]
	return v, ok
}

// Has is `key in m`.
func (m *Map) Has(key string) bool { _, ok := m.vals[key]; return ok }

// Keys are the keys in order.
func (m *Map) Keys() []string { return m.keys }

// Len is the number of keys.
func (m *Map) Len() int { return len(m.keys) }

// get is Python's dict.get(key, def).
func (m *Map) get(key string, def Value) Value {
	if v, ok := m.vals[key]; ok {
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
	if s, ok := v.(string); ok {
		return s
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
			b.WriteString(strRepr(k))
			b.WriteString(": ")
			writeRepr(b, x.vals[k])
		}
		b.WriteByte('}')
	default:
		fmt.Fprintf(b, "%v", x)
	}
}

// floatRepr is Python's repr of a float: the shortest digits that read
// back the same, positional between 1e-4 and 1e16, with ".0" on a whole
// number.
func floatRepr(f float64) string {
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
