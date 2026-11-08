package config

import (
	"fmt"
	"math"
	"math/big"
	"slices"
	"strings"
)

// PyJSON is Python's json.dumps(v, indent=indent, sort_keys=sortKeys)
// for a value parsed from JSON (ParseJSON): what 1.x writes back into a
// state file it read, key order and number forms included. indent < 0
// is json.dumps's default, one line with ", " and ": ".
func PyJSON(v Value, indent int, sortKeys bool) (string, error) {
	var b strings.Builder
	if err := writePyJSON(&b, v, indent, sortKeys, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writePyJSON(b *strings.Builder, v Value, indent int, sortKeys bool, depth int) error {
	newline := func(d int) {
		if indent >= 0 {
			b.WriteByte('\n')
			b.WriteString(strings.Repeat(" ", indent*d))
		}
	}
	sep := ", "
	if indent >= 0 {
		sep = ","
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case *big.Int:
		b.WriteString(x.String())
	case float64:
		switch {
		case math.IsNaN(x):
			b.WriteString("NaN")
		case math.IsInf(x, 1):
			b.WriteString("Infinity")
		case math.IsInf(x, -1):
			b.WriteString("-Infinity")
		default:
			b.WriteString(floatRepr(x))
		}
	case string:
		b.WriteString(PyJSONString(x))
	case []Value:
		if len(x) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteString(sep)
			}
			newline(depth + 1)
			if err := writePyJSON(b, item, indent, sortKeys, depth+1); err != nil {
				return err
			}
		}
		newline(depth)
		b.WriteByte(']')
	case *Map:
		if x.Len() == 0 {
			b.WriteString("{}")
			return nil
		}
		order := make([]int, x.Len())
		for i := range order {
			order[i] = i
		}
		keys := x.Keys()
		if sortKeys {
			for _, k := range keys {
				if _, ok := k.(string); !ok {
					return fmt.Errorf("'<' not supported between instances of %s keys", pyTypeName(k))
				}
			}
			slices.SortStableFunc(order, func(i, j int) int { return strings.Compare(keys[i].(string), keys[j].(string)) })
		}
		b.WriteByte('{')
		for n, i := range order {
			if n > 0 {
				b.WriteString(sep)
			}
			newline(depth + 1)
			key, ok := keys[i].(string)
			if !ok {
				return fmt.Errorf("keys must be str, not %s", pyTypeName(keys[i]))
			}
			b.WriteString(PyJSONString(key))
			b.WriteString(": ")
			if err := writePyJSON(b, x.Values()[i], indent, sortKeys, depth+1); err != nil {
				return err
			}
		}
		newline(depth)
		b.WriteByte('}')
	default:
		return fmt.Errorf("Object of type %s is not JSON serializable", pyTypeName(v))
	}
	return nil
}

// PyJSONString is a str as json.dumps writes it (ensure_ascii): the
// escapes JSON has names for, and \uXXXX for every other control
// character and everything past ASCII.
func PyJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r <= 0xffff):
				fmt.Fprintf(&b, `\u%04x`, r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func pyTypeName(v Value) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case *big.Int:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []Value:
		return "list"
	case *Map:
		return "dict"
	}
	return "object"
}
