package config

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// FlowYAML writes a value LoadYAML built as one line of flow-style YAML
// that yaml.safe_load (and LoadYAML) reads back to the same value: every
// string double-quoted with everything outside printable ASCII escaped,
// floats in the forms YAML 1.1 resolves as floats, dates and times as
// timestamps. 1.x writes the parser daemons' config copy with PyYAML's
// block-style safe_dump; FR_OS 2 writes this instead
// (testdata/reference/decisions.md, "The sensors' config copy"): the
// daemons read the same data.
func FlowYAML(v Value) (string, error) {
	var b strings.Builder
	if err := writeFlow(&b, v, map[any]bool{}); err != nil {
		return "", err
	}
	return b.String(), nil
}

var errRecursive = errors.New("config: a value that contains itself")

func writeFlow(b *strings.Builder, v Value, seen map[any]bool) error {
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
		b.WriteString(yamlFloatText(x))
	case string:
		b.WriteString(yamlQuoted(x))
	case Date:
		b.WriteString(x.str())
	case Datetime:
		b.WriteString(x.str())
	case []Value:
		if len(x) > 0 {
			key := &x[0]
			if seen[key] {
				return errRecursive
			}
			seen[key] = true
			defer delete(seen, key)
		}
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := writeFlow(b, item, seen); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Map:
		if seen[x] {
			return errRecursive
		}
		seen[x] = true
		defer delete(seen, x)
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			if err := writeFlow(b, k, seen); err != nil {
				return err
			}
			b.WriteString(": ")
			if err := writeFlow(b, x.vals[i], seen); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("config: cannot write a %T as YAML", v)
	}
	return nil
}

// yamlFloatText is PyYAML's represent_float: repr, with a ".0" a float
// needs in YAML 1.1 before an exponent.
func yamlFloatText(f float64) string {
	switch {
	case math.IsNaN(f):
		return ".nan"
	case math.IsInf(f, 1):
		return ".inf"
	case math.IsInf(f, -1):
		return "-.inf"
	}
	text := floatRepr(f)
	if !strings.Contains(text, ".") && strings.Contains(text, "e") {
		text = strings.Replace(text, "e", ".0e", 1)
	}
	return text
}

// yamlQuoted is s double-quoted: printable ASCII as it is (but `"` and
// `\`), everything else escaped.
func yamlQuoted(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
