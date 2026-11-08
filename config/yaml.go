package config

import (
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/starsmash29/fr_os-community/internal/pyyaml"
)

// MaxConfigBytes is the largest config.yaml ReadFile reads (AGENTS.md:
// every read has a size limit). 1.x reads any size; a router's config is
// a few kilobytes, its longest lists a few thousand names.
const MaxConfigBytes = 4 << 20

// ReadFile is 1.x's read_config: the checked config at path, and the
// text it was read from (an apply records that text, ROADMAP SEC-5).
func ReadFile(path string) (*Config, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > MaxConfigBytes {
		return nil, "", &Error{Msg: fmt.Sprintf("Invalid YAML in %s: config: larger than %d bytes", path, MaxConfigBytes)}
	}
	// Path.read_text() reads in universal-newline mode: "\r\n" and a
	// lone "\r" are "\n" before YAML sees them.
	text := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	raw, err := LoadYAML(text)
	if err != nil {
		return nil, "", &Error{Msg: fmt.Sprintf("Invalid YAML in %s: %s", path, err)}
	}
	c, err := Parse(raw)
	if err != nil {
		return nil, "", err
	}
	return c, text, nil
}

// LoadYAML is yaml.safe_load(text) for PyYAML 6.0.1: the value 1.x's
// checks see. Errors read as str() of PyYAML's exception. Where 1.x
// would crash instead (an exception that isn't a YAMLError, such as
// `!!int x`), and where testdata/reference/decisions.md says so, the text
// is refused with a message of FR_OS 2's own.
func LoadYAML(text string) (v Value, err error) {
	root, err := pyyaml.Load(text)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return nil, nil
	}
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *pyyaml.MarkedError:
				err = e
			case *pyyaml.LimitError:
				err = e
			default:
				panic(r)
			}
			v = nil
		}
	}()
	c := &constructor{done: map[*pyyaml.Node]Value{}}
	data := c.object(root)
	for len(c.pending) > 0 {
		round := c.pending
		c.pending = nil
		for _, fill := range round {
			fill()
		}
	}
	out := unbox(data, map[*seqBox][]Value{}, map[*Map]bool{})
	if tag := findUnsupported(out); tag != "" {
		// decisions.md: no config value is bytes, a set or pairs.
		crash("the YAML tag !!%s is not supported", strings.TrimPrefix(tag, yamlTag))
	}
	return out, nil
}

// unsupported stands for what PyYAML builds for !!binary (bytes, which
// Python can hash), !!set (a set), !!omap and !!pairs (lists of pairs):
// they are built and checked as PyYAML does, so its errors come out the
// same, and a text that still holds one is refused at the end.
type unsupported struct {
	tag      string
	hashable bool
}

func findUnsupported(v Value) string {
	switch x := v.(type) {
	case *unsupported:
		return x.tag
	case []Value:
		for _, e := range x {
			if t := findUnsupported(e); t != "" {
				return t
			}
		}
	case *Map:
		for i := range x.keys {
			if t := findUnsupported(x.keys[i]); t != "" {
				return t
			}
			if t := findUnsupported(x.vals[i]); t != "" {
				return t
			}
		}
	}
	return ""
}

// pairs is construct_yaml_omap and construct_yaml_pairs, after the
// empty list is handed out.
func (c *constructor) pairs(n *pyyaml.Node) {
	context := "while constructing an ordered map"
	if n.Tag == yamlTag+"pairs" {
		context = "while constructing pairs"
	}
	if n.Kind != pyyaml.SequenceNode {
		constructorError(context, n.Start, n, "expected a sequence, but found %s", n.Kind.ID())
	}
	for _, sub := range n.Items {
		if sub.Kind != pyyaml.MappingNode {
			constructorError(context, n.Start, sub, "expected a mapping of length 1, but found %s", sub.Kind.ID())
		}
		if len(sub.Pairs) != 1 {
			constructorError(context, n.Start, sub, "expected a single mapping item, but found %d items", len(sub.Pairs))
		}
		c.object(sub.Pairs[0][0])
		c.object(sub.Pairs[0][1])
	}
}

// binary is construct_yaml_binary: base64.decodebytes (Python 3.13's
// binascii.a2b_base64, not strict), which skips characters outside the
// alphabet and reads on after the padding.
func (c *constructor) binary(n *pyyaml.Node) Value {
	text := c.scalar(n)
	runes := []rune(text)
	for i, r := range runes {
		if r < 0x80 {
			continue
		}
		end := i
		for end+1 < len(runes) && runes[end+1] >= 0x80 {
			end++
		}
		what := fmt.Sprintf("character '%s' in position %d", pyEscape(r), i)
		if end > i {
			what = fmt.Sprintf("characters in position %d-%d", i, end)
		}
		constructorError("", pyyaml.Mark{}, n,
			"failed to convert base64 data into ascii: 'ascii' codec can't encode %s: ordinal not in range(128)", what)
	}
	quad, pads, decoded := 0, 0, 0
	for i := 0; i < len(text); i++ {
		ch := text[i]
		if ch == '=' {
			if quad >= 2 {
				pads++
			}
			continue
		}
		if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '+' || ch == '/') {
			continue
		}
		pads = 0
		if quad > 0 {
			decoded++
		}
		quad = (quad + 1) % 4
	}
	switch {
	case quad == 1:
		constructorError("", pyyaml.Mark{}, n,
			"failed to decode base64 data: Invalid base64-encoded string: number of data characters (%d) cannot be 1 more than a multiple of 4",
			decoded/3*4+1)
	case quad != 0 && quad+pads < 4:
		constructorError("", pyyaml.Mark{}, n, "failed to decode base64 data: Incorrect padding")
	}
	return &unsupported{tag: n.Tag, hashable: true}
}

// The constructor (yaml.constructor.SafeConstructor). Python builds a
// list or a dict empty, hands it out, and fills it in a later round (a
// generator); errors come in that order, so the rounds are kept. A list
// is a seqBox until the end, so it can be filled after it is handed out.

type seqBox struct{ items []Value }

type constructor struct {
	done    map[*pyyaml.Node]Value
	pending []func()
}

const yamlTag = "tag:yaml.org,2002:"

func crash(format string, args ...any) {
	panic(&pyyaml.LimitError{Msg: "config: " + fmt.Sprintf(format, args...)})
}

func constructorError(context string, contextMark pyyaml.Mark, n *pyyaml.Node, format string, args ...any) {
	panic(pyyaml.Errorf(context, contextMark, n.Start, format, args...))
}

func (c *constructor) object(n *pyyaml.Node) Value {
	if v, ok := c.done[n]; ok {
		return v
	}
	var v Value
	switch n.Tag {
	case yamlTag + "null":
		c.scalar(n)
		v = nil
	case yamlTag + "bool":
		v = yamlBool(c.scalar(n))
	case yamlTag + "int":
		v = yamlInt(c.scalar(n))
	case yamlTag + "float":
		v = yamlFloat(c.scalar(n))
	case yamlTag + "timestamp":
		c.scalar(n)
		v = yamlTimestamp(n)
	case yamlTag + "str":
		v = c.scalar(n)
	case yamlTag + "seq":
		box := &seqBox{}
		v = box
		c.pending = append(c.pending, func() {
			if n.Kind != pyyaml.SequenceNode {
				constructorError("", pyyaml.Mark{}, n, "expected a sequence node, but found %s", n.Kind.ID())
			}
			box.items = make([]Value, 0, len(n.Items))
			for _, child := range n.Items {
				box.items = append(box.items, c.object(child))
			}
		})
	case yamlTag + "map":
		m := NewMap()
		v = m
		c.pending = append(c.pending, func() { c.mapping(n, m) })
	case yamlTag + "binary":
		v = c.binary(n)
	case yamlTag + "omap", yamlTag + "pairs":
		u := &unsupported{tag: n.Tag}
		v = u
		c.pending = append(c.pending, func() { c.pairs(n) })
	case yamlTag + "set":
		u := &unsupported{tag: n.Tag}
		v = u
		c.pending = append(c.pending, func() { c.mapping(n, NewMap()) })
	default:
		constructorError("", pyyaml.Mark{}, n, "could not determine a constructor for the tag %s", strRepr(n.Tag))
	}
	c.done[n] = v
	return v
}

// scalar is SafeConstructor.construct_scalar: a mapping with a `=` key
// stands for that key's value.
func (c *constructor) scalar(n *pyyaml.Node) string {
	if n.Kind == pyyaml.MappingNode {
		for _, kv := range n.Pairs {
			if kv[0].Tag == yamlTag+"value" {
				return c.scalar(kv[1])
			}
		}
	}
	if n.Kind != pyyaml.ScalarNode {
		constructorError("", pyyaml.Mark{}, n, "expected a scalar node, but found %s", n.Kind.ID())
	}
	return n.Value
}

// flatten is SafeConstructor.flatten_mapping: `<<` merges, in place on
// the node, as PyYAML does.
func flatten(n *pyyaml.Node) {
	var merge [][2]*pyyaml.Node
	for i := 0; i < len(n.Pairs); {
		key, value := n.Pairs[i][0], n.Pairs[i][1]
		switch key.Tag {
		case yamlTag + "merge":
			n.Pairs = append(n.Pairs[:i:i], n.Pairs[i+1:]...)
			switch value.Kind {
			case pyyaml.MappingNode:
				flatten(value)
				merge = append(merge, value.Pairs...)
			case pyyaml.SequenceNode:
				var sub [][][2]*pyyaml.Node
				for _, s := range value.Items {
					if s.Kind != pyyaml.MappingNode {
						constructorError("while constructing a mapping", n.Start, s, "expected a mapping for merging, but found %s", s.Kind.ID())
					}
					flatten(s)
					sub = append(sub, s.Pairs)
				}
				for j := len(sub) - 1; j >= 0; j-- {
					merge = append(merge, sub[j]...)
				}
			default:
				constructorError("while constructing a mapping", n.Start, value, "expected a mapping or list of mappings for merging, but found %s", value.Kind.ID())
			}
		case yamlTag + "value":
			key.Tag = yamlTag + "str"
			i++
		default:
			i++
		}
	}
	if len(merge) > 0 {
		n.Pairs = append(merge, n.Pairs...)
	}
}

func (c *constructor) mapping(n *pyyaml.Node, into *Map) {
	if n.Kind == pyyaml.MappingNode {
		flatten(n)
	}
	if n.Kind != pyyaml.MappingNode {
		constructorError("", pyyaml.Mark{}, n, "expected a mapping node, but found %s", n.Kind.ID())
	}
	for _, kv := range n.Pairs {
		key := c.object(kv[0])
		if _, ok := keyOf(key); !ok {
			constructorError("while constructing a mapping", n.Start, kv[0], "found unhashable key")
		}
		into.SetKey(key, c.object(kv[1]))
	}
}

// unbox turns seqBoxes into []Value, once each: a node reached by two
// aliases is one value, as in Python.
func unbox(v Value, seqs map[*seqBox][]Value, maps map[*Map]bool) Value {
	switch x := v.(type) {
	case *seqBox:
		if out, ok := seqs[x]; ok {
			return out
		}
		out := x.items
		seqs[x] = out
		for i, e := range out {
			out[i] = unbox(e, seqs, maps)
		}
		return out
	case *Map:
		if !maps[x] {
			maps[x] = true
			for i := range x.vals {
				x.vals[i] = unbox(x.vals[i], seqs, maps)
			}
			for i := range x.keys {
				x.keys[i] = unbox(x.keys[i], seqs, maps)
			}
		}
	}
	return v
}

var yamlBools = map[string]bool{"yes": true, "no": false, "true": true, "false": false, "on": true, "off": false}

func yamlBool(s string) bool {
	b, ok := yamlBools[pyLower(s)]
	if !ok {
		crash("%s is not a YAML boolean", strRepr(s)) // 1.x: KeyError
	}
	return b
}

// yamlInt is construct_yaml_int.
func yamlInt(s string) *big.Int {
	v := strings.ReplaceAll(s, "_", "")
	if v == "" {
		crash("%s is not a YAML integer", strRepr(s)) // 1.x: IndexError
	}
	sign := int64(1)
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '+' || v[0] == '-' {
		v = v[1:]
	}
	parse := func(text string, base int) *big.Int {
		n, ok := pyInt(text, base)
		if !ok {
			crash("%s is not a YAML integer", strRepr(s)) // 1.x: ValueError
		}
		return n
	}
	var n *big.Int
	switch {
	case v == "0":
		return big.NewInt(0)
	case strings.HasPrefix(v, "0b"):
		n = parse(v[2:], 2)
	case strings.HasPrefix(v, "0x"):
		n = parse(v[2:], 16)
	case v == "":
		crash("%s is not a YAML integer", strRepr(s)) // 1.x: IndexError
	case v[0] == '0':
		n = parse(v, 8)
	case strings.Contains(v, ":"):
		n = new(big.Int)
		base := big.NewInt(1)
		parts := strings.Split(v, ":")
		for i := len(parts) - 1; i >= 0; i-- {
			n.Add(n, new(big.Int).Mul(parse(parts[i], 10), base))
			base.Mul(base, big.NewInt(60))
		}
	default:
		n = parse(v, 10)
	}
	return n.Mul(n, big.NewInt(sign))
}

// pyInt is Python's int(s, base) for base 2, 8, 10 or 16, on a text
// without underscores: Unicode spaces around it, a sign, the base's
// prefix, and digits (any Unicode decimal digit counts as one).
func pyInt(s string, base int) (*big.Int, bool) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case pyIsSpace(r):
			b.WriteByte(' ')
		case r < 0x80:
			b.WriteRune(r)
		default:
			if d, ok := decimalValue(r); ok {
				b.WriteByte(byte('0' + d))
			} else {
				return nil, false
			}
		}
	}
	t := strings.Trim(b.String(), " \t\n\v\f\r")
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	if len(t) >= 2 && t[0] == '0' {
		p := t[1] | 0x20
		if (base == 16 && p == 'x') || (base == 8 && p == 'o') || (base == 2 && p == 'b') {
			t = t[2:]
		}
	}
	if t == "" {
		return nil, false
	}
	for _, c := range t {
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'z':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			d = int(c-'A') + 10
		default:
			return nil, false
		}
		if d >= base {
			return nil, false
		}
	}
	n, ok := new(big.Int).SetString(t, base)
	if !ok {
		return nil, false
	}
	if neg {
		n.Neg(n)
	}
	return n, true
}

// yamlFloat is construct_yaml_float.
func yamlFloat(s string) float64 {
	v := pyLower(strings.ReplaceAll(s, "_", ""))
	if v == "" {
		crash("%s is not a YAML float", strRepr(s)) // 1.x: IndexError
	}
	sign := 1.0
	if v[0] == '-' {
		sign = -1
	}
	if v[0] == '+' || v[0] == '-' {
		v = v[1:]
	}
	parse := func(text string) float64 {
		f, ok := pyFloat(text)
		if !ok {
			crash("%s is not a YAML float", strRepr(s)) // 1.x: ValueError
		}
		return f
	}
	switch {
	case v == ".inf":
		return sign * math.Inf(1)
	case v == ".nan":
		return math.NaN()
	case strings.Contains(v, ":"):
		parts := strings.Split(v, ":")
		value, base := 0.0, 1.0
		for i := len(parts) - 1; i >= 0; i-- {
			value += parse(parts[i]) * base
			base *= 60
		}
		return sign * value
	}
	return sign * parse(v)
}

var pyFloatRE = regexp.MustCompile(`\A[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|inf|infinity|nan)\z`)

// pyFloat is Python's float(s) on a lower-case text without
// underscores.
func pyFloat(s string) (float64, bool) {
	var b strings.Builder
	for _, r := range s {
		switch {
		case pyIsSpace(r):
			b.WriteByte(' ')
		case r < 0x80:
			b.WriteRune(r)
		default:
			if d, ok := decimalValue(r); ok {
				b.WriteByte(byte('0' + d))
			} else {
				return 0, false
			}
		}
	}
	t := strings.Trim(b.String(), " \t\n\v\f\r")
	if !pyFloatRE.MatchString(t) {
		return 0, false
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil && !isRangeErr(err) {
		return 0, false
	}
	return f, true // out of range: ±inf or 0, as Python
}

func isRangeErr(err error) bool {
	ne, ok := err.(*strconv.NumError)
	return ok && ne.Err == strconv.ErrRange
}

var timestampRE = regexp.MustCompile(`\A([0-9][0-9][0-9][0-9])-([0-9][0-9]?)-([0-9][0-9]?)(?:(?:[Tt]|[ \t]+)([0-9][0-9]?):([0-9][0-9]):([0-9][0-9])(?:\.([0-9]*))?(?:[ \t]*(Z|([-+])([0-9][0-9]?)(?::([0-9][0-9]))?))?)?\n?\z`)

// yamlTimestamp is construct_yaml_timestamp: a Date, or a Datetime.
func yamlTimestamp(n *pyyaml.Node) Value {
	if n.Kind != pyyaml.ScalarNode {
		crash("a YAML timestamp must be a scalar") // 1.x: TypeError
	}
	g := timestampRE.FindStringSubmatch(n.Value)
	if g == nil {
		crash("%s is not a YAML timestamp", strRepr(n.Value)) // 1.x: AttributeError
	}
	atoi := func(s string) int { v, _ := strconv.Atoi(s); return v }
	year, month, day := atoi(g[1]), atoi(g[2]), atoi(g[3])
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) {
		crash("%s is not a valid date", strRepr(n.Value)) // 1.x: ValueError
	}
	if g[4] == "" {
		return Date{year, month, day}
	}
	d := Datetime{Year: year, Month: month, Day: day, Hour: atoi(g[4]), Minute: atoi(g[5]), Second: atoi(g[6])}
	if d.Hour > 23 || d.Minute > 59 || d.Second > 59 {
		crash("%s is not a valid time", strRepr(n.Value)) // 1.x: ValueError
	}
	if frac := g[7]; frac != "" {
		if len(frac) > 6 {
			frac = frac[:6]
		}
		d.Micro = atoi(frac + strings.Repeat("0", 6-len(frac)))
	}
	switch {
	case g[9] != "":
		d.Aware = true
		d.Offset = atoi(g[10])*3600 + atoi(g[11])*60
		if g[9] == "-" {
			d.Offset = -d.Offset
		}
		if d.Offset <= -86400 || d.Offset >= 86400 {
			crash("%s has an offset of a day or more", strRepr(n.Value)) // 1.x: ValueError
		}
	case g[8] != "":
		d.Aware = true
	}
	return d
}

func daysIn(year, month int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// pyEscape is how a UnicodeEncodeError names a character.
func pyEscape(r rune) string {
	switch {
	case r <= 0xff:
		return fmt.Sprintf(`\x%02x`, r)
	case r <= 0xffff:
		return fmt.Sprintf(`\u%04x`, r)
	}
	return fmt.Sprintf(`\U%08x`, r)
}
