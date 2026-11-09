package webui

import (
	"math/big"
	"strings"
	"unicode"
)

// pyIntResult is pydantic's int from a form string: the value, or the
// error type ("int_parsing", "int_parsing_size") when it refuses it.
//
// pydantic-core reads the string itself, not with Python's int(): it
// trims Unicode white space (not the ASCII separators \x1c-\x1f, which
// Python's int() also strips), takes one sign, digits with single
// underscores between them, and a fraction only if it is all zeros
// ("1.0" is 1, "1." is not a number). Past 4300 digits it gives up, as
// Python's int() does.
func pyIntResult(text string) (*big.Int, string) {
	s := strings.TrimFunc(text, unicode.IsSpace)
	if s != text && strings.ContainsAny(s, "\x1c\x1d\x1e\x1f") {
		return nil, "int_parsing"
	}
	if whole, frac, ok := strings.Cut(s, "."); ok {
		if frac == "" || strings.Trim(frac, "0") != "" {
			return nil, "int_parsing"
		}
		s = whole
	}
	sign := ""
	if s != "" && (s[0] == '+' || s[0] == '-') {
		sign, s = s[:1], s[1:]
	}
	if s == "" || s[0] == '_' || s[len(s)-1] == '_' || strings.Contains(s, "__") {
		return nil, "int_parsing"
	}
	digits := strings.ReplaceAll(s, "_", "")
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return nil, "int_parsing"
		}
	}
	if significant := strings.TrimLeft(digits, "0"); len(sign)+len(significant) > 4300 {
		return nil, "int_parsing_size"
	}
	n, _ := new(big.Int).SetString(sign+digits, 10)
	return n, ""
}

var intMessages = map[string]string{
	"int_parsing":      "Input should be a valid integer, unable to parse string as an integer",
	"int_parsing_size": "Unable to parse input string as an integer, exceeded maximum size",
}

// int is a required int Form field.
func (p *formParams) int(name string) *big.Int {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		p.errors = append(p.errors, fieldError{kind: "missing", name: name, msg: "Field required"})
		return nil
	}
	return p.parseInt(name, v)
}

// intOr is an int Form field with a default (nil for `int | None =
// Form(None)`), which an empty or absent field takes.
func (p *formParams) intOr(name string, def *big.Int) *big.Int {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		return def
	}
	return p.parseInt(name, v)
}

func (p *formParams) parseInt(name, v string) *big.Int {
	n, kind := pyIntResult(v)
	if kind != "" {
		p.errors = append(p.errors, fieldError{kind: kind, name: name, msg: intMessages[kind], input: &v})
	}
	return n
}

// list is a `list[str] = Form([])` field: every value sent under the
// name, in order; none is the empty list.
func (p *formParams) list(name string) []string { return p.f.getAll(name) }
