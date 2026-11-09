package webui

import (
	"bytes"
	"errors"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
)

// What 1.x's webUI gets from FastAPI and Starlette, kept where a
// browser or a script can see it: how a form is read, the 422 a missing
// or malformed field gets, the JSON of an HTTPException, the redirect
// and cookie headers.

// maxBody bounds a request body (Starlette's own form limits are 1 MB
// per part and 1000 fields).
const maxBody = 1 << 20

// form is a request's form fields, in order; a name given twice keeps
// its last value, as Starlette's FormData.get.
type form struct {
	values map[string]string
	has    bool
}

func (f form) get(name string) (string, bool) {
	v, ok := f.values[name]
	return v, ok
}

// pyUnquotePlus is Starlette's unquote_plus(field.decode("latin-1")):
// '+' is a space; a run of ASCII has its %XX decoded and is read as
// UTF-8, every invalid sequence a U+FFFD; a byte above 0x7f that wasn't
// percent-encoded stays the Latin-1 character it is.
func pyUnquotePlus(raw []byte) string {
	var b strings.Builder
	var ascii []byte
	flush := func() {
		if len(ascii) == 0 {
			return
		}
		var decoded []byte
		for i := 0; i < len(ascii); i++ {
			c := ascii[i]
			if c == '%' && i+2 < len(ascii) && isHex(ascii[i+1]) && isHex(ascii[i+2]) {
				n, _ := strconv.ParseUint(string(ascii[i+1:i+3]), 16, 8)
				decoded = append(decoded, byte(n))
				i += 2
				continue
			}
			decoded = append(decoded, c)
		}
		b.WriteString(pyDecodeUTF8(decoded))
		ascii = ascii[:0]
	}
	for _, c := range raw {
		if c == '+' {
			c = ' '
		}
		if c < 0x80 {
			ascii = append(ascii, c)
			continue
		}
		flush()
		b.WriteRune(rune(c))
	}
	flush()
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// pyDecodeUTF8 is bytes.decode("utf-8", "replace"): one U+FFFD for each
// maximal invalid subsequence, as Python's decoder.
func pyDecodeUTF8(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var b strings.Builder
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r != utf8.RuneError || size > 1 {
			b.WriteRune(r)
			data = data[size:]
			continue
		}
		// The longest prefix of a valid sequence is one error.
		n := invalidPrefix(data)
		b.WriteRune(utf8.RuneError)
		data = data[n:]
	}
	return b.String()
}

func invalidPrefix(data []byte) int {
	c := data[0]
	var need int
	var lo, hi byte = 0x80, 0xbf
	switch {
	case c >= 0xc2 && c <= 0xdf:
		need = 1
	case c == 0xe0:
		need, lo = 2, 0xa0
	case c >= 0xe1 && c <= 0xec, c == 0xee, c == 0xef:
		need = 2
	case c == 0xed:
		need, hi = 2, 0x9f
	case c == 0xf0:
		need, lo = 3, 0x90
	case c >= 0xf1 && c <= 0xf3:
		need = 3
	case c == 0xf4:
		need, hi = 3, 0x8f
	default:
		return 1
	}
	i := 1
	for ; i <= need && i < len(data); i++ {
		if i == 1 && (data[i] < lo || data[i] > hi) || i > 1 && (data[i] < 0x80 || data[i] > 0xbf) {
			return i
		}
	}
	return i
}

// readForm is request.form(): urlencoded or multipart; any other body
// is no form at all.
func readForm(r *http.Request, body []byte) (form, error) {
	f := form{values: map[string]string{}}
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "application/x-www-form-urlencoded":
		f.has = true
		for _, part := range bytes.FieldsFunc(body, func(r rune) bool { return r == '&' }) {
			name, value, _ := bytes.Cut(part, []byte("="))
			f.values[pyUnquotePlus(name)] = pyUnquotePlus(value)
		}
	case "multipart/form-data":
		f.has = true
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			p, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return f, err
			}
			data, err := io.ReadAll(io.LimitReader(p, maxBody))
			if err != nil {
				return f, err
			}
			f.values[p.FormName()] = pyDecodeUTF8(data)
		}
	}
	return f, nil
}

// fieldError is one entry of a 422's detail.
type fieldError struct {
	kind, name, msg string
	input           *string
}

// formParams reads a route's Form fields in their declaration order and
// collects FastAPI's errors: a required field that is missing or empty,
// a bool or float that doesn't parse.
type formParams struct {
	f      form
	errors []fieldError
}

func (p *formParams) str(name string) string {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		p.errors = append(p.errors, fieldError{kind: "missing", name: name, msg: "Field required"})
		return ""
	}
	return v
}

func (p *formParams) strOr(name, def string) string {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		return def
	}
	return v
}

// boolOr is pydantic's bool from a string: 1/on/t/true/y/yes and
// 0/off/f/false/n/no, any case; empty or absent is the default.
func (p *formParams) boolOr(name string, def bool) bool {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "on", "t", "true", "y", "yes":
		return true
	case "0", "off", "f", "false", "n", "no":
		return false
	}
	p.errors = append(p.errors, fieldError{kind: "bool_parsing", name: name,
		msg: "Input should be a valid boolean, unable to interpret input", input: &v})
	return def
}

// float is pydantic's float from a string, which reads it as Python's
// float() does: surrounding whitespace, a sign, single underscores
// between digits, inf/infinity/nan.
func (p *formParams) float(name string) float64 {
	v, ok := p.f.get(name)
	if !ok || v == "" {
		p.errors = append(p.errors, fieldError{kind: "missing", name: name, msg: "Field required"})
		return 0
	}
	f, ok := pyFloat(v)
	if !ok {
		p.errors = append(p.errors, fieldError{kind: "float_parsing", name: name,
			msg: "Input should be a valid number, unable to parse string as a number", input: &v})
	}
	return f
}

func pyFloat(text string) (float64, bool) {
	s := strings.TrimFunc(text, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\v' || r == '\f'
	})
	body := strings.TrimLeft(s, "+-")
	if len(s)-len(body) > 1 {
		return 0, false
	}
	switch strings.ToLower(body) {
	case "inf", "infinity":
		if strings.HasPrefix(s, "-") {
			return math.Inf(-1), true
		}
		return math.Inf(1), true
	case "nan":
		return math.NaN(), true
	}
	digits := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= '0' && c <= '9':
			digits = true
		case c == '_':
			if i == 0 || i == len(body)-1 || !isDigit(body[i-1]) || !isDigit(body[i+1]) {
				return 0, false
			}
		case c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-':
		default:
			return 0, false
		}
	}
	if !digits {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.ReplaceAll(s, "_", ""), 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) {
			return f, true // Python's float() gives inf, or 0.0
		}
		return 0, false
	}
	return f, true
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// detailJSON is FastAPI's 422 body for the errors.
func detailJSON(errs []fieldError) string {
	var b strings.Builder
	b.WriteString(`{"detail":[`)
	for i, e := range errs {
		if i > 0 {
			b.WriteByte(',')
		}
		input := "null"
		if e.input != nil {
			input = jsonStr(*e.input)
		}
		b.WriteString(`{"type":` + jsonStr(e.kind) + `,"loc":["body",` + jsonStr(e.name) + `],"msg":` +
			jsonStr(e.msg) + `,"input":` + input + `}`)
	}
	b.WriteString(`]}`)
	return b.String()
}

// pyJSONCompact is Starlette's JSONResponse body for v: compact, not
// ASCII-escaped.
func pyJSONCompact(v config.Value) string {
	var b strings.Builder
	writeCompact(&b, v)
	return b.String()
}

func writeCompact(b *strings.Builder, v config.Value) {
	switch x := v.(type) {
	case *config.Map:
		b.WriteByte('{')
		for i, k := range x.Keys() {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsonStr(pyStr(k)))
			b.WriteByte(':')
			writeCompact(b, x.Values()[i])
		}
		b.WriteByte('}')
	case []config.Value:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCompact(b, e)
		}
		b.WriteByte(']')
	case string:
		b.WriteString(jsonStr(x))
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case float64:
		b.WriteString(config.FloatRepr(x))
	default:
		b.WriteString(pyStr(x))
	}
}

// redirectWith is the target of a 303 to path with params (name,
// value, ...) as a query string, urlencoded as 1.x's redirect_with
// does: the one-shot flash messages.
func redirectWith(path string, params ...string) string {
	var q []string
	for i := 0; i+1 < len(params); i += 2 {
		q = append(q, url.QueryEscape(params[i])+"="+url.QueryEscape(params[i+1]))
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + strings.Join(q, "&")
}

// cookie is a Set-Cookie value as Python's http.cookies writes it, the
// attributes in name order: expires, HttpOnly, Max-Age, Path, SameSite,
// Secure.
type cookie struct {
	name, value  string
	expires      string
	httpOnly     bool
	maxAge       *int
	path         string
	sameSite     string
	secure       bool
	deleteCookie bool
}

func (c cookie) String() string {
	var b strings.Builder
	b.WriteString(c.name + "=" + c.value)
	if c.expires != "" {
		b.WriteString("; expires=" + c.expires)
	}
	if c.httpOnly {
		b.WriteString("; HttpOnly")
	}
	if c.maxAge != nil {
		b.WriteString("; Max-Age=" + strconv.Itoa(*c.maxAge))
	}
	if c.path != "" {
		b.WriteString("; Path=" + c.path)
	}
	if c.sameSite != "" {
		b.WriteString("; SameSite=" + c.sameSite)
	}
	if c.secure {
		b.WriteString("; Secure")
	}
	return b.String()
}
