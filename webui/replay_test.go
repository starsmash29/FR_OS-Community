package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/net/html"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// The differential test of the webUI: every session 1.x's webUI went
// through (reference/test_fros_webui_cases.py) is replayed against this
// one, with the same clock, random bytes, helper answers and files, and
// must answer the same: status, headers, body (HTML compared as its
// tokens, entities decoded and whitespace collapsed, since Jinja and
// html/template write the same page with different spacing and
// escapes), the helper requests and the files left.

// notPorted are the screens later parts of phase 3 port: their steps
// are skipped (their helper requests still use up the answers they
// used up in 1.x). TODO(3a-2): the dashboard.
var notPorted = map[string]bool{"GET /": true}

// maxText is the harness's MAX_TEXT: larger files are recorded by digest.
const maxText = 1 << 18

func TestReplaysTheWebUISessionsOf1x(t *testing.T) {
	cases, err := reference.WebUICases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 25 {
		t.Fatalf("only %d webUI sessions recorded", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Session, func(t *testing.T) { replay(t, c) })
	}
}

// fakeHelpers is the harness's _Fake.send: the case's table, then the
// base answers; the first entry for the command and socket that isn't
// used up answers, and an "error" entry (or none) makes the helper
// unreachable.
type fakeHelpers struct {
	answers []reference.WebUIAnswer
	times   []int
	calls   []config.Value
}

func newFakeHelpers(c reference.WebUICase) *fakeHelpers {
	f := &fakeHelpers{answers: slices.Concat(c.Table, c.Base)}
	for _, a := range f.answers {
		n := -1
		if a.Times != nil {
			n = *a.Times
		}
		f.times = append(f.times, n)
	}
	return f
}

func (f *fakeHelpers) answer(cmd, socket string) *reference.WebUIAnswer {
	for i, a := range f.answers {
		want := a.Socket
		if want == "" {
			want = "apply.sock"
		}
		if a.Cmd != cmd || want != socket {
			continue
		}
		if f.times[i] == 0 {
			continue
		}
		if f.times[i] > 0 {
			f.times[i]--
		}
		if len(a.Error) == 0 {
			return &f.answers[i]
		}
		break
	}
	return nil
}

func (f *fakeHelpers) send(socketPath string, cmd *config.Map, timeout float64, _ int) (config.Value, error) {
	name, _ := cmd.Get("cmd")
	call := config.NewMap()
	call.Set("socket", filepath.Base(socketPath))
	call.Set("request", cmd)
	call.Set("timeout", timeout)
	defer func() { f.calls = append(f.calls, call) }()
	a := f.answer(pyStr(name), filepath.Base(socketPath))
	if a == nil {
		msg := fmt.Sprintf("cannot reach apply-helper at %s: [Errno 2] No such file or directory", socketPath)
		call.Set("error", msg)
		return nil, &HelperError{Msg: msg}
	}
	reply, err := config.ParseJSON(a.Reply)
	if err != nil {
		return nil, err
	}
	call.Set("reply", reply)
	again, _ := config.ParseJSON(a.Reply) // the route gets its own copy
	return again, nil
}

// skip uses up what a skipped step's helper requests used up in 1.x.
func (f *fakeHelpers) skip(t *testing.T, recorded []byte) {
	v, err := config.ParseJSON(recorded)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := v.([]config.Value)
	for _, c := range list {
		m := c.(*config.Map)
		req, _ := m.Get("request")
		cmd, _ := req.(*config.Map).Get("cmd")
		f.answer(pyStr(cmd), mapStr(m, "socket"))
	}
}

func replay(t *testing.T, c reference.WebUICase) {
	root := t.TempDir()
	for rel, v := range c.FilesBefore {
		data, err := fileData(v)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.ReplaceAll(data, []byte("@ROOT@"), []byte(root)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stream, err := hex.DecodeString(c.Random)
	if err != nil {
		t.Fatal(err)
	}
	random := bytes.NewReader(stream[c.RandomStart:])
	now := c.Now
	helpers := newFakeHelpers(c)
	env := Env{
		Now:   func() float64 { return now },
		Rand:  random,
		Local: time.UTC, // the harness runs with TZ=UTC
		Paths: Paths{Root: root},
		Send:  helpers.send,
		Run: func(argv []string, _ float64) (int, string, error) {
			t.Errorf("ran %q: no screen of phase 3a runs a program", argv)
			return 1, "", fmt.Errorf("not in this test")
		},
	}
	server, err := New(env, c.Version, c.Codename)
	if err != nil {
		t.Fatal(err)
	}
	rooted := func(s string) string { return strings.ReplaceAll(s, root, "@ROOT@") }
	for i, step := range c.Steps {
		if step.Advance != nil {
			now += *step.Advance
			continue
		}
		where := fmt.Sprintf("step %d: %s %s", i, step.Method, step.Path)
		if notPorted[step.Method+" "+strings.SplitN(step.Path, "?", 2)[0]] {
			helpers.skip(t, step.Helper)
			continue
		}
		helpers.calls = nil
		r := request1x(step)
		w := httptest.NewRecorder()
		server.ServeHTTP(w, r)

		if w.Code != step.Status {
			t.Errorf("%s: status %d, 1.x %d\n%s", where, w.Code, step.Status, w.Body.String())
		}
		if got, want := headerSet(w.Result().Header), wantHeaders(step.ResponseHeaders); !slices.Equal(got, want) {
			t.Errorf("%s: headers\n got %q\nwant %q", where, got, want)
		}
		compareBody(t, where, w.Body.Bytes(), step, w.Header().Get("Content-Type"))

		got, err := config.PyJSON(helpers.calls, -1, true)
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := config.ParseJSON(step.Helper)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := config.PyJSON(recorded, -1, true)
		if rooted(got) != want {
			t.Errorf("%s: helper requests\n got %s\nwant %s", where, rooted(got), want)
		}
	}
	if random.Len() != 0 {
		t.Errorf("drew %d random bytes fewer than 1.x", random.Len())
	}
	compareFiles(t, root, c.FilesAfter)
}

// request1x is the request Starlette's TestClient sent.
func request1x(step reference.WebUIStep) *http.Request {
	var body []byte
	contentType := ""
	switch {
	case len(step.JSON) > 0 && string(step.JSON) != "null":
		body, contentType = step.JSON, "application/json"
	case step.Method == "POST" && len(step.Form) > 0:
		values := url.Values{}
		for k, v := range step.Form {
			values.Set(k, v)
		}
		body, contentType = []byte(values.Encode()), "application/x-www-form-urlencoded"
	}
	r := httptest.NewRequest(step.Method, "https://router.lan"+step.Path, bytes.NewReader(body))
	r.RemoteAddr = "testclient:50000"
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for k, v := range step.Headers {
		if strings.EqualFold(k, "host") {
			r.Host = v
			continue
		}
		r.Header.Set(k, v)
	}
	if len(step.Cookies) > 0 {
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(step.Cookies)) {
			parts = append(parts, k+"="+step.Cookies[k])
		}
		r.Header.Set("Cookie", strings.Join(parts, "; "))
	}
	return r
}

// ignoredHeaders are the ones the harness drops, and the static files'
// validators (decisions.md: an ETag of the content, no Last-Modified).
var ignoredHeaders = map[string]bool{"date": true, "server": true, "content-length": true, "etag": true,
	"last-modified": true}

func headerSet(h map[string][]string) []string {
	var out []string
	for k, vs := range h {
		k = strings.ToLower(k)
		if ignoredHeaders[k] {
			continue
		}
		for _, v := range vs {
			out = append(out, k+": "+v)
		}
	}
	slices.Sort(out)
	return out
}

func wantHeaders(recorded [][2]string) []string {
	var out []string
	for _, h := range recorded {
		k := strings.ToLower(h[0])
		if !ignoredHeaders[k] {
			out = append(out, k+": "+h[1])
		}
	}
	slices.Sort(out)
	return out
}

func compareBody(t *testing.T, where string, got []byte, step reference.WebUIStep, contentType string) {
	t.Helper()
	switch {
	case step.BodySHA256 != "":
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != step.BodySHA256 {
			t.Errorf("%s: the large body differs", where)
		}
	case step.BodyHex != "":
		if hex.EncodeToString(got) != step.BodyHex {
			t.Errorf("%s: the body differs", where)
		}
	case strings.HasPrefix(contentType, "text/html"):
		g, w := htmlTokens(string(got)), htmlTokens(*step.Body)
		if !slices.Equal(g, w) {
			for i := 0; i < len(g) || i < len(w); i++ {
				var a, b string
				if i < len(g) {
					a = g[i]
				}
				if i < len(w) {
					b = w[i]
				}
				if a != b {
					t.Errorf("%s: the page differs at token %d\n got %q\nwant %q", where, i, a, b)
					return
				}
			}
		}
	default:
		if string(got) != *step.Body {
			t.Errorf("%s: body\n got %q\nwant %q", where, got, *step.Body)
		}
	}
}

// htmlTokens is a page as its tags (attributes in order, values
// decoded) and its non-blank texts with whitespace collapsed.
func htmlTokens(page string) []string {
	z := html.NewTokenizer(strings.NewReader(page))
	var out []string
	skip := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			return out
		}
		tok := z.Token()
		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			if skip > 0 {
				if tok.Data == "svg" && tt == html.StartTagToken {
					skip++
				}
				continue
			}
			// TODO(3a-2): segno's QR code, ported byte for byte.
			if tok.Data == "svg" && hasAttr(tok, "xmlns") {
				if tt == html.StartTagToken {
					skip = 1
				}
				continue
			}
			var b strings.Builder
			b.WriteString("<" + tok.Data)
			for _, a := range tok.Attr {
				fmt.Fprintf(&b, " %s=%q", a.Key, a.Val)
			}
			out = append(out, b.String()+">")
		case html.EndTagToken:
			if skip > 0 {
				if tok.Data == "svg" {
					skip--
				}
				continue
			}
			out = append(out, "</"+tok.Data+">")
		case html.TextToken:
			if skip > 0 {
				continue
			}
			if text := strings.Join(strings.Fields(tok.Data), " "); text != "" {
				out = append(out, text)
			}
		case html.DoctypeToken:
			out = append(out, "<!doctype "+tok.Data+">")
		}
	}
}

func hasAttr(tok html.Token, key string) bool {
	for _, a := range tok.Attr {
		if a.Key == key {
			return true
		}
	}
	return false
}

// fileData is a recorded file's bytes: its text, or {"hex"}.
func fileData(v []byte) ([]byte, error) {
	var text string
	if err := json.Unmarshal(v, &text); err == nil {
		return []byte(text), nil
	}
	var obj struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(v, &obj); err != nil || obj.Hex == "" {
		return nil, fmt.Errorf("a file recorded by digest can't be set up")
	}
	return hex.DecodeString(obj.Hex)
}

// recordedFile is a file as the harness's _files records it.
func recordedFile(data []byte) any {
	if len(data) > maxText {
		sum := sha256.Sum256(data)
		return map[string]any{"sha256": hex.EncodeToString(sum[:]), "size": float64(len(data))}
	}
	if utf8.Valid(data) {
		return string(data)
	}
	return map[string]any{"hex": hex.EncodeToString(data)}
}

func compareFiles(t *testing.T, root string, want map[string]jsontext.Value) {
	t.Helper()
	got := map[string]any{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		data = bytes.ReplaceAll(data, []byte(root), []byte("@ROOT@"))
		got[rel] = recordedFile(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[string]any{}
	for rel, v := range want {
		var x any
		if err := json.Unmarshal(v, &x); err != nil {
			t.Fatal(err)
		}
		wanted[rel] = x
	}
	for _, rel := range slices.Sorted(mapsAnyKeys(got, wanted)) {
		if !reflect.DeepEqual(got[rel], wanted[rel]) {
			t.Errorf("file %s\n got %v\nwant %v", rel, got[rel], wanted[rel])
		}
	}
}

func mapsAnyKeys(a, b map[string]any) func(func(string) bool) {
	return func(yield func(string) bool) {
		seen := map[string]bool{}
		for _, m := range []map[string]any{a, b} {
			for k := range m {
				if !seen[k] {
					seen[k] = true
					if !yield(k) {
						return
					}
				}
			}
		}
	}
}
