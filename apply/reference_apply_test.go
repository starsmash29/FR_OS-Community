package apply_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/helper"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// TestReferenceApply replays every session recorded against 1.x's
// apply-helper (reference/test_fros_apply_cases.py) against the same
// fake system: the same programs must run, with the same input and
// timeout, in the same order; the replies must be the same; and the
// tree must end the same, file for file and mode for mode.
func TestReferenceApply(t *testing.T) {
	cases, err := reference.ApplyCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no apply cases")
	}
	defer apply.SetEuid(func() int { return 0 })()
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if len(c.Leaks) > 0 {
				t.Fatalf("1.x touched paths outside the case's root: %q", c.Leaks)
			}
			replayApply(t, c)
		})
	}
}

// fakeSystem answers like the recording's fake.
type fakeSystem struct {
	root, tmp string
	table     []reference.ApplyAnswer
	random    []byte
	calls     []call
	tmpName   *regexp.Regexp
	passed    map[int]int
}

type call struct {
	argv    []string
	stdin   string
	timeout time.Duration
}

// norm is s as the recording writes it.
func (f *fakeSystem) norm(s string) string {
	s = strings.ReplaceAll(s, f.root, "@ROOT@")
	s = f.tmpName.ReplaceAllString(s, "@TMP@/tmp*")
	return strings.ReplaceAll(s, f.tmp+"/", "@TMP@/")
}

func (f *fakeSystem) run(c apply.Cmd) (apply.Result, error) {
	argv := make([]string, len(c.Argv))
	for i, a := range c.Argv {
		argv[i] = f.norm(a)
	}
	f.calls = append(f.calls, call{argv, c.Stdin, c.Timeout})
	for i, a := range f.table {
		if len(a.Argv) <= len(argv) && slices.Equal(argv[:len(a.Argv)], a.Argv) {
			if f.passed[i] < a.After {
				f.passed[i]++
				continue
			}
			switch a.Error {
			case "missing":
				return apply.Result{}, apply.ErrNotFound
			case "timeout":
				return apply.Result{}, &apply.TimeoutError{Argv: c.Argv, Timeout: c.Timeout}
			}
			return apply.Result{Stdout: a.Stdout, Stderr: a.Stderr, Code: a.RC}, nil
		}
	}
	return apply.Result{}, nil
}

func (f *fakeSystem) nft(argv []string) (helper.NftResult, error) {
	r, err := f.run(apply.Cmd{Argv: argv})
	if errors.Is(err, apply.ErrNotFound) {
		return helper.NftResult{}, helper.ErrNoNft
	}
	return helper.NftResult{Stdout: r.Stdout, Stderr: r.Stderr, Code: r.Code}, err
}

func (f *fakeSystem) rand(b []byte) error {
	if len(f.random) < len(b) {
		return errors.New("the case's random bytes ran out")
	}
	copy(b, f.random)
	f.random = f.random[len(b):]
	return nil
}

func replayApply(t *testing.T, c reference.ApplyCase) {
	root := t.TempDir()
	random, err := hex.DecodeString(c.Random)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Clean(os.TempDir())
	f := &fakeSystem{root: root, tmp: tmp, table: c.Table, random: random, passed: map[int]int{},
		tmpName: regexp.MustCompile(regexp.QuoteMeta(tmp) + `/tmp[A-Za-z0-9_]+`)}
	materialize(t, root, c.Setup)

	sec, frac := math.Modf(c.Now)
	now := time.Unix(int64(sec), int64(frac*1e9))
	sys := apply.DefaultSystem()
	sys.Paths = apply.DefaultPaths().Under(root)
	sys.Run = f.run
	sys.Euid = func() int { return 0 }
	sys.Now = func() time.Time { return now }
	sys.Which = func(name string) string { return "/usr/bin/" + name }
	sys.LoginUsers = func() []string { return slices.Clone(c.LoginUsers) }
	sys.Random = f.rand
	var openssl []any
	if err := json.Unmarshal(c.OpenSSL, &openssl); err != nil || len(openssl) != 4 {
		t.Fatalf("openssl %s: %v", c.OpenSSL, err)
	}
	version := [3]int{int(openssl[0].(float64)), int(openssl[1].(float64)), int(openssl[2].(float64))}
	sys.OpenSSLVersion = func() ([3]int, string) { return version, openssl[3].(string) }
	sys.Sleep = func(time.Duration) {}
	sys.Chown = func(string, int, int) error { return nil } // as the recording's: no accounts
	p := sys.Paths
	s := &helper.Server{Env: helper.Env{
		ConfigPath: p.Config, BackupDir: p.BackupDir, KeaConfigPath: p.KeaConfig,
		ZtnaStatePath: filepath.Join(root, helper.ZtnaStatePath), AdblockHostsPath: p.AdblockHosts,
		KeaLeasesPath: filepath.Join(root, helper.KeaLeasesPath), ApplyPendingPath: p.ApplyPending,
		RejectedConfigPath: p.RejectedConfig, ApplyLockPath: p.ApplyLock,
		Sys: sys, Nft: f.nft, Now: func() float64 { return c.Now },
	}, Policy: func() helper.Policy {
		return helper.Policy{FullUIDs: map[int]bool{0: true}, SensorUIDs: map[int]bool{}}
	}}

	if c.Decided == "xdp" {
		// decisions.md, "applies": the XDP SNI filter isn't in FR_OS 2
		// yet, so every apply of the config is refused before anything
		// changes.
		for i, step := range c.Steps {
			line := append(bytes.Clone(step.Request), '\n')
			got, err := s.Answer(bufio.NewReader(bytes.NewReader(line)), 1, 0)
			text := marshal(t, got, err)
			if okOf(text) || !strings.Contains(text, "the XDP SNI filter is not in FR_OS 2 yet") {
				t.Errorf("step %d (decided: xdp): got %s", i, text)
			}
		}
		got := snapshot(t, f, root)
		delete(got, "etc/fr_os/.apply.lock") // taken, and left, by every apply
		for _, rel := range slices.Sorted(maps.Keys(got)) {
			if w, ok := c.Setup[rel]; !ok || !sameFile(got[rel], w) {
				t.Errorf("a refused apply changed %s", rel)
			}
		}
		for rel := range c.Setup {
			if _, ok := got[rel]; !ok {
				t.Errorf("a refused apply removed %s", rel)
			}
		}
		return
	}
	for i, step := range c.Steps {
		start := len(f.calls)
		var got any
		if later, ok := waitOf(t, step.Request); ok {
			// fr-apply-revert.service, later seconds on; its sleeps move
			// the clock.
			clock := now.Add(time.Duration(later * float64(time.Second)))
			sys.Now = func() time.Time { return clock }
			sys.Sleep = func(d time.Duration) { clock = clock.Add(d) }
			var messages []string
			if messages, err = s.Wait(); err == nil {
				got = map[string]any{"messages": messages}
			}
			sys.Now = func() time.Time { return now }
		} else {
			line := append(bytes.Clone(step.Request), '\n')
			got, err = s.Answer(bufio.NewReader(bytes.NewReader(line)), 1, 0)
		}
		where := fmt.Sprintf("step %d %s", i, step.Request)
		checkCalls(t, where, f.calls[start:], step.Calls)
		switch {
		case step.Raised != "":
			// 1.x sent no reply (decisions.md, "Errors 1.x lets through"):
			// 2.x refuses with what went wrong.
			text := marshal(t, got, err)
			if okOf(text) {
				t.Errorf("%s: 1.x raised %s (%s), got %s", where, step.Raised, step.Error, text)
			}
		default:
			text := marshal(t, got, err)
			if !sameJSON(t, f.norm(text), string(step.Reply)) {
				t.Errorf("%s:\n%s", where, replyDiff(f.norm(text), string(step.Reply)))
			}
		}
	}
	checkTree(t, f, snapshot(t, f, root), c.Files)
}

func waitOf(t *testing.T, request jsontext.Value) (float64, bool) {
	var r map[string]any
	if err := json.Unmarshal(request, &r); err != nil {
		t.Fatal(err)
	}
	later, ok := r["wait"].(float64)
	return later, ok
}

func marshal(t *testing.T, v any, err error) string {
	if err != nil {
		return fmt.Sprintf(`{"no reply": %q}`, err.Error())
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func okOf(text string) bool {
	v, _ := config.ParseJSON([]byte(text))
	m, _ := v.(*config.Map)
	if m == nil {
		return false
	}
	ok, _ := m.Get("ok")
	return ok == true
}

func sameJSON(t *testing.T, a, b string) bool {
	va, err1 := config.ParseJSON([]byte(a))
	vb, err2 := config.ParseJSON([]byte(b))
	if err1 != nil || err2 != nil {
		t.Fatalf("unreadable reply: %v %v (%s / %s)", err1, err2, a, b)
	}
	return config.Repr(va) == config.Repr(vb)
}

func checkCalls(t *testing.T, where string, got []call, want []reference.ApplyCall) {
	t.Helper()
	n := min(len(got), len(want))
	for i := range n {
		g, w := got[i], want[i]
		if !slices.Equal(g.argv, w.Argv) {
			t.Errorf("%s: call %d\n got %q\nwant %q", where, i, g.argv, w.Argv)
			return
		}
		if !sameInput(g.stdin, w.Input) {
			t.Errorf("%s: call %d %q: input\n got %q\nwant %s", where, i, g.argv, short(g.stdin), short(string(w.Input)))
			return
		}
		if !sameTimeout(g.timeout, w.Timeout) {
			t.Errorf("%s: call %d %q: timeout %v, want %s", where, i, g.argv, g.timeout, w.Timeout)
			return
		}
	}
	if len(got) != len(want) {
		var extra []string
		if len(got) > n {
			for _, g := range got[n:] {
				extra = append(extra, strings.Join(g.argv, " "))
			}
			t.Errorf("%s: %d calls, want %d; also ran %q", where, len(got), len(want), extra)
		} else {
			for _, w := range want[n:] {
				extra = append(extra, strings.Join(w.Argv, " "))
			}
			t.Errorf("%s: %d calls, want %d; did not run %q", where, len(got), len(want), extra)
		}
	}
}

func short(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func sameInput(got string, want jsontext.Value) bool {
	var w any
	if err := json.Unmarshal(want, &w); err != nil {
		return false
	}
	switch x := w.(type) {
	case nil:
		return got == ""
	case string:
		return got == x
	case map[string]any:
		sum := sha256.Sum256([]byte(got))
		return hex.EncodeToString(sum[:]) == x["sha256"]
	}
	return false
}

func sameTimeout(got time.Duration, want jsontext.Value) bool {
	if string(want) == "null" || len(want) == 0 {
		return got == 0
	}
	w, err := strconv.ParseFloat(string(want), 64)
	return err == nil && math.Abs(got.Seconds()-w) < 1e-9
}

// --- the tree ------------------------------------------------------------------

func materialize(t *testing.T, root string, files map[string]*reference.ApplyFile) {
	for _, rel := range slices.Sorted(maps.Keys(files)) {
		path := filepath.Join(root, rel)
		e := files[rel]
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		var data []byte
		switch {
		case e.Text != nil:
			data = []byte(*e.Text)
		case e.Hex != "":
			data, _ = hex.DecodeString(e.Hex)
		default:
			t.Fatalf("setup file %s has no content", rel)
		}
		mode, _ := strconv.ParseUint(strings.TrimPrefix(e.Mode, "0o"), 8, 32)
		if err := os.WriteFile(path, data, fs.FileMode(mode)); err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, fs.FileMode(mode))
	}
}

func snapshot(t *testing.T, f *fakeSystem, root string) map[string]*reference.ApplyFile {
	out := map[string]*reference.ApplyFile{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				out[rel+"/"] = nil
			}
			return nil
		}
		st, err := os.Lstat(path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		e := &reference.ApplyFile{Mode: "0o" + strconv.FormatUint(uint64(st.Mode().Perm()|st.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)), 8)}
		switch text := f.norm(string(data)); {
		case !utf8.ValidString(text):
			e.Hex = hex.EncodeToString(data)
		case len(text) > 1<<16:
			sum := sha256.Sum256([]byte(text))
			e.SHA256, e.Len = hex.EncodeToString(sum[:]), len(text)
		default:
			e.Text = &text
		}
		out[rel] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkTree(t *testing.T, f *fakeSystem, got, want map[string]*reference.ApplyFile) {
	t.Helper()
	for _, rel := range slices.Sorted(maps.Keys(want)) {
		w := want[rel]
		g, ok := got[rel]
		if !ok {
			t.Errorf("missing %s", rel)
			continue
		}
		if w == nil || g == nil {
			if (w == nil) != (g == nil) {
				t.Errorf("%s: a directory on one side only", rel)
			}
			continue
		}
		if g.Mode != w.Mode {
			t.Errorf("%s: mode %s, want %s", rel, g.Mode, w.Mode)
		}
		switch {
		case w.Text != nil && rel == scheduleState:
			// decisions.md, "applies": the fingerprint is 2.x's own.
			if g.Text == nil || withoutFingerprint(*g.Text) != withoutFingerprint(*w.Text) {
				t.Errorf("%s:\n got %v\nwant %q", rel, g.Text, *w.Text)
			}
		case w.Text != nil && rel == sensorCopy:
			// decisions.md, "The sensors' config copy": flow YAML, the
			// same data.
			if g.Text == nil || !sameYAML(t, *g.Text, *w.Text) {
				t.Errorf("%s: not the same data", rel)
			}
		case w.Text != nil:
			if g.Text == nil || *g.Text != *w.Text {
				gt := "<not text>"
				if g.Text != nil {
					gt = *g.Text
				}
				t.Errorf("%s:\n got %q\nwant %q", rel, short(gt), short(*w.Text))
			}
		case w.Hex != "":
			if g.Hex != w.Hex {
				t.Errorf("%s: bytes differ", rel)
			}
		case w.SHA256 != "":
			if g.SHA256 != w.SHA256 {
				t.Errorf("%s: sha256 %s (%d bytes), want %s (%d)", rel, g.SHA256, g.Len, w.SHA256, w.Len)
			}
		}
	}
	for _, rel := range slices.Sorted(maps.Keys(got)) {
		if _, ok := want[rel]; !ok {
			t.Errorf("extra %s", rel)
		}
	}
}

const sensorCopy = "etc/fr_os/sensor-config.yaml"

func sameYAML(t *testing.T, got, want string) bool {
	if !strings.HasPrefix(got, apply.SensorCopyHeader) || !strings.HasPrefix(want, apply.SensorCopyHeader) {
		return false
	}
	g, err1 := config.LoadYAML(strings.TrimPrefix(got, apply.SensorCopyHeader))
	w, err2 := config.LoadYAML(strings.TrimPrefix(want, apply.SensorCopyHeader))
	if err1 != nil || err2 != nil {
		t.Logf("sensor copy: %v / %v", err1, err2)
		return false
	}
	return config.Repr(g) == config.Repr(w)
}

// replyDiff is where two replies differ: their messages part by part
// ("; "-separated), then the rest.
func replyDiff(got, want string) string {
	msg := func(text string) (string, string) {
		v, _ := config.ParseJSON([]byte(text))
		m, _ := v.(*config.Map)
		if m == nil {
			return "", text
		}
		s, _ := m.Get("message")
		str, _ := s.(string)
		m.Set("message", "")
		return str, config.Repr(m)
	}
	gm, gr := msg(got)
	wm, wr := msg(want)
	var b strings.Builder
	gp, wp := strings.Split(gm, "; "), strings.Split(wm, "; ")
	shown := 0
	for i := range max(len(gp), len(wp)) {
		if shown == 3 {
			b.WriteString("  ...\n")
			break
		}
		var g, w string
		if i < len(gp) {
			g = gp[i]
		}
		if i < len(wp) {
			w = wp[i]
		}
		if g != w {
			shown++
			fmt.Fprintf(&b, "  message part %d:\n   got %q\n  want %q\n", i, g, w)
		}
	}
	if gr != wr {
		fmt.Fprintf(&b, "  rest:\n   got %s\n  want %s\n", gr, wr)
	}
	return b.String()
}

const scheduleState = "etc/fr_os/schedule_state.json"

var fingerprint = regexp.MustCompile(`"config_fingerprint": "[0-9a-f]{64}"`)

func withoutFingerprint(text string) string {
	return fingerprint.ReplaceAllString(text, `"config_fingerprint": ""`)
}

func sameFile(a, b *reference.ApplyFile) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Mode == b.Mode && a.Hex == b.Hex && a.SHA256 == b.SHA256 &&
		(a.Text == nil) == (b.Text == nil) && (a.Text == nil || *a.Text == *b.Text)
}
