package helper

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/internal/reference"
)

// notLoaded is what the recording's nft says for a set the case doesn't
// name (reference/test_fros_helper_cases.py's NOT_LOADED).
var notLoaded = NftResult{Code: 1, Stderr: "Error: No such file or directory\nlist set inet fr_os x\n                     ^\n"}

// pythonJSONError is a message that quotes Python's json or codec error,
// which 2.x words its own way (decisions.md, "the helper's requests").
var pythonJSONError = regexp.MustCompile(`^(invalid request: |could not parse nft JSON output: )(.*: line \d+ column \d+ \(char \d+\)|'utf-8' codec can't decode .*)$`)

// TestReference replays every recorded request to 1.x's apply-helper.
func TestReference(t *testing.T) {
	cases, err := reference.HelperCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 400 {
		t.Fatalf("only %d helper cases", len(cases))
	}
	decided := 0
	for _, c := range cases {
		got, calls, err := replay(t, c)
		if c.Decided != "" {
			decided++
			checkDecided(t, c, got, err)
			continue
		}
		if !slices.EqualFunc(calls, c.NftCalls, slices.Equal) {
			t.Errorf("%s: nft runs\n got %q\nwant %q", c.ID, calls, c.NftCalls)
		}
		if string(c.Reply) == "null" {
			if !errors.Is(err, errNoReply) {
				t.Errorf("%s: 1.x sent no reply, got %s (%v)", c.ID, marshal(t, got), err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: no reply (%v), 1.x sent %s", c.ID, err, c.Reply)
			continue
		}
		gotText, wantText := marshal(t, got), string(c.Reply)
		if same(t, gotText, wantText) {
			continue
		}
		if m := pythonJSONError.FindStringSubmatch(messageOf(t, wantText)); m != nil &&
			strings.HasPrefix(messageOf(t, gotText), m[1]) && okOf(t, gotText) == false {
			continue
		}
		t.Errorf("%s (%s, %.80q):\n got %s\nwant %s", c.ID, c.Role, lineOf(t, c), gotText, wantText)
	}
	if decided == 0 {
		t.Error("no decided cases: has the recording changed?")
	}
}

func lineOf(t *testing.T, c reference.HelperCase) []byte {
	if c.Line != nil {
		return []byte(*c.Line)
	}
	b, err := hex.DecodeString(c.LineHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func replay(t *testing.T, c reference.HelperCase) (any, [][]string, error) {
	dir := t.TempDir()
	write := func(name string, hexed *string) string {
		path := filepath.Join(dir, name)
		if hexed != nil {
			b, err := hex.DecodeString(*hexed)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return path
	}
	rejected := filepath.Join(dir, "config.rejected.yaml")
	if c.Files.Rejected {
		os.WriteFile(rejected, []byte("version: 1\n"), 0o600)
	}
	calls := [][]string{}
	env := Env{
		ConfigPath:         filepath.Join(dir, "config.yaml"),
		Sys:                inertSystem(dir),
		ApplyPendingPath:   write("apply-pending.json", c.Files.ApplyPending),
		RejectedConfigPath: rejected,
		KeaLeasesPath:      write("kea-leases4.csv", c.Files.KeaLeases),
		Now:                func() float64 { return c.Now },
		Nft: func(argv []string) (NftResult, error) {
			calls = append(calls, slices.Clone(argv))
			if c.Nft == nil {
				return NftResult{}, ErrNoNft
			}
			a, ok := c.Nft[argv[len(argv)-1]]
			if !ok {
				return notLoaded, nil
			}
			return NftResult{Stdout: a.Stdout, Stderr: a.Stderr, Code: a.RC}, nil
		},
	}
	policy := Policy{FullUIDs: map[int]bool{}, SensorUIDs: map[int]bool{}}
	switch c.Role {
	case "full":
		policy.FullUIDs[c.UID] = true
	case "sensor":
		policy.SensorUIDs[c.UID] = true
	}
	s := &Server{Env: env, Policy: func() Policy { return policy }}
	reply, err := s.Answer(bufio.NewReaderSize(bytes.NewReader(lineOf(t, c)), 4096), 1, c.UID)
	return reply, calls, err
}

// checkDecided: a case 1.x let through and 2.x refuses on purpose.
func checkDecided(t *testing.T, c reference.HelperCase, got any, err error) {
	if err != nil {
		t.Errorf("%s (decided: %s): no reply (%v)", c.ID, c.Decided, err)
		return
	}
	text := marshal(t, got)
	if okOf(t, text) || !strings.HasPrefix(messageOf(t, text), "invalid request: ") {
		t.Errorf("%s (decided: %s): got %s, want an invalid request", c.ID, c.Decided, text)
	}
}

func marshal(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// same compares two replies as values, keys in order: Python writes
// "é" where Go writes "é", and spaces after its separators.
func same(t *testing.T, a, b string) bool {
	va, err1 := config.ParseJSON([]byte(a))
	vb, err2 := config.ParseJSON([]byte(b))
	if err1 != nil || err2 != nil {
		t.Fatalf("unreadable reply: %v %v", err1, err2)
	}
	return config.Repr(va) == config.Repr(vb)
}

func messageOf(t *testing.T, text string) string {
	v, _ := config.ParseJSON([]byte(text))
	m, _ := v.(*config.Map)
	if m == nil {
		return ""
	}
	s, _ := m.Get("message")
	str, _ := s.(string)
	return str
}

func okOf(t *testing.T, text string) bool {
	v, _ := config.ParseJSON([]byte(text))
	m, _ := v.(*config.Map)
	if m == nil {
		return false
	}
	ok, _ := m.Get("ok")
	return ok == true
}
