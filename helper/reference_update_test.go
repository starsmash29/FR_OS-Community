package helper

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/internal/reference"
	"github.com/starsmash29/fr_os-community/release"
)

// TestReferenceUpdate holds the signed release update to 1.x's
// frfw.update, the update-helper's apply and rollback and `firewall-cli
// update`: what is downloaded, refused and verified, the order of the
// steps, the reply or the output and exit status, the state file, the
// check cache and the releases cache left, and the alerts. The steps that
// change the system are recorded on both sides, not run (installing a
// release is FR_OS 2's own: decisions.md, "phase 4f-4b"; apply.Updater's
// tests run them on a real tree).
func TestReferenceUpdate(t *testing.T) {
	cases, err := reference.UpdateCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) < 100 {
		t.Fatalf("only %d update cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) { replayUpdate(t, c) })
	}
}

// goTmp is a temporary directory os.MkdirTemp made in the releases
// cache.
var goTmp = regexp.MustCompile(`/tmp[0-9]+/`)

func replayUpdate(t *testing.T, c reference.UpdateCase) {
	root := t.TempDir()
	sys := apply.DefaultSystem()
	sys.Paths = apply.DefaultPaths().Under(root)
	sec, frac := math.Modf(c.Now)
	now := time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC()
	sys.Now = func() time.Time { return now }
	sys.Run = func(cmd apply.Cmd) (apply.Result, error) {
		t.Errorf("ran %q", cmd.Argv)
		return apply.Result{}, errors.New("not run here")
	}
	sys.Euid = func() int { return 1000 } // the audit log's chown isn't the case's
	put := func(path, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if c.State != nil {
		put(sys.Paths.UpdateState, *c.State)
	}
	if c.CheckCache != nil {
		put(sys.Paths.UpdateCheck, *c.CheckCache)
	}
	for v, files := range c.Cache {
		for name, data := range files {
			put(filepath.Join(sys.Paths.Releases, v, name), string(unhexU(t, data)))
		}
	}
	configPath := filepath.Join(root, "etc/fr_os/config.yaml")
	if c.Config != nil {
		put(configPath, *c.Config)
	}

	var steps []string
	unresolved := errors.New("<urlopen error [Errno -3] Temporary failure in name resolution>")
	step := func(name string) error {
		steps = append(steps, name)
		if c.Fail == strings.Fields(name)[0] {
			return errors.New(c.FailMessage)
		}
		return nil
	}
	keys := []release.Key{{Name: "case.pem", Data: []byte(c.Key)}}
	updater := func(repo string) *apply.Updater {
		return &apply.Updater{Sys: sys, Repo: repo, Installed: c.Installed, Keys: keys,
			Download: func(url, dest string, max int64) error {
				a, ok := c.Downloads[url]
				if !ok {
					return &apply.DownloadError{Err: unresolved}
				}
				steps = append(steps, "download "+url)
				switch {
				case a.Error != nil:
					return &apply.DownloadError{Err: errors.New("<urlopen error " + *a.Error + ">")}
				case a.Status >= 400:
					return &apply.DownloadError{Status: a.Status, Reason: a.Reason}
				}
				return os.WriteFile(dest, unhexU(t, *a.Data), 0o644)
			},
			Install:      func(top, version string) error { return step("install " + filepath.Base(top)) },
			Restart:      func() error { return step("restart") },
			RestartWebUI: func() error { return step("webui") },
		}
	}
	fetch := func(url string, timeout float64) (int, []byte, error) {
		a, ok := c.Github[url]
		switch {
		case !ok:
			return 0, nil, unresolved
		case a.Error != nil:
			return 0, nil, errors.New("<urlopen error " + *a.Error + ">")
		case a.Status >= 400:
			return a.Status, nil, nil
		case a.Body != nil:
			return 200, []byte(*a.Body), nil
		}
		return 200, unhexU(t, *a.Data), nil
	}

	norm := func(s string) string {
		return goTmp.ReplaceAllString(strings.ReplaceAll(s, root, "@ROOT@"), "/@TMP@/")
	}
	switch c.Op {
	case "helper":
		repo := c.Repo
		if repo == "" {
			repo = apply.DefaultUpdateRepo
		}
		u := &UpdateServer{Sys: sys, Repo: repo, Policy: func() Policy { return Policy{FullUIDs: map[int]bool{0: true}} },
			Updater: func() *apply.Updater { return updater(repo) }}
		reply, err := u.Answer(bufio.NewReader(strings.NewReader(c.Request+"\n")), 1, 0)
		if err != nil {
			t.Fatalf("no reply: %v", err)
		}
		b, err := json.Marshal(reply)
		if err != nil {
			t.Fatal(err)
		}
		var got, want any
		if err := json.Unmarshal([]byte(norm(string(b))), &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(c.Reply, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("reply\n got  %v\n want %v", got, want)
		}
	case "cli":
		s := NewServer()
		s.Env.Sys = sys
		s.Env.Installed = c.Installed
		s.Env.Fetch = fetch
		s.Env.Updater = updater
		argv := make([]string, len(c.Argv))
		for i, a := range c.Argv {
			argv[i] = strings.ReplaceAll(a, "@ROOT@", root)
		}
		var stdout, stderr bytes.Buffer
		code := s.CLI(argv, &stdout, &stderr)
		gotErr, wantErr := norm(stderr.String()), c.Stderr
		// What is wrong with an answer that isn't JSON is told by each
		// side's own parser (decisions.md, "phase 4f-4b").
		if i := strings.Index(wantErr, "/releases/latest: "); i >= 0 && strings.Contains(wantErr, "invalid JSON from") &&
			strings.HasPrefix(gotErr, wantErr[:i]) {
			gotErr, wantErr = gotErr[:i], wantErr[:i]
		}
		if code != *c.Code || norm(stdout.String()) != c.Stdout || gotErr != wantErr {
			t.Errorf("exit %d\n%s%s\nwant exit %d\n%s%s", code, stdout.String(), stderr.String(), *c.Code, c.Stdout,
				c.Stderr)
		}
	default:
		t.Fatalf("unknown op %q", c.Op)
	}

	if !slices.Equal(steps, c.Steps) && (len(steps) != 0 || len(c.Steps) != 0) {
		t.Errorf("steps\n got  %q\n want %q", steps, c.Steps)
	}
	read := func(path string) *string {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s := norm(string(b))
		return &s
	}
	if got := read(sys.Paths.UpdateState); !sameText(got, c.StateAfter) {
		t.Errorf("state file\n got  %s\n want %s", show(got), show(c.StateAfter))
	}
	if got := read(sys.Paths.UpdateCheck); !sameText(got, c.CheckCacheAfter) {
		t.Errorf("check cache\n got  %s\n want %s", show(got), show(c.CheckCacheAfter))
	}
	cache := map[string][]string{}
	if dirs, err := os.ReadDir(sys.Paths.Releases); err == nil {
		for _, d := range dirs {
			if !d.IsDir() {
				cache[d.Name()] = nil
				continue
			}
			files, _ := os.ReadDir(filepath.Join(sys.Paths.Releases, d.Name()))
			names := []string{}
			for _, f := range files {
				if f.Name() != "src" {
					names = append(names, f.Name())
				}
			}
			cache[d.Name()] = names
		}
	}
	if len(cache) != 0 || len(c.CacheAfter) != 0 {
		if !reflect.DeepEqual(cache, c.CacheAfter) {
			t.Errorf("releases cache\n got  %v\n want %v", cache, c.CacheAfter)
		}
	}
	var alerts []reference.UpdateAlert
	if b, err := os.ReadFile(sys.Paths.AuditLog); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			var e struct{ Alert, User, Client string }
			if err := json.Unmarshal([]byte(line), &e, json.MatchCaseInsensitiveNames(true)); err != nil {
				t.Fatal(err)
			}
			if e.Alert != "" {
				alerts = append(alerts, reference.UpdateAlert{Message: norm(e.Alert), User: e.User, Client: e.Client})
			}
		}
	}
	if len(alerts) != 0 || len(c.Alerts) != 0 {
		if !reflect.DeepEqual(alerts, c.Alerts) {
			t.Errorf("alerts\n got  %v\n want %v", alerts, c.Alerts)
		}
	}
}

func sameText(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func show(s *string) string {
	if s == nil {
		return "(none)"
	}
	return *s
}

func unhexU(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
