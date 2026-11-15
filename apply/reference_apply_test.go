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
	"sync"
	"syscall"
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
	// persistName is the persistence filesystem's temporary mount point.
	persistName *regexp.Regexp
	// passwords answer the step's password prompts, in order.
	passwords []string
	passed    map[int]int
	// xdp answers the step's fr-xdp calls, in order (reference_xdp_test.go).
	xdp []xdpAnswer
	// accounts are the case's users and groups (nil: none), made the
	// number created so far.
	accounts *reference.ApplyAccounts
	made     int
}

// firstID is the first id an account the case creates gets.
const firstID = 64900

// accountChange is what useradd, groupadd, usermod and gpasswd change,
// as the recording's fake does.
func (f *fakeSystem) accountChange(argv []string) {
	a := f.accounts
	n := len(argv)
	switch {
	case n >= 3 && argv[0] == "useradd" && argv[n-2] == "--":
		id := firstID + f.made
		f.made++
		a.Users[argv[n-1]] = id
		if slices.Contains(argv, "--user-group") {
			a.Groups[argv[n-1]] = &reference.ApplyGroup{GID: id}
		}
	case n >= 3 && argv[0] == "groupadd" && argv[n-2] == "--":
		id := firstID + f.made
		f.made++
		a.Groups[argv[n-1]] = &reference.ApplyGroup{GID: id}
	case n >= 6 && slices.Equal(argv[:3], []string{"usermod", "--append", "--groups"}) && argv[n-2] == "--" &&
		a.Groups[argv[3]] != nil:
		g := a.Groups[argv[3]]
		g.Members = append(g.Members, argv[n-1])
	case n >= 4 && argv[0] == "gpasswd" && argv[1] == "--delete" && a.Groups[argv[3]] != nil:
		g := a.Groups[argv[3]]
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == argv[2] })
	}
}

func (f *fakeSystem) user(name string) (int, bool) {
	if f.accounts == nil {
		return 0, false
	}
	uid, ok := f.accounts.Users[name]
	return uid, ok
}

func (f *fakeSystem) group(name string) (int, []string, bool) {
	if f.accounts == nil || f.accounts.Groups[name] == nil {
		return 0, nil, false
	}
	g := f.accounts.Groups[name]
	return g.GID, slices.Clone(g.Members), true
}

// chown changes nothing; with the case's accounts it is recorded as a
// call ["chown", path, uid, gid].
func (f *fakeSystem) chown(path string, uid, gid int) error {
	if f.accounts != nil {
		f.calls = append(f.calls, call{argv: []string{"chown", f.norm(path), strconv.Itoa(uid), strconv.Itoa(gid)}})
	}
	return nil
}

type call struct {
	argv    []string
	stdin   string
	timeout time.Duration
}

// norm is s as the recording writes it.
func (f *fakeSystem) norm(s string) string {
	s = strings.ReplaceAll(s, f.root, "@ROOT@")
	s = f.persistName.ReplaceAllString(s, "@TMP@/fros-persistence-*")
	s = f.tmpName.ReplaceAllString(s, "@TMP@/tmp*")
	return strings.ReplaceAll(s, f.tmp+"/", "@TMP@/")
}

func (f *fakeSystem) run(c apply.Cmd) (apply.Result, error) {
	argv := make([]string, len(c.Argv))
	for i, a := range c.Argv {
		argv[i] = f.norm(a)
	}
	f.calls = append(f.calls, call{argv, c.Stdin, c.Timeout})
	if len(argv) > 0 && argv[0] == apply.XdpTool {
		if len(f.xdp) == 0 || !slices.Equal(f.xdp[0].argv, argv) {
			return apply.Result{Code: 1, Stderr: "the recording made no such call\n"}, nil
		}
		a := f.xdp[0]
		f.xdp = f.xdp[1:]
		return a.res, a.err
	}
	res := apply.Result{}
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
			res = apply.Result{Stdout: a.Stdout, Stderr: a.Stderr, Code: a.RC}
			break
		}
	}
	if res.Code == 0 && f.accounts != nil {
		f.accountChange(argv)
	}
	return res, nil
}

// gro and setGRO are the GRO ioctl as the recording's pseudo-call: rc
// the errno, stdout the value.
func (f *fakeSystem) gro(device string) (bool, error) {
	r, err := f.run(apply.Cmd{Argv: []string{"ioctl", "SIOCETHTOOL", device, "ETHTOOL_GGRO"}})
	if err == nil && r.Code != 0 {
		err = syscall.Errno(r.Code)
	}
	return strings.TrimSpace(r.Stdout) == "1", err
}

func (f *fakeSystem) setGRO(device string, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	r, err := f.run(apply.Cmd{Argv: []string{"ioctl", "SIOCETHTOOL", device, "ETHTOOL_SGRO", v}})
	if err == nil && r.Code != 0 {
		err = syscall.Errno(r.Code)
	}
	return err
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
	// A temporary directory of the case's own: what an apply leaves
	// there (a persistence mount point the fake's mount never mounted)
	// goes with it.
	t.Setenv("TMPDIR", t.TempDir())
	tmp := filepath.Clean(os.TempDir())
	f := &fakeSystem{root: root, tmp: tmp, table: c.Table, random: random, passed: map[int]int{},
		tmpName:     regexp.MustCompile(regexp.QuoteMeta(tmp) + `/tmp[A-Za-z0-9_]+`),
		persistName: regexp.MustCompile(regexp.QuoteMeta(tmp) + `/fros-persistence-[A-Za-z0-9_]+`)}
	if c.Accounts != nil {
		f.accounts = &reference.ApplyAccounts{Users: maps.Clone(c.Accounts.Users), Groups: map[string]*reference.ApplyGroup{}}
		for name, g := range c.Accounts.Groups {
			f.accounts.Groups[name] = &reference.ApplyGroup{GID: g.GID, Members: slices.Clone(g.Members)}
		}
	}
	materialize(t, root, c.Setup)

	sec, frac := math.Modf(c.Now)
	now := time.Unix(int64(sec), int64(frac*1e9))
	sys := apply.DefaultSystem()
	sys.Paths = apply.DefaultPaths().Under(root)
	sys.Run = f.run
	sys.GRO = f.gro
	sys.SetGRO = f.setGRO
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
	sys.Chown = f.chown
	sys.User = f.user
	sys.Group = f.group
	sys.Fetch = func(url string) ([]byte, error) { return fetchAnswer(c.Fetch, url) }
	// The DHCP probe is the recording's pseudo-call ["dhcp-offer", device]:
	// its output is the network offered, none when nothing answered.
	// The ports are asked at once (as 1.x's thread pool; the recording
	// asked them in order): checkCalls compares a run of probes as a set.
	var probing sync.Mutex
	sys.ProbeDHCP = func(device string) (string, bool) {
		probing.Lock()
		defer probing.Unlock()
		r, err := f.run(apply.Cmd{Argv: []string{"dhcp-offer", device}})
		network := strings.TrimSpace(r.Stdout)
		return network, err == nil && r.Code == 0 && network != ""
	}
	// The kernel commands' system calls are the recording's
	// pseudo-calls: ["statvfs", path] (stdout the free bytes),
	// ["connect", host, port, timeout] (rc 0: it answered) and
	// ["sleep", seconds], which moves a clock of their own from 0.
	sys.KernelRelease = func() string { return "6.1.0-26-amd64" }
	sys.DiskFree = func(path string) (uint64, error) {
		r, err := f.run(apply.Cmd{Argv: []string{"statvfs", path}})
		if err != nil {
			return 0, err
		}
		if r.Code != 0 {
			return 0, syscall.Errno(r.Code)
		}
		n, _ := strconv.ParseUint(strings.TrimSpace(r.Stdout), 10, 64)
		return n, nil
	}
	sys.Dial = func(host string, port int, timeout time.Duration) error {
		r, err := f.run(apply.Cmd{Argv: []string{"connect", host, strconv.Itoa(port),
			strconv.FormatFloat(timeout.Seconds(), 'f', -1, 64)}})
		if err == nil && r.Code != 0 {
			err = syscall.Errno(r.Code)
		}
		return err
	}
	healthClock := 0.0
	sys.HealthClock = func() float64 { return healthClock }
	sys.HealthSleep = func(seconds float64) {
		f.run(apply.Cmd{Argv: []string{"sleep", config.FloatRepr(seconds)}})
		healthClock += seconds
	}
	sys.Getpass = func(string) (string, error) {
		if len(f.passwords) == 0 {
			return "", apply.ErrNoInput
		}
		p := f.passwords[0]
		f.passwords = f.passwords[1:]
		return p, nil
	}
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

	bpftool := map[int]int{} // the table's bpftool answers given
	for i, step := range c.Steps {
		start := len(f.calls)
		calls, answers := translateXDP(c.Table, bpftool, step.Calls)
		f.xdp = answers
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
		} else if argv, passwords, ok := cliOf(t, step.Request); ok {
			f.passwords = passwords
			// firewall-cli: its exit status and what it printed.
			for i := range argv {
				argv[i] = strings.ReplaceAll(argv[i], "@ROOT@", root)
			}
			var stdout, stderr strings.Builder
			code := s.CLI(argv, &stdout, &stderr)
			where := fmt.Sprintf("step %d %s", i, step.Request)
			checkCalls(t, where, f.calls[start:], calls)
			checkCLI(t, where, step, code, f.norm(stdout.String()), f.norm(stderr.String()))
			continue
		} else {
			line := append(bytes.Clone(step.Request), '\n')
			got, err = s.Answer(bufio.NewReader(bytes.NewReader(line)), 1, 0)
		}
		where := fmt.Sprintf("step %d %s", i, step.Request)
		checkCalls(t, where, f.calls[start:], calls)
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
			want := strings.ReplaceAll(string(step.Reply), bpftoolMissing, xdpToolMissing)
			if !sameJSON(t, f.norm(text), want) && !samePythonJSONError(text, want) {
				t.Errorf("%s:\n%s", where, replyDiff(f.norm(text), want))
			}
		}
	}
	checkTree(t, f, snapshot(t, f, root), c.Files)
}

// pythonJSONError is a message quoting Python's json error, which 2.x
// words its own way after the same prefix (decisions.md, "the helper's
// requests").
var pythonJSONError = regexp.MustCompile(`^(could not parse ip neigh output: |could not read the IPv6 state: |invalid request: )` +
	`.*: line \d+ column \d+ \(char \d+\)$`)

func samePythonJSONError(got, want string) bool {
	msg := func(text string) (string, bool) {
		v, _ := config.ParseJSON([]byte(text))
		m, _ := v.(*config.Map)
		if m == nil {
			return "", false
		}
		s, _ := m.Get("message")
		str, _ := s.(string)
		return str, okOf(text)
	}
	gm, gok := msg(got)
	wm, wok := msg(want)
	m := pythonJSONError.FindStringSubmatch(wm)
	return m != nil && !gok && !wok && strings.HasPrefix(gm, m[1])
}

// cliOf is a firewall-cli step's argv, and the answers its password
// prompts get.
func cliOf(t *testing.T, request jsontext.Value) ([]string, []string, bool) {
	var r map[string]any
	if err := json.Unmarshal(request, &r); err != nil {
		t.Fatal(err)
	}
	list, ok := r["cli"].([]any)
	if !ok {
		return nil, nil, false
	}
	strs := func(list []any) []string {
		out := make([]string, len(list))
		for i, a := range list {
			out[i] = a.(string)
		}
		return out
	}
	passwords, _ := r["passwords"].([]any)
	return strs(list), strs(passwords), true
}

// cliReply is what a firewall-cli step recorded.
type cliReply struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// checkCLI holds firewall-cli to 1.x: the same exit status and output.
// A command line argparse refuses (2) is held to its status only: the
// usage text is 2.x's own; and where 1.x died on an exception
// (traceback), 2.x exits 1 with a line saying what (decisions.md,
// "phase 4f-1").
func checkCLI(t *testing.T, where string, step reference.ApplyStep, code int, stdout, stderr string) {
	t.Helper()
	if step.Raised != "" {
		if code != 1 {
			t.Errorf("%s: 1.x raised %s (%s); exit %d, want 1\nstdout %q\nstderr %q", where, step.Raised, step.Error,
				code, stdout, stderr)
		}
		return
	}
	var want cliReply
	if err := json.Unmarshal(step.Reply, &want); err != nil {
		t.Fatal(err)
	}
	if code != want.Code {
		t.Errorf("%s: exit %d, want %d\nstdout %q\nstderr %q\nwant stdout %q\nwant stderr %q", where, code,
			want.Code, stdout, stderr, want.Stdout, want.Stderr)
		return
	}
	if want.Code == 2 {
		return
	}
	if stdout != want.Stdout {
		t.Errorf("%s: stdout\n got %q\nwant %q", where, short(stdout), short(want.Stdout))
	}
	if stderr != want.Stderr {
		t.Errorf("%s: stderr\n got %q\nwant %q", where, short(stderr), short(want.Stderr))
	}
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
	got = slices.Clone(got)
	sortProbes(got)
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

// sortProbes puts each run of DHCP probes (["dhcp-offer", device],
// asked of every port at once) in the order of their devices, the order
// the recording asked them in.
func sortProbes(calls []call) {
	probe := func(c call) bool { return len(c.argv) == 2 && c.argv[0] == "dhcp-offer" }
	for i := 0; i < len(calls); {
		j := i
		for j < len(calls) && probe(calls[j]) {
			j++
		}
		if j == i {
			i++
			continue
		}
		slices.SortStableFunc(calls[i:j], func(a, b call) int { return strings.Compare(a.argv[1], b.argv[1]) })
		i = j
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
		if x["any"] == true {
			return true
		}
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
		case e.Link != "":
			if err := os.Symlink(e.Link, path); err != nil {
				t.Fatal(err)
			}
			continue
		case e.Size > 0:
			mode, _ := strconv.ParseUint(strings.TrimPrefix(e.Mode, "0o"), 8, 32)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fs.FileMode(mode))
			if err == nil {
				err = f.Truncate(e.Size)
				f.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			os.Chmod(path, fs.FileMode(mode))
			continue
		case e.Text != nil && strings.Contains(*e.Text, setupFingerprint):
			data = []byte(strings.ReplaceAll(*e.Text, setupFingerprint, fingerprintOf(t, root, files)))
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

// setupFingerprint is, in a setup file, the fingerprint of the setup's
// config.yaml as each implementation computes its own (decisions.md,
// "The schedule record's fingerprint").
const setupFingerprint = "@FP@"

func fingerprintOf(t *testing.T, root string, files map[string]*reference.ApplyFile) string {
	e := files["etc/fr_os/config.yaml"]
	if e == nil || e.Text == nil {
		t.Fatal("a fingerprint with no config.yaml")
	}
	raw, err := config.LoadYAML(*e.Text)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := apply.ConfigFingerprint(c)
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func snapshot(t *testing.T, f *fakeSystem, root string) map[string]*reference.ApplyFile {
	out := map[string]*reference.ApplyFile{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.Type()&fs.ModeSymlink != 0 { // never followed
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			out[rel] = &reference.ApplyFile{Link: f.norm(target)}
			return nil
		}
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
		case w.Link != "" || g.Link != "":
			if g.Link != w.Link {
				t.Errorf("%s: link %q, want %q", rel, g.Link, w.Link)
			}
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
		if _, ok := want[rel]; !ok && rel != sensorView {
			t.Errorf("extra %s", rel)
		}
	}
	// decisions.md, "phase 4e-1": 2.x writes the sensors' view of the
	// copy next to it, which 1.x's daemons computed from the copy.
	w, wok := want[sensorCopy]
	g, gok := got[sensorView]
	switch {
	case !wok && gok:
		t.Errorf("%s without %s", sensorView, sensorCopy)
	case wok && (w == nil || w.Text == nil):
		t.Errorf("%s: not text", sensorCopy)
	case wok && !gok:
		t.Errorf("missing %s", sensorView)
	case wok:
		raw, err := config.LoadYAML(strings.TrimPrefix(*w.Text, apply.SensorCopyHeader))
		if err != nil {
			t.Fatalf("%s: %v", sensorCopy, err)
		}
		if want := apply.SensorView(raw); g.Text == nil || *g.Text != want {
			t.Errorf("%s: got %v, want %q", sensorView, g.Text, want)
		}
		if g.Mode != w.Mode {
			t.Errorf("%s: mode %s, want %s as the copy's", sensorView, g.Mode, w.Mode)
		}
	}
}

const (
	sensorCopy = "etc/fr_os/sensor-config.yaml"
	sensorView = "etc/fr_os/sensor-view.json"
)

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

// fetchAnswer is the case's answer for a download: a body, or a failed
// one (1.x reports a failure by its URL alone).
func fetchAnswer(table []reference.ApplyFetch, url string) ([]byte, error) {
	for _, a := range table {
		if a.URL != url {
			continue
		}
		switch {
		case a.Status != 0:
			return nil, fmt.Errorf("HTTP Error %d: %s", a.Status, a.Reason)
		case a.Error != "":
			return nil, errors.New(a.Error)
		case a.Body != nil:
			return []byte(*a.Body), nil
		}
		return hex.DecodeString(a.Hex)
	}
	return nil, errors.New("not in the case's table")
}
