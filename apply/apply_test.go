package apply

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// kind is an exception with no text, named by its type.
type kind string

func (k kind) Error() string { return "" }
func (k kind) Kind() string  { return string(k) }

// TestErrorText: what an apply reports, word for word what FR_OS 1.x's
// ApplyError says (each want printed by 1.x at reference/PIN).
func TestErrorText(t *testing.T) {
	for _, tc := range []struct {
		err  Error
		want string
	}{
		{Error{Step: "the firewall", Cause: errors.New("bad")},
			"Nothing was applied -- the firewall: bad. The running system is unchanged."},
		{Error{Step: "DHCP (Kea)", Cause: errors.New("kea failed"), Changed: true, RolledBack: []string{"DHCP (Kea)", "the firewall"}},
			"Apply failed at DHCP (Kea): kea failed. Rolled back to the previous state: DHCP (Kea), the firewall. Nothing else was changed."},
		{Error{Step: "IPv6", Cause: kind("E"), Changed: true, NotRolledBack: []string{"the firewall (nothing was loaded before it)"}},
			"Apply failed at IPv6: E. NOT rolled back: the firewall (nothing was loaded before it)."},
		{Error{Step: "x", Cause: errors.New("é"), Changed: true, RolledBack: []string{"a"}, NotRolledBack: []string{"b (c)", "d (e)"}},
			"Apply failed at x: é. Rolled back to the previous state: a. NOT rolled back: b (c); d (e)."},
	} {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("got  %q\nwant %q", got, tc.want)
		}
	}
}

// TestRollBack: last first, an undo that fails or can't be done is
// reported by name and the rest still run (1.x's answer:
// (('five', 'one'), ('four (no)', 'three (E)', 'two (why)'))).
func TestRollBack(t *testing.T) {
	var tx Transaction
	var ran []string
	ok := func(name string) func() error { return func() error { ran = append(ran, name); return nil } }
	tx.Begin("one", ok("one"), "")
	tx.Begin("two", nil, "why")
	tx.Begin("three", func() error { return kind("E") }, "")
	tx.Begin("four", func() error { panic("no") }, "")
	tx.Begin("five", ok("five"), "")
	done, failed := tx.RollBack()
	if !slices.Equal(done, []string{"five", "one"}) || !slices.Equal(failed, []string{"four (no)", "three (E)", "two (why)"}) {
		t.Errorf("RollBack = %q, %q", done, failed)
	}
	if !slices.Equal(ran, []string{"five", "one"}) {
		t.Errorf("ran %q", ran)
	}
	if done, failed := tx.RollBack(); done != nil || failed != nil {
		t.Error("the journal was not emptied")
	}
}

// TestValidate: 1.x's messages for refused values.
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		f    func(string) (string, error)
		in   string
		want string
	}{
		{Ifname, "-x", "invalid interface name '-x'"},
		{Ifname, ".", "invalid interface name '.'"},
		{Ifname, "é", "invalid interface name 'é'"},
		{Ifname, "eth0\n", "invalid interface name 'eth0\\n'"},
		{SystemdUnit, "a b", "invalid systemd unit name 'a b'"},
		{SystemctlAction, "kill", "systemctl action 'kill' is not one frfw uses"},
		{IPv4Interface, "10.0.0.1/255.0.0.0", "invalid IPv4 address/prefix '10.0.0.1/255.0.0.0'"},
	} {
		if _, err := tc.f(tc.in); err == nil || err.Error() != tc.want {
			t.Errorf("%q: %v, want %q", tc.in, err, tc.want)
		}
	}
	for _, ok := range []string{"eth0", "eth1.30", "wg0"} {
		if _, err := Ifname(ok); err != nil {
			t.Error(err)
		}
	}
	if !slices.Equal(NftArgv("-c", "-f", "-"), []string{"nft", "-c", "-f", "-"}) ||
		!slices.Equal(NftArgv("list", "table", "inet", "-x"), []string{"nft", "--", "list", "table", "inet", "-x"}) ||
		!slices.Equal(NftArgv("-j", "list", "ruleset"), []string{"nft", "-j", "--", "list", "ruleset"}) {
		t.Error("NftArgv")
	}
}

// recorder answers each program from a table and records the argv.
type recorder struct {
	calls   [][]string
	answers map[string]Result // by argv joined with spaces
	missing bool              // no such program
}

func (r *recorder) run(c Cmd) (Result, error) {
	r.calls = append(r.calls, c.Argv)
	if r.missing {
		return Result{}, ErrNotFound
	}
	return r.answers[strings.Join(c.Argv, " ")], nil
}

// TestSystemctl: `--` before the unit, --no-block while booting.
func TestSystemctl(t *testing.T) {
	r := &recorder{answers: map[string]Result{"systemctl is-system-running": {Stdout: "running\n"}}}
	if _, err := Systemctl(r.run, "restart", "kea-dhcp4-server", 0); err != nil {
		t.Fatal(err)
	}
	r.answers["systemctl is-system-running"] = Result{Stdout: "starting\n"}
	Systemctl(r.run, "restart", "kea-dhcp4-server", 0)
	if !slices.Equal(r.calls[1], []string{"systemctl", "restart", "--", "kea-dhcp4-server"}) ||
		!slices.Equal(r.calls[3], []string{"systemctl", "--no-block", "restart", "--", "kea-dhcp4-server"}) {
		t.Errorf("%q", r.calls)
	}
	if _, err := Systemctl(r.run, "restart", "--force", 0); err == nil {
		t.Error("an option as a unit")
	}
}

// TestServiceState: back to running (restarted when its config changed)
// or stopped; nothing without systemd.
func TestServiceState(t *testing.T) {
	r := &recorder{answers: map[string]Result{
		"systemctl is-active -- kea": {Stdout: "active\n"},
	}}
	s, _ := CaptureService(r.run, "kea")
	if !s.Known || !s.Active {
		t.Fatalf("%+v", s)
	}
	for _, tc := range []struct {
		changed bool
		how     string
		want    string
	}{{false, "restart", "start"}, {true, "restart", "restart"}, {true, "reload-or-restart", "reload-or-restart"}} {
		r.calls = nil
		if err := s.Restore(r.run, tc.changed, tc.how); err != nil {
			t.Fatal(err)
		}
		if last := r.calls[len(r.calls)-1]; !slices.Equal(last, []string{"systemctl", tc.want, "--", "kea"}) {
			t.Errorf("%v: %q", tc, last)
		}
	}
	stopped := ServiceState{"kea", true, false}
	r.calls = nil
	stopped.Restore(r.run, true, "restart") // running now: stopped
	if last := r.calls[len(r.calls)-1]; !slices.Equal(last, []string{"systemctl", "stop", "--", "kea"}) {
		t.Errorf("%q", last)
	}
	r.answers["systemctl is-active -- kea"] = Result{Stdout: "inactive\n", Code: 3}
	r.calls = nil
	stopped.Restore(r.run, true, "restart") // stopped already: nothing
	for _, c := range r.calls {
		if c[1] == "stop" {
			t.Error("stopped a stopped unit")
		}
	}
	r.answers["systemctl start -- kea"] = Result{Code: 1, Stderr: "Job failed.\n"}
	if err := s.Restore(r.run, false, "restart"); err == nil || err.Error() != "Job failed." {
		t.Errorf("%v", err)
	}
	none := &recorder{missing: true}
	if s, err := CaptureService(none.run, "kea"); err != nil || s.Known {
		t.Errorf("%+v %v", s, err)
	}
}

// TestLinkState: what the address step added comes off, what it removed
// goes back, a device it created goes away (from `ip -j addr show`).
func TestLinkState(t *testing.T) {
	show := "ip -j addr show dev eth1"
	r := &recorder{answers: map[string]Result{show: {Stdout: `[{"ifname":"eth1","flags":["BROADCAST","MULTICAST"],` +
		`"addr_info":[{"family":"inet","local":"10.0.0.1","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]}]`}}}
	before, err := CaptureLink(r.run, "eth1")
	if err != nil || !before.Exists || before.Up || !slices.Equal(before.Addresses, []string{"10.0.0.1/24"}) {
		t.Fatalf("%+v %v", before, err)
	}
	r.answers[show] = Result{Stdout: `[{"flags":["UP"],"addr_info":[{"family":"inet","local":"10.73.1.1","prefixlen":24}]}]`}
	r.calls = nil
	if err := before.Restore(r.run); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"ip", "-j", "addr", "show", "dev", "eth1"}, {"ip", "addr", "del", "10.73.1.1/24", "dev", "eth1"},
		{"ip", "addr", "add", "10.0.0.1/24", "dev", "eth1"}, {"ip", "link", "set", "dev", "eth1", "down"}}
	if !slices.EqualFunc(r.calls, want, slices.Equal) {
		t.Errorf("%q", r.calls)
	}
	created := LinkState{Device: "eth1"}
	r.calls = nil
	created.Restore(r.run)
	if last := r.calls[len(r.calls)-1]; !slices.Equal(last, []string{"ip", "link", "del", "dev", "eth1"}) {
		t.Errorf("%q", last)
	}
	if _, err := CaptureLink(r.run, "-eth1"); err == nil {
		t.Error("an option as a device")
	}
}

// TestFileState: a file put back with its bytes, mode and owner, or
// removed when there was none.
func TestFileState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kea-dhcp4.conf")
	none, _ := CaptureFile(path)
	os.WriteFile(path, []byte("new"), 0o600)
	if d, _ := none.Differs(); !d {
		t.Error("a new file reads as unchanged")
	}
	if err := none.Restore(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("not removed")
	}
	os.WriteFile(path, []byte("old\n"), 0o640)
	if os.Geteuid() == 0 {
		os.Chown(path, 0, 65534)
	}
	syscall.Chmod(path, 0o2640) // the raw bits: os.Chmod ignores 0o2000
	old, err := CaptureFile(path)
	if err != nil || old.Mode != 0o2640 {
		t.Fatalf("%+v %v", old, err)
	}
	os.WriteFile(path, []byte("changed"), 0o644)
	os.Chmod(path, 0o644)
	if d, _ := old.Differs(); !d {
		t.Error("a changed file reads as unchanged")
	}
	if err := old.Restore(); err != nil {
		t.Fatal(err)
	}
	if d, _ := old.Differs(); d {
		t.Error("not restored")
	}
	if os.Geteuid() == 0 {
		st, _ := os.Stat(path)
		if st.Sys().(*syscall.Stat_t).Gid != 65534 {
			t.Error("owner not restored")
		}
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*")); len(left) != 0 {
		t.Errorf("left behind %q", left)
	}
}

// TestWrites: the applied config's record is root's alone; config.yaml
// keeps its owner and mode across a save.
func TestWrites(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "sub", "applied-config.yaml")
	if err := WritePrivate(record, "a: 1\n"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(record); st.Mode().Perm() != 0o600 {
		t.Errorf("record mode %v", st.Mode())
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := WriteKeepingOwner(cfg, "version: 1\n"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(cfg); st.Mode().Perm() != 0o640 {
		t.Errorf("new config mode %v", st.Mode())
	}
	os.Chmod(cfg, 0o600)
	if os.Geteuid() == 0 {
		os.Chown(cfg, 0, 65534)
	}
	if err := WriteKeepingOwner(cfg, "version: 1\nhostname: r\n"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(cfg)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode not kept: %v", st.Mode())
	}
	if os.Geteuid() == 0 && st.Sys().(*syscall.Stat_t).Gid != 65534 {
		t.Error("group not kept")
	}
	if b, _ := os.ReadFile(cfg); string(b) != "version: 1\nhostname: r\n" {
		t.Errorf("%q", b)
	}
}

// netnsRun runs every program in one network namespace of its own, so a
// real nft loads rulesets into a kernel nobody else uses. Root only.
func netnsRun(t *testing.T) Runner {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	ns := filepath.Join(t.TempDir(), "netns")
	if err := os.WriteFile(ns, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("unshare", "--net="+ns, "true").CombinedOutput(); err != nil {
		t.Skipf("no network namespace: %v %s", err, out)
	}
	t.Cleanup(func() { exec.Command("umount", ns).Run() })
	return func(c Cmd) (Result, error) {
		c.Argv = append([]string{"nsenter", "--net=" + ns, "--"}, c.Argv...)
		return Run(c)
	}
}

const ruleset = `flush ruleset
table inet fr_os {
	set jail { type ipv4_addr; flags timeout; }
	chain input { type filter hook input priority filter; policy accept; }
}
`

// TestRealNft: check, load with a backup of the running ruleset, keep
// only the newest backups, roll back to the last one, the baseline, and
// a captured ruleset put back with its set members' time left.
func TestRealNft(t *testing.T) {
	run := netnsRun(t)
	dir := t.TempDir()
	if err := CheckSyntax(run, "table inet x { chain y { nonsense } }"); err == nil {
		t.Error("nft -c took nonsense")
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	msg, backup, err := ApplyRuleset(run, ruleset, false, dir, 2, now)
	if err != nil || backup != "" || msg != "Ruleset applied" {
		t.Fatalf("first load: %q %q %v", msg, backup, err)
	}
	if !TableLoaded(run) {
		t.Fatal("table not loaded")
	}
	for i := 1; i <= 3; i++ {
		msg, backup, err = ApplyRuleset(run, strings.Replace(ruleset, "policy accept", "policy drop", 1), false, dir, 2, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	if want := filepath.Join(dir, "ruleset-20261108T120003Z.nft"); backup != want || msg != "Ruleset applied (previous ruleset backed up to "+want+")" {
		t.Errorf("%q %q", msg, backup)
	}
	backups, _ := ListBackups(dir)
	if len(backups) != 2 || filepath.Base(backups[0]) != "ruleset-20261108T120002Z.nft" {
		t.Errorf("kept %q", backups)
	}
	first, _ := os.ReadFile(backups[0])
	if !strings.HasPrefix(string(first), "flush ruleset\n\n") {
		t.Errorf("backup %q", first)
	}
	if _, _, err := ApplyRuleset(run, "table inet fr_os { chain c { nonsense } }", false, dir, 2, now.Add(time.Hour)); err == nil {
		t.Error("a bad ruleset loaded")
	}
	if b, _ := ListBackups(dir); len(b) != 2 {
		t.Error("a refused ruleset made a backup")
	}
	if _, err := runNft(run, "", "add", "element", "inet", "fr_os", "jail", "{ 192.0.2.7 timeout 1h }"); err != nil {
		t.Fatal(err)
	}
	captured, err := CaptureRuleset(run)
	if err != nil || !strings.Contains(captured, "192.0.2.7") {
		t.Fatalf("%v\n%s", err, captured)
	}
	if err := LoadBaseline(run); err != nil {
		t.Fatal(err)
	}
	if listing, _ := CaptureRuleset(run); strings.Contains(listing, "jail") || !strings.Contains(listing, "nd-neighbor-solicit") {
		t.Errorf("baseline:\n%s", listing)
	}
	if err := LoadCaptured(run, captured); err != nil {
		t.Fatal(err)
	}
	if listing, _ := CaptureRuleset(run); !strings.Contains(listing, "192.0.2.7") || !strings.Contains(listing, "expires") {
		t.Errorf("captured not back:\n%s", listing)
	}
	latest, err := RollbackLast(run, dir)
	if err != nil || latest != backups[1] {
		t.Fatalf("%q %v", latest, err)
	}
	if _, err := RollbackLast(run, t.TempDir()); err == nil || !strings.HasPrefix(err.Error(), "No ruleset backups found in ") {
		t.Errorf("%v", err)
	}
	if msg, _, err := ApplyRuleset(run, ruleset, true, dir, 2, now); err != nil || msg != "Syntax OK (dry-run, not applied)" {
		t.Errorf("dry run: %q %v", msg, err)
	}
}

// TestNoNft: 1.x's message without the nftables package.
func TestNoNft(t *testing.T) {
	r := &recorder{missing: true}
	if err := CheckSyntax(r.run, ruleset); err == nil || err.Error() != "'nft' binary not found; install the nftables package" {
		t.Errorf("%v", err)
	}
	r = &recorder{answers: map[string]Result{"nft -c -f -": {Code: 1}}}
	if err := CheckSyntax(r.run, ruleset); err == nil || err.Error() != "nft exited with status 1" {
		t.Errorf("%v", err)
	}
}

func TestParseOpenSSLVersion(t *testing.T) {
	for out, want := range map[string]string{
		"OpenSSL 3.0.15 3 Sep 2024\n":                                     "OpenSSL 3.0.15 3 Sep 2024",
		"OpenSSL 3.5.1 1 Jul 2025 (Library: OpenSSL 3.0.15 3 Sep 2024)\n": "OpenSSL 3.0.15 3 Sep 2024",
	} {
		v, text := parseOpenSSLVersion(out)
		if text != want || v != [3]int{3, 0, 15} {
			t.Errorf("%q: %v %q", out, v, text)
		}
	}
	if v, text := parseOpenSSLVersion("LibreSSL x"); v != [3]int{} || text != "LibreSSL x" {
		t.Errorf("LibreSSL: %v %q", v, text)
	}
}
