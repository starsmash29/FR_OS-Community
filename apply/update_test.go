package apply

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/release"
	"github.com/starsmash29/fr_os-community/version"
)

// The installer on a real file tree under a temporary root: a release
// signed with a key made for the test, what lands where, the switch of
// /usr/libexec/fr_os, the programs systemd is asked to run, the state
// file, the refusals, and the way back.

type updateRig struct {
	t     *testing.T
	root  string
	sys   *System
	key   ed25519.PrivateKey
	keys  []release.Key
	calls [][]string
	fail  map[string]Result
}

func newUpdateRig(t *testing.T) *updateRig {
	t.Helper()
	root := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	r := &updateRig{t: t, root: root, key: key, fail: map[string]Result{},
		keys: []release.Key{{Name: "test.pem", Data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})}}}
	sys := DefaultSystem()
	sys.Paths = DefaultPaths().Under(root)
	sys.Now = func() time.Time { return time.Date(2026, 11, 16, 9, 0, 0, 250000000, time.UTC) }
	sys.Run = func(c Cmd) (Result, error) {
		r.calls = append(r.calls, c.Argv)
		return r.fail[strings.Join(c.Argv, " ")], nil
	}
	r.sys = sys
	return r
}

func (r *updateRig) updater(installed string) *Updater {
	return &Updater{Sys: r.sys, Repo: DefaultUpdateRepo, Installed: installed, Keys: r.keys,
		Download: func(url, dest string, max int64) error {
			return &DownloadError{Status: 404, Reason: "Not Found"}
		}}
}

type tarEntry struct {
	name, body string
	dir        bool
	mode       int64
	link       string
}

// releaseFiles is a release's tarball members, as package-release.sh
// packs installer/build-binaries.sh's stage.
func releaseFiles(v string) []tarEntry {
	top := "fr_os-" + v + "/"
	return []tarEntry{
		{name: top, dir: true},
		{name: top + "VERSION", body: v + "\n", mode: 0o644},
		{name: top + "bin/", dir: true},
		{name: top + "bin/firewall-cli", body: "cli " + v, mode: 0o755},
		{name: top + "bin/fr-update-helper", body: "updater " + v, mode: 0o755},
		{name: top + "bin/fr-webui", body: "webui " + v, mode: 0o755},
		{name: top + "bpf/xdp_sni_filter.o", body: "xdp " + v, mode: 0o644},
		{name: top + "scripts/fr-first-boot.sh", body: "#!/bin/sh\n# " + v, mode: 0o755},
		{name: top + "systemd/fr-webui.service", body: "[Unit]\n# " + v, mode: 0o644},
		{name: top + "systemd/journald-fr_os.conf", body: "[Journal]\n# " + v, mode: 0o644},
		{name: top + "systemd/sysctl-fr_os-ipv6.conf", body: "# " + v, mode: 0o644},
		{name: top + "bin/link", link: "/etc/shadow"},
	}
}

func tarball(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	w := tar.NewWriter(z)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: e.mode, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		switch {
		case e.dir:
			h.Typeflag, h.Mode, h.Size = tar.TypeDir, 0o755, 0
		case e.link != "":
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// signed is a release's three files: the tarball, its SHA256SUMS and the
// signature over it.
func (r *updateRig) signed(v string, entries []tarEntry) map[string][]byte {
	data := tarball(r.t, entries)
	sum := sha256.Sum256(data)
	sums := []byte(hex.EncodeToString(sum[:]) + "  " + release.TarballName(v) + "\n")
	return map[string][]byte{release.TarballName(v): data, release.SumsName: sums,
		release.SignatureName: ed25519.Sign(r.key, sums)}
}

// cache puts a release where a router keeps the verified ones.
func (r *updateRig) cache(v string, files map[string][]byte) {
	dir := filepath.Join(r.sys.Paths.Releases, v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			r.t.Fatal(err)
		}
	}
}

// image is what the image's hook installs for v: its directory, and the
// symlink to it.
func (r *updateRig) image(v string) {
	p := r.sys.Paths
	dir := filepath.Join(p.LibexecReleases, v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.t.Fatal(err)
	}
	for _, f := range []string{"firewall-cli", "fr-update-helper"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("image "+v), 0o755); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(v+"\n"), 0o644); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Symlink("fr_os-releases/"+v, p.Libexec); err != nil {
		r.t.Fatal(err)
	}
}

func (r *updateRig) read(path string) string {
	r.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	return string(data)
}

func (r *updateRig) link() string {
	target, err := os.Readlink(r.sys.Paths.Libexec)
	if err != nil {
		r.t.Fatal(err)
	}
	return target
}

func (r *updateRig) versions() []string {
	entries, _ := os.ReadDir(r.sys.Paths.LibexecReleases)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func wantRestarts() [][]string {
	calls := [][]string{{"systemctl", "daemon-reload"}}
	for _, unit := range UpdateServices {
		calls = append(calls, []string{"systemctl", "try-restart", "--", unit})
	}
	return append(calls, []string{"systemd-run", "--quiet", "--on-active=3", "--unit=fr-webui-restart", "systemctl",
		"try-restart", "--", "fr-webui.service"})
}

func TestAnUpdateInstallsTheSignedReleaseAndRollsBack(t *testing.T) {
	r := newUpdateRig(t)
	p := r.sys.Paths
	r.image("2.0.0")
	r.cache("2.0.1", r.signed("2.0.1", releaseFiles("2.0.1")))
	if err := os.MkdirAll(filepath.Join(p.LibexecReleases, "1.9.0"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := r.updater("2.0.0").Apply("2.0.1")
	if err != nil || got != "2.0.1" {
		t.Fatalf("apply: %q %v", got, err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.1" {
		t.Errorf("/usr/libexec/fr_os -> %s", link)
	}
	for path, want := range map[string]string{
		filepath.Join(p.Libexec, "firewall-cli"):          "cli 2.0.1",
		filepath.Join(p.Libexec, "fr-first-boot.sh"):      "#!/bin/sh\n# 2.0.1",
		filepath.Join(p.Libexec, "VERSION"):               "2.0.1\n",
		filepath.Join(p.SystemdUnits, "fr-webui.service"): "[Unit]\n# 2.0.1",
		p.JournaldDropin: "[Journal]\n# 2.0.1",
		p.SysctlIPv6:     "# 2.0.1",
		p.XdpObject:      "xdp 2.0.1",
	} {
		if got := r.read(path); got != want {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(p.Libexec, "link")); !os.IsNotExist(err) {
		t.Errorf("a link from the tarball was made: %v", err)
	}
	if _, err := os.Stat(p.WatchdogDropin); !os.IsNotExist(err) {
		t.Errorf("a drop-in the release doesn't have was written: %v", err)
	}
	st, err := os.Stat(filepath.Join(p.Libexec, "fr-webui"))
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("fr-webui: %v %v", st, err)
	}
	// The version switched from stays for a rollback; older ones go.
	if v := r.versions(); !slices.Equal(v, []string{"2.0.0", "2.0.1"}) {
		t.Errorf("versions kept: %v", v)
	}
	if !slices.EqualFunc(r.calls, wantRestarts(), slices.Equal) {
		t.Errorf("programs run:\n%q\nwant\n%q", r.calls, wantRestarts())
	}
	wantState := `{
  "current_version": "2.0.1",
  "previous_version": "2.0.0",
  "last_update": {
    "action": "apply",
    "version": "2.0.1",
    "applied_at": "2026-11-16T09:00:00.250000+00:00",
    "status": "success",
    "message": ""
  }
}
`
	if got := r.read(p.UpdateState); got != wantState {
		t.Errorf("state:\n%s", got)
	}
	// The cache keeps what verified, and nothing unpacked.
	entries, _ := os.ReadDir(filepath.Join(p.Releases, "2.0.1"))
	var cached []string
	for _, e := range entries {
		cached = append(cached, e.Name())
	}
	if want := []string{release.SumsName, release.SignatureName, release.TarballName("2.0.1")}; !slices.Equal(cached, want) {
		t.Errorf("cache: %v", cached)
	}
	if entries, _ := os.ReadDir(p.Releases); len(entries) != 1 {
		t.Errorf("left in the releases directory: %v", entries)
	}

	// Back: 2.0.0's release from the cache (the image keeps it), verified
	// again and installed in place of 2.0.1.
	r.cache("2.0.0", r.signed("2.0.0", releaseFiles("2.0.0")))
	r.calls = nil
	got, err = r.updater("2.0.1").Rollback()
	if err != nil || got != "2.0.0" {
		t.Fatalf("rollback: %q %v", got, err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.0" {
		t.Errorf("after the rollback /usr/libexec/fr_os -> %s", link)
	}
	if got := r.read(filepath.Join(p.Libexec, "firewall-cli")); got != "cli 2.0.0" {
		t.Errorf("after the rollback firewall-cli is %q", got)
	}
	if !slices.EqualFunc(r.calls, wantRestarts(), slices.Equal) {
		t.Errorf("rollback ran %q", r.calls)
	}
	if got := r.read(p.UpdateState); !strings.Contains(got, `"previous_version": null`) ||
		!strings.Contains(got, `"action": "rollback"`) || !strings.Contains(got, `"current_version": "2.0.0"`) {
		t.Errorf("state after the rollback:\n%s", got)
	}
	// One level deep.
	if _, err := r.updater("2.0.0").Rollback(); err == nil || err.Error() != "no previous version recorded to roll back to" {
		t.Errorf("a second rollback: %v", err)
	}
}

// SEC-12: only forward, refused before anything is fetched; an installed
// version that isn't one fails closed; a beta comes before its release.
func TestAnUpdateOnlyGoesForward(t *testing.T) {
	for _, c := range []struct{ installed, target, want string }{
		{"2.0.1", "2.0.1", "already running version 2.0.1"},
		{"2.0.1", "v2.0.1", "already running version v2.0.1"},
		{"2.0.1", "2.0.0", "refusing to install 2.0.0: it is older than the installed 2.0.1"},
		{"2.0.0", "2.0.0-beta.3", "refusing to install 2.0.0-beta.3: it is older than the installed 2.0.0"},
		{"2.0.10", "2.0.9", "refusing to install 2.0.9: it is older"},
		{"0.0.0-dev", "2.0.1", "not a recognized vMAJOR.MINOR.PATCH version: '0.0.0-dev'"},
		{"2.0.0", "2.0.1 ", "not a recognized vMAJOR.MINOR.PATCH version: '2.0.1 '"},
		{"2.0.0", "../../etc", "not a recognized vMAJOR.MINOR.PATCH version: '../../etc'"},
	} {
		r := newUpdateRig(t)
		downloaded := false
		u := r.updater(c.installed)
		u.Download = func(string, string, int64) error { downloaded = true; return nil }
		_, err := u.Apply(c.target)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s over %s: %v", c.target, c.installed, err)
		}
		if downloaded || len(r.calls) > 0 {
			t.Errorf("%s over %s: fetched or ran something", c.target, c.installed)
		}
		if _, err := os.Stat(r.sys.Paths.UpdateState); !os.IsNotExist(err) {
			t.Errorf("%s over %s: the state was written", c.target, c.installed)
		}
	}
	// 2.0.0-beta.1 to 2.0.0-beta.2 to 2.0.0.
	r := newUpdateRig(t)
	r.image("2.0.0-beta.1")
	r.cache("2.0.0-beta.2", r.signed("2.0.0-beta.2", releaseFiles("2.0.0-beta.2")))
	if _, err := r.updater("2.0.0-beta.1").Apply("2.0.0-beta.2"); err != nil {
		t.Fatalf("beta to beta: %v", err)
	}
	r.cache("2.0.0", r.signed("2.0.0", releaseFiles("2.0.0")))
	if _, err := r.updater("2.0.0-beta.2").Apply("2.0.0"); err != nil {
		t.Fatalf("beta to release: %v", err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.0" {
		t.Errorf("-> %s", link)
	}
}

// The update-helper keeps running across an update it installed: the
// version it compares with is the release in use, read for each request,
// never the one it was built as, so a second request can't take the
// router back below the release it just installed (SEC-12; review
// v2.0.0-beta.1 R2), and the release in use is never replaced.
func TestTheInstalledVersionIsTheReleaseInUse(t *testing.T) {
	r := newUpdateRig(t)
	r.image("2.0.0")
	r.cache("2.0.1", r.signed("2.0.1", releaseFiles("2.0.1")))
	r.cache("2.0.2", r.signed("2.0.2", releaseFiles("2.0.2")))
	request := func() *Updater {
		u := NewUpdater(r.sys, "")
		u.Keys = r.keys
		u.Download = func(string, string, int64) error { return errors.New("not here") }
		return u
	}
	first := request()
	if first.Installed != "2.0.0" {
		t.Fatalf("installed %q", first.Installed)
	}
	if _, err := first.Apply("2.0.2"); err != nil {
		t.Fatal(err)
	}
	if u := request(); u.Installed != "2.0.2" {
		t.Errorf("after the update: installed %q", u.Installed)
	}
	if _, err := request().Apply("2.0.1"); err == nil ||
		!strings.HasPrefix(err.Error(), "refusing to install 2.0.1: it is older than the installed 2.0.2") {
		t.Errorf("2.0.1 after 2.0.2: %v", err)
	}
	// An updater made before the switch still believes 2.0.0.
	if _, err := first.Apply("2.0.2"); err == nil || !strings.Contains(err.Error(), "refusing to replace 2.0.2: it is the release in use") {
		t.Errorf("2.0.2 again: %v", err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.2" {
		t.Errorf("-> %s", link)
	}
	if got := r.read(filepath.Join(r.sys.Paths.Libexec, "VERSION")); got != "2.0.2\n" {
		t.Errorf("VERSION %q", got)
	}
	if err := os.Remove(filepath.Join(r.sys.Paths.LibexecReleases, "2.0.2", "VERSION")); err != nil {
		t.Fatal(err)
	}
	if got := InstalledVersion(r.sys.Paths); got != version.Version {
		t.Errorf("without VERSION: %q", got)
	}
}

// What doesn't verify, or isn't a release, changes nothing: the
// programs, the units and the earlier rollback target stay; the attempt
// is recorded as failed.
func TestAReleaseThatDoesntVerifyChangesNothing(t *testing.T) {
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	for name, c := range map[string]struct {
		files func(r *updateRig) map[string][]byte
		want  string
	}{
		"signed by another key": {func(r *updateRig) map[string][]byte {
			f := r.signed("2.0.1", releaseFiles("2.0.1"))
			f[release.SignatureName] = ed25519.Sign(other, f[release.SumsName])
			return f
		}, "update to 2.0.1 failed: release 2.0.1 failed verification, not installing it: SHA256SUMS: the " +
			"signature matches none of the 1 trusted key(s)"},
		"tarball changed after signing": {func(r *updateRig) map[string][]byte {
			f := r.signed("2.0.1", releaseFiles("2.0.1"))
			f[release.TarballName("2.0.1")] = tarball(r.t, releaseFiles("2.0.2"))
			return f
		}, "update to 2.0.1 failed: release 2.0.1 failed verification, not installing it: fr_os-2.0.1-amd64.tar.gz: " +
			"sha256 "},
		"a member outside": {func(r *updateRig) map[string][]byte {
			return r.signed("2.0.1", append(releaseFiles("2.0.1"), tarEntry{name: "fr_os-2.0.1/../../evil", body: "x"}))
		}, "update to 2.0.1 failed: refusing to extract 'fr_os-2.0.1/../../evil': escapes "},
		"an absolute member": {func(r *updateRig) map[string][]byte {
			return r.signed("2.0.1", append(releaseFiles("2.0.1"), tarEntry{name: "/etc/evil", body: "x"}))
		}, "update to 2.0.1 failed: refusing to extract '/etc/evil': escapes "},
		"two directories": {func(r *updateRig) map[string][]byte {
			return r.signed("2.0.1", append(releaseFiles("2.0.1"), tarEntry{name: "other/", dir: true}))
		}, "update to 2.0.1 failed: unexpected release archive layout under "},
		"another version's tree": {func(r *updateRig) map[string][]byte {
			return r.signed("2.0.1", releaseFiles("2.0.2"))
		}, "update to 2.0.1 failed: release 2.0.1 is not an FR_OS 2 release: it unpacks to 'fr_os-2.0.2', not 'fr_os-2.0.1'"},
		"no updater in it": {func(r *updateRig) map[string][]byte {
			files := slices.DeleteFunc(releaseFiles("2.0.1"), func(e tarEntry) bool { return strings.HasSuffix(e.name, "fr-update-helper") })
			return r.signed("2.0.1", files)
		}, "update to 2.0.1 failed: release 2.0.1 is not an FR_OS 2 release: it has no bin/fr-update-helper"},
		"not a tarball": {func(r *updateRig) map[string][]byte {
			f := r.signed("2.0.1", nil)
			data := []byte("not gzip")
			sum := sha256.Sum256(data)
			f[release.TarballName("2.0.1")] = data
			f[release.SumsName] = []byte(hex.EncodeToString(sum[:]) + "  " + release.TarballName("2.0.1") + "\n")
			f[release.SignatureName] = ed25519.Sign(r.key, f[release.SumsName])
			return f
		}, "update to 2.0.1 failed: fr_os-2.0.1-amd64.tar.gz is not a gzip-compressed tar archive"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newUpdateRig(t)
			p := r.sys.Paths
			r.image("2.0.0")
			before := `{"current_version": "2.0.0", "previous_version": "1.9.9", "last_update": {}}`
			if err := os.MkdirAll(filepath.Dir(p.UpdateState), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.UpdateState, []byte(before), 0o644); err != nil {
				t.Fatal(err)
			}
			r.cache("2.0.1", c.files(r))
			_, err := r.updater("2.0.0").Apply("2.0.1")
			if err == nil || !strings.HasPrefix(err.Error(), c.want) {
				t.Fatalf("%v\nwant %s", err, c.want)
			}
			if strings.Contains(err.Error(), "partly updated") {
				t.Errorf("a refusal before any change says the system may be partly updated: %v", err)
			}
			if link := r.link(); link != "fr_os-releases/2.0.0" || len(r.calls) > 0 {
				t.Errorf("changed: -> %s, ran %q", link, r.calls)
			}
			if _, err := os.Stat(filepath.Join(r.root, "evil")); !os.IsNotExist(err) {
				t.Errorf("a member was written outside: %v", err)
			}
			if _, err := os.Stat("/etc/evil"); !os.IsNotExist(err) {
				t.Errorf("/etc/evil: %v", err)
			}
			state := r.read(p.UpdateState)
			if !strings.Contains(state, `"previous_version": "1.9.9"`) || !strings.Contains(state, `"status": "failed"`) {
				t.Errorf("state:\n%s", state)
			}
			if v := r.versions(); !slices.Equal(v, []string{"2.0.0"}) {
				t.Errorf("versions: %v", v)
			}
		})
	}
}

// Without a copy in the cache, the release's three files are downloaded
// from its GitHub release, and kept once verified.
func TestAnUpdateDownloadsWhatIsntCached(t *testing.T) {
	r := newUpdateRig(t)
	r.image("2.0.0")
	files := r.signed("2.0.1", releaseFiles("2.0.1"))
	u := r.updater("2.0.0")
	var urls []string
	u.Download = func(url, dest string, max int64) error {
		urls = append(urls, url)
		return os.WriteFile(dest, files[filepath.Base(url)], 0o600)
	}
	if _, err := u.Apply("v2.0.1"); err != nil {
		t.Fatal(err)
	}
	base := "https://github.com/starsmash29/FR_OS-Community/releases/download/v2.0.1/"
	if want := []string{base + "fr_os-2.0.1-amd64.tar.gz", base + "SHA256SUMS", base + "SHA256SUMS.sig"}; !slices.Equal(urls, want) {
		t.Errorf("downloaded %q", urls)
	}
	st, err := os.Stat(filepath.Join(r.sys.Paths.Releases, "v2.0.1", "SHA256SUMS"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("cached SHA256SUMS: %v %v", st, err)
	}

	// A download that fails changes nothing.
	r = newUpdateRig(t)
	r.image("2.0.0")
	_, err = r.updater("2.0.0").Apply("2.0.1")
	if want := "update to 2.0.1 failed: could not download " + base[:len(base)-7] + "v2.0.1/fr_os-2.0.1-amd64.tar.gz: " +
		"HTTP Error 404: Not Found"; err == nil || err.Error() != want {
		t.Errorf("%v\nwant %s", err, want)
	}
	u = r.updater("2.0.0")
	u.Repo = "not a repo"
	if _, err := u.Apply("2.0.1"); err == nil || !strings.HasSuffix(err.Error(),
		"invalid GitHub repository 'not a repo' (expected OWNER/NAME)") {
		t.Errorf("a repository that isn't one: %v", err)
	}
}

// Once anything changed, a failure says the system may be partly updated,
// and the rollback target is already recorded (1.x's review triage C1).
func TestAFailedRestartCanBeRolledBack(t *testing.T) {
	r := newUpdateRig(t)
	r.image("2.0.0")
	r.cache("2.0.1", r.signed("2.0.1", releaseFiles("2.0.1")))
	r.fail["systemctl try-restart -- fr-firewall.service"] = Result{Code: 1, Stderr: "Job failed.\n"}
	_, err := r.updater("2.0.0").Apply("2.0.1")
	want := "update to 2.0.1 failed: `systemctl try-restart -- fr-firewall.service` failed: Job failed. -- the system " +
		"may be partly updated; roll back to 2.0.0 (webUI Update screen, or `firewall-cli update rollback`)"
	if err == nil || err.Error() != want {
		t.Fatalf("%v\nwant %s", err, want)
	}
	state := r.read(r.sys.Paths.UpdateState)
	if !strings.Contains(state, `"current_version": "2.0.0"`) || !strings.Contains(state, `"previous_version": "2.0.0"`) {
		t.Errorf("state:\n%s", state)
	}
	delete(r.fail, "systemctl try-restart -- fr-firewall.service")
	r.cache("2.0.0", r.signed("2.0.0", releaseFiles("2.0.0")))
	if got, err := r.updater("2.0.0").Rollback(); err != nil || got != "2.0.0" {
		t.Fatalf("rollback: %q %v", got, err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.0" {
		t.Errorf("-> %s", link)
	}
}

// An image from before versioned directories had the programs in
// /usr/libexec/fr_os itself: the first update moves them aside.
func TestTheFirstUpdateOfAnImageWithoutVersionedDirectories(t *testing.T) {
	r := newUpdateRig(t)
	p := r.sys.Paths
	if err := os.MkdirAll(p.Libexec, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Libexec, "firewall-cli"), []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.cache("2.0.1", r.signed("2.0.1", releaseFiles("2.0.1")))
	if _, err := r.updater("2.0.0").Apply("2.0.1"); err != nil {
		t.Fatal(err)
	}
	if link := r.link(); link != "fr_os-releases/2.0.1" {
		t.Errorf("-> %s", link)
	}
	if got := r.read(filepath.Join(p.Libexec, "firewall-cli")); got != "cli 2.0.1" {
		t.Errorf("firewall-cli: %q", got)
	}
}

// A state file that names something other than a version is never
// used as a directory name (security-lessons F1).
func TestARollbackTargetMustBeAVersion(t *testing.T) {
	for state, want := range map[string]string{
		`{"previous_version": "../../usr"}`: "not a recognized vMAJOR.MINOR.PATCH version: '../../usr'",
		`{"previous_version": 5}`:           "not a recognized vMAJOR.MINOR.PATCH version: 5",
		`{"previous_version": ""}`:          "no previous version recorded to roll back to",
		`not json`:                          "no previous version recorded to roll back to",
		"\xff":                              "no previous version recorded to roll back to",
	} {
		r := newUpdateRig(t)
		if err := os.MkdirAll(filepath.Dir(r.sys.Paths.UpdateState), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.sys.Paths.UpdateState, []byte(state), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := r.updater("2.0.1").Rollback()
		var ue *UpdateError
		if !errors.As(err, &ue) || err.Error() != want {
			t.Errorf("%s: %v", state, err)
		}
	}
}
