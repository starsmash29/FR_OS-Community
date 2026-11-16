package apply

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/release"
	"github.com/starsmash29/fr_os-community/version"
)

// Installing a signed release and rolling back to the one before (1.x's
// frfw.update.apply_update and rollback_update), as root: from the
// update-helper (the webUI's Install and Roll back buttons), from
// `firewall-cli update apply|rollback`, and from fr-update-check.timer
// for a security release when update.auto_install_security is on (J3).
//
// A release is its tarball, fr_os-<version>-amd64.tar.gz (what
// installer/build-binaries.sh stages, as installer/package-release.sh
// packs it), with SHA256SUMS and SHA256SUMS.sig. Nothing from it is used
// before the signature over SHA256SUMS verifies against the keys this
// build trusts and the tarball against the signed checksum (release/,
// security-lessons G3) -- also for a copy already on disk: a rollback
// verifies again. Releases only go forward (ROADMAP SEC-12): an older
// one is refused before anything is fetched, and the one way back is the
// rollback, to the version this router updated from, one level deep.
//
// 1.x pip-installs a source tarball; FR_OS 2 has no Python on the router,
// so a release is the finished, static programs (decisions.md, "phase
// 4f-4b"). Each version's programs and scripts are a directory of their
// own, /usr/libexec/fr_os-releases/<version>/, and /usr/libexec/fr_os,
// where every unit runs them from, is a symlink to the one in use,
// replaced in one rename: an install cut short leaves the programs of
// one version or the other, never half of each, and a rollback is the
// same switch back. The cache /opt/fr_os/releases/<version>/ keeps what
// was verified, so a rollback needs no network -- useful precisely when
// the update that broke something broke connectivity too.

// UpdateServices are the units restarted after an install, in 1.x's
// order (SERVICES_TO_RESTART), and FR_OS 2's two other daemons after
// them. Not fr-update-helper.service: it is the process installing; it
// runs the new version from its next start. fr-webui.service restarts a
// few seconds later (RestartWebUISoon): the answer to the request that
// asked for the update has to get back first.
var UpdateServices = []string{
	// First: a release may change the accounts and groups the others run
	// as, and this oneshot makes them so (ROADMAP SEC-11).
	"fr-accounts.service",
	"fr-apply-helper.service",
	"fr-firewall.service",
	// After fr-firewall, whose apply writes their view of the config and
	// swaps in the release's XDP program.
	"fr-ai-ids.service",
	"fr-appid.service",
	"fr-tls-fp.service",
	"fr-xdp-sni-logger.service",
	"fr-console-ports.service",
}

// webUIRestartDelay is _WEBUI_RESTART_DELAY_SECONDS.
const webUIRestartDelay = 3

// The limits of what a release may be: its tarball as downloaded, the
// checksum list and its signature, and what the tarball unpacks to.
const (
	maxTarballBytes   = 1 << 30
	maxSumsBytes      = 1 << 20
	maxUnpackedBytes  = 2 << 30
	maxTarballEntries = 20000
)

// releaseEssentials are what a release must carry to be installed: the
// router's own commands and the updater that installs the next release.
var releaseEssentials = []string{"bin/firewall-cli", "bin/fr-update-helper"}

// Updater installs and rolls back releases.
type Updater struct {
	Sys *System
	// Repo is where releases are downloaded from (update.repo).
	Repo string
	// Installed is the version running (version.Version).
	Installed string
	// Keys are the keys a release must be signed with (nil: the ones this
	// build trusts, release.TrustedKeys).
	Keys []release.Key
	// Download fetches url into dest, at most max bytes (nil:
	// DownloadRelease).
	Download func(url, dest string, max int64) error
	// The steps that change the system once the release verified
	// (_install_release_dir, _restart_services, _restart_webui_delayed);
	// nil: the router's. top is the unpacked release's directory.
	Install      func(top, version string) error
	Restart      func() error
	RestartWebUI func() error
}

// NewUpdater is the router's, for repo. The installed version is read
// when the updater is made, from the release /usr/libexec/fr_os points
// at (InstalledVersion), not taken from the version this program was
// built as: the update-helper keeps running across an update it
// installed, and a version compiled into it would let a second request
// install a release older than the one it just switched to (SEC-12;
// review v2.0.0-beta.1 R2).
func NewUpdater(sys *System, repo string) *Updater {
	if repo == "" {
		repo = DefaultUpdateRepo
	}
	return &Updater{Sys: sys, Repo: repo, Installed: InstalledVersion(sys.Paths)}
}

// InstalledVersion is the version of the release /usr/libexec/fr_os
// points at: its VERSION file, which the image and every install write.
// A router without one (an image from before versioned directories) is
// the version this program was built as.
func InstalledVersion(p Paths) string {
	data, err := readLimited(filepath.Join(p.Libexec, "VERSION"), 256)
	if err != nil {
		return version.Version
	}
	return strings.TrimSuffix(string(data), "\n")
}

// DownloadError is a download that failed: urllib's HTTPError text for an
// answer that isn't a success.
type DownloadError struct {
	Status int
	Reason string
	Err    error
}

func (e *DownloadError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("HTTP Error %d: %s", e.Status, e.Reason)
	}
	return e.Err.Error()
}

var downloadClient = &http.Client{Timeout: 15 * time.Minute}

// DownloadRelease is the router's Download: a GET, after GitHub's
// redirect to its file store, into dest.
func DownloadRelease(url, dest string, max int64) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &DownloadError{Err: err}
	}
	req.Header.Set("User-Agent", "fr_os-update")
	resp, err := downloadClient.Do(req)
	if err != nil {
		return &DownloadError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &DownloadError{Status: resp.StatusCode, Reason: http.StatusText(resp.StatusCode)}
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, max+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > max {
		err = fmt.Errorf("larger than %d bytes", max)
	}
	if err != nil {
		return &DownloadError{Err: err}
	}
	return nil
}

// --- the state file ----------------------------------------------------------------

// UpdateState is frfw.update.UpdateState: what the last install or
// rollback did, and the version a rollback goes back to. Previous and
// Last are what the file holds, whatever their type (1.x writes back
// what it read).
type UpdateState struct {
	Current  string
	Previous config.Value
	Last     config.Value
}

// LoadUpdateState is load_state: the file's history, with current (what
// is installed now, the one thing that can't drift from the truth)
// whatever it says. A missing, unreadable or broken file is no history.
func LoadUpdateState(path, current string) *UpdateState {
	st := &UpdateState{Current: current, Last: config.NewMap()}
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		// 1.x lets a file that isn't UTF-8 through as an exception
		// (decisions.md, "phase 4f-4b").
		return st
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return st
	}
	m, ok := v.(*config.Map)
	if !ok {
		return st
	}
	st.Previous, _ = m.Get("previous_version")
	if last, _ := m.Get("last_update"); config.Truthy(last) {
		st.Last = last
	}
	return st
}

// Save is save_state: json.dumps(indent=2) and a newline, replaced
// through "<path>.tmp". 0644: the webUI shows it, and it holds nothing
// secret.
func (st *UpdateState) Save(path string) error {
	m := config.NewMap()
	m.Set("current_version", st.Current)
	m.Set("previous_version", st.Previous)
	m.Set("last_update", st.Last)
	text, err := config.PyJSON(m, 2, false)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(text+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (u *Updater) attempt(action, version, status, message string) *config.Map {
	m := config.NewMap()
	m.Set("action", action)
	m.Set("version", version)
	m.Set("applied_at", PyUTCNow(u.Sys.Now()))
	m.Set("status", status)
	m.Set("message", message)
	return m
}

// --- install and roll back ---------------------------------------------------------

// Apply is apply_update: download (or take from the cache), verify and
// install target, then restart what runs it. Only a version newer than
// the installed one (SEC-12): an older one is refused before anything is
// fetched. Once the release verified and before anything changes, the
// running version is recorded as the one to roll back to, with the
// attempt "in_progress", so a rollback can undo it however far it got
// (1.x's review triage C1); a failure before that changed nothing and
// keeps the earlier rollback target. It returns the version installed.
func (u *Updater) Apply(target string) (string, error) {
	t, err := ParseUpdateVersion(target)
	if err != nil {
		return "", err
	}
	current := u.Installed
	// An installed version this can't read fails closed.
	c, err := ParseUpdateVersion(current)
	if err != nil {
		return "", err
	}
	switch t.Compare(c) {
	case 0:
		return "", updateErrorf("already running version %s", target)
	case -1:
		return "", updateErrorf("refusing to install %s: it is older than the installed %s, and an older release "+
			"brings back what has been fixed since. To go back to the version this router updated from, roll "+
			"back (webUI Update screen, or `firewall-cli update rollback`).", target, current)
	}
	path := u.Sys.Paths.UpdateState
	state := LoadUpdateState(path, current)
	started := false
	recordStart := func() error {
		state.Previous = current
		state.Last = u.attempt("apply", target, "in_progress", "")
		if err := state.Save(path); err != nil {
			return err
		}
		started = true
		return nil
	}
	if err := u.installAndActivate(target, recordStart); err != nil {
		hint := ""
		if started {
			hint = " -- the system may be partly updated; roll back to " + current +
				" (webUI Update screen, or `firewall-cli update rollback`)"
		}
		state.Last = u.attempt("apply", target, "failed", err.Error()+hint)
		_ = state.Save(path)
		return "", updateErrorf("update to %s failed: %s%s", target, err, hint)
	}
	state.Current = target
	state.Last = u.attempt("apply", target, "success", "")
	_ = state.Save(path)
	return target, nil
}

// Rollback is rollback_update: install the version recorded as the one
// before, from the cache when it is there. One level deep: a rollback
// clears it, so a rollback can't be rolled back.
func (u *Updater) Rollback() (string, error) {
	path := u.Sys.Paths.UpdateState
	state := LoadUpdateState(path, u.Installed)
	if !config.Truthy(state.Previous) {
		return "", &UpdateError{"no previous version recorded to roll back to"}
	}
	// Security-lessons F1 (1.x's review triage C2): the state file names
	// a directory removed and installed as root -- only a real version.
	if _, err := ParseUpdateVersion(state.Previous); err != nil {
		return "", err
	}
	target := state.Previous.(string)
	if err := u.installAndActivate(target, nil); err != nil {
		state.Last = u.attempt("rollback", target, "failed", err.Error())
		_ = state.Save(path)
		return "", updateErrorf("rollback to %s failed: %s", target, err)
	}
	state.Current = target
	state.Previous = nil
	state.Last = u.attempt("rollback", target, "success", "")
	_ = state.Save(path)
	return target, nil
}

// installAndActivate is _install_and_activate: fetch and verify (which
// changes nothing), then before, then install and restart -- the part
// that can leave the system half updated.
func (u *Updater) installAndActivate(target string, before func() error) error {
	top, cleanup, err := u.fetchRelease(target)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		return err
	}
	if before != nil {
		if err := before(); err != nil {
			return err
		}
	}
	install, restart, restartWebUI := u.Install, u.Restart, u.RestartWebUI
	if install == nil {
		install = u.installRelease
	}
	if restart == nil {
		restart = u.restartServices
	}
	if restartWebUI == nil {
		restartWebUI = u.restartWebUISoon
	}
	if err := install(top, target); err != nil {
		return err
	}
	if err := restart(); err != nil {
		return err
	}
	return restartWebUI()
}

// fetchRelease is _fetch_release: version's release, verified and
// unpacked, and what removes the unpacked copy. The cache
// <Releases>/<version>/ keeps the tarball, SHA256SUMS and the signature
// as they verified, readable by everyone like any published release; a
// copy found there is verified again, never trusted for being on disk.
func (u *Updater) fetchRelease(target string) (string, func(), error) {
	dir := u.Sys.Paths.Releases
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	cache := filepath.Join(dir, target)
	tag := target
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + target
	}
	tmp, err := os.MkdirTemp(dir, "tmp")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	artifacts := filepath.Join(tmp, "artifacts")
	if err := os.Mkdir(artifacts, 0o700); err != nil {
		return "", cleanup, err
	}
	names := []string{release.TarballName(target), release.SumsName, release.SignatureName}
	cached := true
	for _, n := range names {
		if st, err := os.Stat(filepath.Join(cache, n)); err != nil || !st.Mode().IsRegular() {
			cached = false
		}
	}
	if cached {
		for _, n := range names {
			if err := copyFile(filepath.Join(cache, n), filepath.Join(artifacts, n)); err != nil {
				return "", cleanup, err
			}
		}
	} else if err := u.downloadAssets(tag, target, artifacts); err != nil {
		return "", cleanup, err
	}
	if err := verifyRelease(artifacts, target, u.Keys); err != nil {
		return "", cleanup, err
	}
	src := filepath.Join(artifacts, "src")
	top, err := safeExtract(filepath.Join(artifacts, names[0]), src)
	if err != nil {
		return "", cleanup, err
	}
	if err := checkReleaseLayout(top, target); err != nil {
		return "", cleanup, err
	}
	// The unpacked copy stays out of the cache: it is installed from
	// here, and the cache keeps what verified.
	unpacked := filepath.Join(tmp, "src")
	if err := os.Rename(src, unpacked); err != nil {
		return "", cleanup, err
	}
	top = filepath.Join(unpacked, filepath.Base(top))
	if err := os.RemoveAll(cache); err != nil {
		return "", cleanup, err
	}
	if err := os.Rename(artifacts, cache); err != nil {
		return "", cleanup, err
	}
	if err := os.Chmod(cache, 0o755); err != nil {
		return "", cleanup, err
	}
	for _, n := range names {
		if err := os.Chmod(filepath.Join(cache, n), 0o644); err != nil {
			return "", cleanup, err
		}
	}
	return top, cleanup, nil
}

func (u *Updater) downloadAssets(tag, target, dest string) error {
	repo, err := checkedRepo(u.Repo)
	if err != nil {
		return err
	}
	download := u.Download
	if download == nil {
		download = DownloadRelease
	}
	base := "https://github.com/" + repo + "/releases/download/" + tag
	for _, n := range []string{release.TarballName(target), release.SumsName, release.SignatureName} {
		max := int64(maxSumsBytes)
		if n != release.SumsName && n != release.SignatureName {
			max = maxTarballBytes
		}
		url := base + "/" + n
		if err := download(url, filepath.Join(dest, n), max); err != nil {
			return updateErrorf("could not download %s: %s", url, err)
		}
	}
	return nil
}

// verifyRelease is _verify.
func verifyRelease(artifacts, target string, keys []release.Key) error {
	name := release.TarballName(target)
	fail := func(err error) error {
		return updateErrorf("release %s failed verification, not installing it: %s", target, err)
	}
	sums, err := readLimited(filepath.Join(artifacts, release.SumsName), maxSumsBytes)
	if err != nil {
		return fail(err)
	}
	sig, err := readLimited(filepath.Join(artifacts, release.SignatureName), maxSumsBytes)
	if err != nil {
		return fail(err)
	}
	f, err := os.Open(filepath.Join(artifacts, name))
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	if _, err := release.VerifyRelease(f, sums, sig, name, keys); err != nil {
		var se *release.SignatureError
		if errors.As(err, &se) {
			return fail(err)
		}
		return err
	}
	return nil
}

func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), max)
	}
	return data, nil
}

// safeExtract is _safe_extract: tarball unpacked into dest, refusing any
// member that would land outside it. Only regular files and directories:
// an update installs nothing else, so links are skipped, never created.
// Every member is checked before anything is written. It returns the one
// directory the release unpacks to.
func safeExtract(tarball, dest string) (string, error) {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return "", err
	}
	type member struct {
		hdr    *tar.Header
		target string
	}
	open := func() (*tar.Reader, func(), error) {
		f, err := os.Open(tarball)
		if err != nil {
			return nil, nil, err
		}
		z, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, nil, updateErrorf("%s is not a gzip-compressed tar archive: %s", filepath.Base(tarball), err)
		}
		return tar.NewReader(z), func() { z.Close(); f.Close() }, nil
	}
	// First pass: every member's place.
	tr, done, err := open()
	if err != nil {
		return "", err
	}
	var members []member
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			done()
			return "", updateErrorf("the release archive is damaged: %s", err)
		}
		if len(members) >= maxTarballEntries {
			done()
			return "", updateErrorf("the release archive has more than %d entries", maxTarballEntries)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}
		total += hdr.Size
		if total > maxUnpackedBytes {
			done()
			return "", updateErrorf("the release archive unpacks to more than %d bytes", maxUnpackedBytes)
		}
		target := memberTarget(resolved, hdr.Name)
		if target != resolved && !strings.HasPrefix(target, resolved+string(filepath.Separator)) {
			done()
			return "", updateErrorf("refusing to extract %s: escapes %s", config.Repr(hdr.Name), dest)
		}
		members = append(members, member{hdr, target})
	}
	done()
	// Second pass: the members, in order.
	tr, done, err = open()
	if err != nil {
		return "", err
	}
	defer done()
	i := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", updateErrorf("the release archive is damaged: %s", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue
		}
		m := members[i]
		i++
		if m.hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(m.target, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(m.target), 0o755); err != nil {
			return "", err
		}
		mode := os.FileMode(0o644)
		if hdr.Mode&0o111 != 0 {
			mode = 0o755
		}
		f, err := os.OpenFile(m.target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(f, io.LimitReader(tr, hdr.Size))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return "", err
		}
		if err := os.Chmod(m.target, mode); err != nil {
			return "", err
		}
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return "", err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) != 1 {
		return "", updateErrorf("unexpected release archive layout under %s", dest)
	}
	return filepath.Join(dest, dirs[0]), nil
}

// memberTarget is (dest / name).resolve() for a member (nothing in dest
// is a link): an absolute name replaces dest, as pathlib's does.
func memberTarget(dest, name string) string {
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(dest, name)
}

// checkReleaseLayout refuses a tarball that isn't an FR_OS 2 release of
// target, before anything is installed (2.x's own: 1.x pip-installs any
// source tree): its directory is fr_os-<version>, its VERSION says so,
// and it carries the router's commands and the next updater.
func checkReleaseLayout(top, target string) error {
	plain := strings.TrimPrefix(target, "v")
	fail := func(what string) error {
		return updateErrorf("release %s is not an FR_OS 2 release: %s", target, what)
	}
	if filepath.Base(top) != "fr_os-"+plain {
		return fail("it unpacks to " + config.Repr(filepath.Base(top)) + ", not " + config.Repr("fr_os-"+plain))
	}
	data, err := readLimited(filepath.Join(top, "VERSION"), 256)
	if err != nil || strings.TrimSuffix(string(data), "\n") != plain {
		return fail("its VERSION isn't " + plain)
	}
	for _, p := range releaseEssentials {
		if st, err := os.Stat(filepath.Join(top, p)); err != nil || !st.Mode().IsRegular() {
			return fail("it has no " + p)
		}
	}
	return nil
}

// --- the router's install steps ----------------------------------------------------

// installRelease puts the unpacked release top in place: its programs
// and scripts in a directory of the version's own, its XDP program, its
// units and drop-ins, then /usr/libexec/fr_os switched to it in one
// rename, and systemd told (1.x's _install_release_dir). The version
// switched from and the new one are kept; older versions' directories
// go.
func (u *Updater) installRelease(top, target string) error {
	p := u.Sys.Paths
	plain := strings.TrimPrefix(target, "v")
	old, _ := os.Readlink(p.Libexec)
	if filepath.Base(old) == plain {
		// Never replace the directory in use: the programs running now
		// run from it (review v2.0.0-beta.1 R2).
		return updateErrorf("refusing to replace %s: it is the release in use", plain)
	}
	if err := os.MkdirAll(p.LibexecReleases, 0o755); err != nil {
		return err
	}
	dir := filepath.Join(p.LibexecReleases, plain)
	staged := dir + ".new"
	if err := os.RemoveAll(staged); err != nil {
		return err
	}
	if err := os.Mkdir(staged, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	for _, sub := range []string{"bin", "scripts"} {
		entries, err := os.ReadDir(filepath.Join(top, sub))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			if err := installFile(filepath.Join(top, sub, e.Name()), filepath.Join(staged, e.Name()), 0o755); err != nil {
				return err
			}
		}
	}
	if err := installFile(filepath.Join(top, "VERSION"), filepath.Join(staged, "VERSION"), 0o644); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Rename(staged, dir); err != nil {
		return err
	}

	// The release's XDP program, where fr-xdp loads it from: the next
	// apply (fr-firewall restarts below) sees the new digest and swaps
	// it in. One without is removed, never left to run under code it
	// wasn't built for (1.x's _install_xdp_object).
	obj := filepath.Join(top, "bpf", "xdp_sni_filter.o")
	if st, err := os.Stat(obj); err == nil && st.Mode().IsRegular() {
		if err := os.MkdirAll(filepath.Dir(p.XdpObject), 0o755); err != nil {
			return err
		}
		if err := installFile(obj, p.XdpObject, 0o644); err != nil {
			return err
		}
	} else if err := os.Remove(p.XdpObject); err != nil && !os.IsNotExist(err) {
		return err
	}

	// The units (systemd/fr-*), and the drop-ins the image installs.
	units, err := filepath.Glob(filepath.Join(top, "systemd", "fr-*"))
	if err != nil {
		return err
	}
	slices.Sort(units)
	if len(units) > 0 {
		if err := os.MkdirAll(p.SystemdUnits, 0o755); err != nil {
			return err
		}
	}
	for _, unit := range units {
		if st, err := os.Stat(unit); err != nil || !st.Mode().IsRegular() {
			continue
		}
		if err := installFile(unit, filepath.Join(p.SystemdUnits, filepath.Base(unit)), 0o644); err != nil {
			return err
		}
	}
	for name, dest := range map[string]string{"journald-fr_os.conf": p.JournaldDropin,
		"sysctl-fr_os-ipv6.conf": p.SysctlIPv6, "watchdog-fr_os.conf": p.WatchdogDropin} {
		src := filepath.Join(top, "systemd", name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		if err := installFile(src, dest, 0o644); err != nil {
			return err
		}
	}

	if err := switchLibexec(p, plain); err != nil {
		return err
	}
	if err := u.run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	pruneReleases(p.LibexecReleases, plain, filepath.Base(old))
	return nil
}

// switchLibexec points /usr/libexec/fr_os at fr_os-releases/<plain>, in
// one rename of a symlink made beside it. An image from before versioned
// directories had the programs in /usr/libexec/fr_os itself: that
// directory becomes the installed version's, first.
func switchLibexec(p Paths, plain string) error {
	link := p.Libexec
	if st, err := os.Lstat(link); err == nil && st.IsDir() {
		legacy := filepath.Join(p.LibexecReleases, "image")
		if err := os.RemoveAll(legacy); err != nil {
			return err
		}
		if err := os.Rename(link, legacy); err != nil {
			return err
		}
	}
	rel, err := filepath.Rel(filepath.Dir(link), filepath.Join(p.LibexecReleases, plain))
	if err != nil {
		return err
	}
	staged := link + ".new"
	if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(rel, staged); err != nil {
		return err
	}
	return os.Rename(staged, link)
}

// pruneReleases removes the versions' directories other than keep: the
// one switched to and the one switched from.
func pruneReleases(dir string, keep ...string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if slices.Contains(keep, name) {
			continue
		}
		base := strings.TrimSuffix(name, ".new")
		if _, ok := version.ParseRelease(base); ok || base == "image" {
			_ = os.RemoveAll(filepath.Join(dir, name))
		}
	}
}

// restartServices is _restart_services: try-restart, which leaves a unit
// that isn't running as it is.
func (u *Updater) restartServices() error {
	for _, unit := range UpdateServices {
		if err := u.run("systemctl", "try-restart", "--", unit); err != nil {
			return err
		}
	}
	return nil
}

// restartWebUISoon is _restart_webui_delayed: the webUI restarted a few
// seconds out (systemd-run), so the page saying the update worked gets
// to the browser first.
func (u *Updater) restartWebUISoon() error {
	return u.run("systemd-run", "--quiet", fmt.Sprintf("--on-active=%d", webUIRestartDelay),
		"--unit=fr-webui-restart", "systemctl", "try-restart", "--", WebUIUnit)
}

// run is _run: a step's program, its failure in 1.x's words.
func (u *Updater) run(argv ...string) error {
	r, err := u.Sys.Run(Cmd{Argv: argv, Timeout: 5 * time.Minute})
	if errors.Is(err, ErrNotFound) {
		return updateErrorf("`%s` not found: [Errno 2] No such file or directory: %s", argv[0], config.Repr(argv[0]))
	}
	if err != nil {
		return err
	}
	if r.Code != 0 {
		detail := strings.TrimSpace(r.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(r.Stdout)
		}
		if detail == "" {
			detail = fmt.Sprintf("Command '%s' returned non-zero exit status %d.", reprArgv(argv), r.Code)
		}
		return updateErrorf("`%s` failed: %s", strings.Join(argv, " "), detail)
	}
	return nil
}

// installFile copies src to dest with mode, through a temporary file
// beside dest renamed over it: a reader sees the old file or the new one.
func installFile(src, dest string, mode os.FileMode) error {
	tmp := dest + ".fr_os-new"
	if err := copyFile(src, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Chtimes(dest, st.ModTime(), st.ModTime())
}
