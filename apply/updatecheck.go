package apply

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/version"
)

// Checking for a release (1.x's frfw.update.check_latest and the periodic
// check's cache, security-lessons G10/J3): a GET of GitHub's Releases API,
// made only when an admin opens the Update screen, runs `firewall-cli
// update check`, or fr-update-check.timer runs. It needs no privilege;
// installing a release does (update.go).

// DefaultUpdateRepo is where FR_OS 2's releases are looked for unless the
// config's update.repo says otherwise (1.x's frfw.update.DEFAULT_REPO
// names 1.x's own repository).
const DefaultUpdateRepo = "starsmash29/FR_OS-Community"

// UpdateCheckTimeout is check_latest's timeout, in seconds.
const UpdateCheckTimeout = 10.0

// maxReleaseJSONBytes bounds GitHub's answer: a release's JSON with its
// notes is a few KiB.
const maxReleaseJSONBytes = 1 << 20

// UpdateError is frfw.update.UpdateError: a check, an install or a
// rollback that failed, with the message 1.x gives.
type UpdateError struct{ Msg string }

func (e *UpdateError) Error() string { return e.Msg }

func updateErrorf(format string, a ...any) *UpdateError {
	return &UpdateError{fmt.Sprintf(format, a...)}
}

// ParseUpdateVersion is frfw.update.parse_version: v as a release
// version, or the UpdateError naming it (Python's repr). A beta
// (X.Y.Z-beta.N) is one too (version.ParseRelease).
func ParseUpdateVersion(v config.Value) (version.Release, error) {
	if s, ok := v.(string); ok {
		if r, ok := version.ParseRelease(s); ok {
			return r, nil
		}
	}
	return version.Release{}, updateErrorf("not a recognized vMAJOR.MINOR.PATCH version: %s", config.Repr(v))
}

// checkedRepo is _checked_repo (security-lessons F1): update.repo goes
// into URLs the root updater fetches code from -- only a plain
// OWNER/NAME.
func checkedRepo(repo string) (string, error) {
	if msg := config.ValidateGithubRepo(repo); msg != "" {
		return "", &UpdateError{msg}
	}
	return repo, nil
}

// FetchJSON is a GET of a GitHub API URL: its status and body, or why it
// couldn't be made (1.x's _fetch_json, which leaves the JSON to the
// caller here).
type FetchJSON func(url string, timeout float64) (int, []byte, error)

// FetchGitHub is the router's FetchJSON.
func FetchGitHub(url string, timeout float64) (int, []byte, error) {
	client := &http.Client{Timeout: time.Duration(timeout * float64(time.Second))}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "fr_os-update")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseJSONBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxReleaseJSONBytes {
		return 0, nil, fmt.Errorf("the answer is larger than %d bytes", maxReleaseJSONBytes)
	}
	return resp.StatusCode, body, nil
}

// ReleaseInfo is frfw.update.ReleaseInfo.
type ReleaseInfo struct {
	Tag, Version, Notes, HTMLURL string
	// Security is a security release (security-lessons G10): "[security]"
	// in its title or a "Security: yes" line in its notes.
	Security bool
}

// UpdateCheckResult is frfw.update.UpdateCheckResult: Latest nil when the
// repository has published no release.
type UpdateCheckResult struct {
	Current         string
	Latest          *ReleaseInfo
	UpdateAvailable bool
	CheckedAt       string
}

var securityLineRE = regexp.MustCompile(`(?im)^\s*security:\s*yes\s*$`)

// IsSecurityRelease is is_security_release.
func IsSecurityRelease(name, notes string) bool {
	return strings.Contains(strings.ToLower(name), "[security]") || securityLineRE.MatchString(notes)
}

// pyStrOr is str(raw.get(key) or "").
func pyStrOr(m *config.Map, key string) string {
	v, _ := m.Get(key)
	if !config.Truthy(v) {
		return ""
	}
	return config.Str(v)
}

func releaseFromJSON(raw *config.Map) *ReleaseInfo {
	tag := pyStrOr(raw, "tag_name")
	r := &ReleaseInfo{Tag: tag, Version: strings.TrimPrefix(tag, "v"), Notes: pyStrOr(raw, "body"),
		HTMLURL: pyStrOr(raw, "html_url")}
	if strings.HasPrefix(tag, "v") {
		r.Version = tag[1:]
	}
	r.Security = IsSecurityRelease(pyStrOr(raw, "name"), r.Notes)
	return r
}

// PyUTCNow is datetime.now(timezone.utc).isoformat(): microseconds only
// when there are some.
func PyUTCNow(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

// CheckLatest is check_latest: current against the repository's latest
// release. A repository with no release yet (GitHub's 404) is no update,
// not an error.
func CheckLatest(fetch FetchJSON, now time.Time, current, repo string) (*UpdateCheckResult, error) {
	checkedAt := PyUTCNow(now)
	repo, err := checkedRepo(repo)
	if err != nil {
		return nil, err
	}
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	status, body, err := fetch(url, UpdateCheckTimeout)
	if err != nil {
		return nil, updateErrorf("could not reach %s: %s", url, err)
	}
	if status == http.StatusNotFound {
		return &UpdateCheckResult{Current: current, CheckedAt: checkedAt}, nil
	}
	if status >= 400 {
		return nil, updateErrorf("GitHub returned %d checking %s", status, repo)
	}
	if !utf8.Valid(body) {
		return nil, updateErrorf("invalid JSON from %s: not UTF-8", url)
	}
	v, err := config.ParseJSONLastWins(body)
	if err != nil {
		return nil, updateErrorf("invalid JSON from %s: %s", url, err)
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, updateErrorf("unexpected release response from GitHub for %s", repo)
	}
	latest := releaseFromJSON(m)
	available := false
	l, lok := version.ParseRelease(latest.Version)
	c, cok := version.ParseRelease(current)
	if lok && cok {
		available = l.Compare(c) > 0
	} else {
		// A tag that isn't a release version: different means new rather
		// than never reporting an update.
		available = latest.Version != "" && latest.Version != current
	}
	return &UpdateCheckResult{Current: current, Latest: latest, UpdateAvailable: available, CheckedAt: checkedAt}, nil
}

// CheckCache is write_check_cache's dict: what the periodic check found,
// for the webUI's banner (the webUI need not reach GitHub to know).
func CheckCache(r *UpdateCheckResult, checkError, autoInstallError config.Value) *config.Map {
	m := config.NewMap()
	m.Set("checked_at", r.CheckedAt)
	m.Set("current_version", r.Current)
	m.Set("update_available", r.UpdateAvailable)
	if r.Latest != nil {
		m.Set("latest_version", r.Latest.Version)
	} else {
		m.Set("latest_version", nil)
	}
	m.Set("security", r.Latest != nil && r.Latest.Security && r.UpdateAvailable)
	if r.Latest != nil {
		m.Set("html_url", r.Latest.HTMLURL)
	} else {
		m.Set("html_url", "")
	}
	m.Set("error", checkError)
	m.Set("auto_install_error", autoInstallError)
	return m
}

// WriteCheckCache is write_json_cache: json.dumps of data, 0644 (nothing
// in it is secret), replaced atomically through path's ".tmp" sibling
// (pathlib's with_suffix).
func WriteCheckCache(path string, data *config.Map) error {
	text, err := config.PyJSON(data, -1, false)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := strings.TrimSuffix(path, filepath.Ext(path)) + ".tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadCheckCache is read_check_cache: the cached check, or nil -- also
// when it is about a version that is no longer the installed one.
func ReadCheckCache(path, current string) *config.Map {
	data, err := os.ReadFile(path)
	if err != nil || !utf8.Valid(data) {
		return nil
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil
	}
	if cur, _ := m.Get("current_version"); current != "" && cur != config.Value(current) {
		return nil
	}
	return m
}
