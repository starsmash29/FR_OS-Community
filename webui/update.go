package webui

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/version"
)

// The update screen (1.x's routes/update.py): the installed version,
// what the release check finds, what the periodic check left (G10/J3),
// the kernel's status and its buttons, through the update-helper
// (ROADMAP SEC-14, phase 4f-3b), and the two settings that are config
// saves. Installing and rolling back a signed release go through the
// update-helper too, which takes them in phase 4f-4; until then those
// POSTs answer 501 (decisions.md, 3c-1).

// defaultUpdateRepo is where FR_OS 2's releases are looked for unless
// update.repo says otherwise (1.x's frfw.update.DEFAULT_REPO names
// 1.x's own repository).
const defaultUpdateRepo = "starsmash29/FR_OS-Community"

// updateFetchTimeout is check_latest's timeout, in seconds.
const updateFetchTimeout = 10.0

// maxReleaseBytes bounds GitHub's answer: a release's JSON with its
// notes is a few KiB.
const maxReleaseBytes = 1 << 20

var releaseVersionRE = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// codenameFor is frfw.codename_for (version.Codename).
func codenameFor(v string) string { return version.Codename(v) }

// withCodename is the templates' with_codename filter.
func withCodename(v string) string { return version.WithCodename(v) }

func trimZeros(digits string) string {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	return digits
}

// compareDigits compares two decimal numbers of any length.
func compareDigits(a, b string) int {
	a, b = trimZeros(a), trimZeros(b)
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// newerVersion is parse_version(latest) > parse_version(current), and
// whether both parsed.
func newerVersion(latest, current string) (bool, bool) {
	l, c := releaseVersionRE.FindStringSubmatch(latest), releaseVersionRE.FindStringSubmatch(current)
	if l == nil || c == nil {
		return false, false
	}
	for i := 1; i <= 3; i++ {
		if d := compareDigits(l[i], c[i]); d != 0 {
			return d > 0, true
		}
	}
	return false, true
}

var securityLineRE = regexp.MustCompile(`(?im)^\s*security:\s*yes\s*$`)

// release is frfw.update.ReleaseInfo, as the page shows it.
type release struct {
	Version, Notes string
	Security       bool
}

// pyStrOr is str(raw.get(key) or "").
func pyStrOr(m *config.Map, key string) string {
	v := field(m, key)
	if !config.Truthy(v) {
		return ""
	}
	return pyStr(v)
}

func releaseOf(raw *config.Map) *release {
	tag := pyStrOr(raw, "tag_name")
	r := &release{Version: strings.TrimPrefix(tag, "v"), Notes: pyStrOr(raw, "body")}
	r.Security = strings.Contains(strings.ToLower(pyStrOr(raw, "name")), "[security]") ||
		securityLineRE.MatchString(r.Notes)
	return r
}

// checkResult is frfw.update.UpdateCheckResult: Latest nil when the
// repository has published no release.
type checkResult struct {
	Latest          *release
	UpdateAvailable bool
}

// fetchRelease is a GET of a GitHub API URL: its status and body, or
// why it couldn't be made (1.x's frfw.update._fetch_json, which leaves
// the JSON to the caller here). Only the update check calls it, when an
// admin opens the update screen.
func fetchRelease(url string, timeout float64) (int, []byte, error) {
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
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReleaseBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxReleaseBytes {
		return 0, nil, fmt.Errorf("the answer is larger than %d bytes", maxReleaseBytes)
	}
	return resp.StatusCode, body, nil
}

// checkLatest is frfw.update.check_latest: current against the
// repository's latest release; a refusal is the page's message.
func (s *Server) checkLatest(current, repo string) (*checkResult, string) {
	url := "https://api.github.com/repos/" + repo + "/releases/latest"
	status, body, err := s.env.Fetch(url, updateFetchTimeout)
	if err != nil {
		return nil, fmt.Sprintf("could not reach %s: %s", url, err)
	}
	if status == http.StatusNotFound {
		return &checkResult{}, ""
	}
	if status >= 400 {
		return nil, fmt.Sprintf("GitHub returned %d checking %s", status, repo)
	}
	if !utf8.Valid(body) {
		return nil, fmt.Sprintf("invalid JSON from %s: not UTF-8", url)
	}
	v, err := config.ParseJSONLastWins(body)
	if err != nil {
		return nil, fmt.Sprintf("invalid JSON from %s: %s", url, err)
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, "unexpected release response from GitHub for " + repo
	}
	latest := releaseOf(m)
	newer, parsed := newerVersion(latest.Version, current)
	if !parsed {
		// A tag that isn't vMAJOR.MINOR.PATCH: different means new.
		newer = latest.Version != "" && latest.Version != current
	}
	return &checkResult{Latest: latest, UpdateAvailable: newer}, ""
}

// updateRepo is _resolve_repo: update.repo of a config that parses.
func updateRepo(raw *config.Map) string {
	c, err := config.Parse(raw)
	if err != nil || c.Update.Repo == "" {
		return defaultUpdateRepo
	}
	return c.Update.Repo
}

// updateState is frfw.update.load_state: the previous version and the
// last attempt, from the update-helper's state file.
func (s *Server) updateState() (previous, last config.Value, err error) {
	data, err := os.ReadFile(s.env.Paths.UpdateState())
	if err != nil {
		return nil, nil, nil
	}
	if !utf8.Valid(data) {
		return nil, nil, errInternal // read_text raises
	}
	v, err := config.ParseJSONLastWins(data)
	if err != nil {
		return nil, nil, nil
	}
	m, ok := v.(*config.Map)
	if !ok {
		return nil, nil, nil
	}
	last = field(m, "last_update")
	if !config.Truthy(last) {
		last = nil
	}
	return field(m, "previous_version"), last, nil
}

// kernelStatus is _kernel: the update-helper's kernel_status, or why
// there is none.
func (s *Server) kernelStatus() (config.Value, string, error) {
	result, err := s.helper.KernelStatus()
	if err != nil {
		var he *HelperError
		if errors.As(err, &he) {
			return nil, "the update-helper did not answer: " + he.Msg, nil
		}
		return nil, "", errInternal
	}
	if !config.Truthy(field(result, "ok")) {
		if v := field(result, "message"); config.Truthy(v) {
			return nil, pyStr(v), nil
		}
		return nil, "no answer", nil
	}
	return field(result, "kernel"), "", nil
}

type kernelView struct {
	Summary, Ready                string
	LastCheck                     bool
	LastCheckAt, LastCheckMessage string
	LastCheckFailed               bool
	CanTry, CanCancel, Available  bool
}

func kernelViewOf(k config.Value) *kernelView {
	v := &kernelView{Summary: jinjaText(k, "summary"), Ready: jinjaText(k, "ready")}
	if lc, ok := jinjaGet(k, "last_check"); ok && config.Truthy(lc) {
		v.LastCheck = true
		v.LastCheckAt, v.LastCheckMessage = jinjaText(lc, "at"), jinjaText(lc, "message")
		e, _ := jinjaGet(lc, "error")
		v.LastCheckFailed = config.Truthy(e)
	}
	ready, _ := jinjaGet(k, "ready")
	available, _ := jinjaGet(k, "available")
	v.Available = config.Truthy(available)
	v.CanTry = config.Truthy(ready) && v.Available
	state, _ := jinjaGet(k, "state")
	v.CanCancel = state == config.Value("trial") || state == config.Value("good")
	return v
}

type updateData struct {
	Repo, Installed string
	CheckError      string
	Check           *checkResult
	LatestLabel     string

	PeriodicAt, PeriodicError, AutoInstallError, PeriodicLatest string
	AutoInstallSecurity                                         bool

	Kernel        *kernelView
	KernelError   string
	KernelUpdates bool

	Previous   string
	LastUpdate config.Value
}

func (d *updateData) Last(key string) string { return jinjaText(d.LastUpdate, key) }
func (d *updateData) HasLastMessage() bool {
	v, _ := jinjaGet(d.LastUpdate, "message")
	return config.Truthy(v)
}

func (s *Server) showUpdate(q *request) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	d := &updateData{Repo: updateRepo(raw), Installed: withCodename(s.version)}
	d.Check, d.CheckError = s.checkLatest(s.version, d.Repo)
	if d.Check != nil && d.Check.Latest != nil {
		d.LatestLabel = withCodename(d.Check.Latest.Version)
	}
	previous, last, err := s.updateState()
	if err != nil {
		return nil, err
	}
	if config.Truthy(previous) {
		d.Previous = pyStr(previous)
	}
	d.LastUpdate = last
	if periodic := readUpdateCheck(s.env.Paths.UpdateCheck(), s.version); periodic != nil {
		if v := field(periodic, "checked_at"); config.Truthy(v) {
			d.PeriodicAt = pyStr(v)
		}
		if v := field(periodic, "error"); config.Truthy(v) {
			d.PeriodicError = pyStr(v)
		}
		if v := field(periodic, "auto_install_error"); config.Truthy(v) {
			d.AutoInstallError = pyStr(v)
			d.PeriodicLatest = jinjaText(periodic, "latest_version")
		}
	}
	kernel, kernelError, err := s.kernelStatus()
	if err != nil {
		return nil, err
	}
	d.KernelError = kernelError
	if kernelError == "" && config.Truthy(kernel) {
		d.Kernel = kernelViewOf(kernel)
	}
	section, err := getMapOr(raw, "update")
	if err != nil {
		return nil, err
	}
	d.AutoInstallSecurity = field(section, "auto_install_security") == config.Value(true)
	ku, has := section.Get("kernel_updates")
	d.KernelUpdates = !has || ku != config.Value(false)
	return s.render(q, "update", flash(q, &page{Username: q.user.Username, Data: d}))
}

// saveUpdateSetting is save_auto_security and save_kernel_updates: one
// boolean of the update section.
func (s *Server) saveUpdateSetting(q *request, key, on, off string) (*answer, error) {
	raw, err := s.loadRawConfig()
	if err != nil {
		return nil, err
	}
	var enabled bool
	if err = q.fields(func(p *formParams) { enabled = p.boolOr("enabled", false) }); err != nil {
		return nil, err
	}
	section, err := copiedSection(raw, "update")
	if err != nil {
		return nil, err
	}
	section.Set(key, enabled)
	raw.Set("update", section)
	ok, message, err := s.trySave(raw)
	if err != nil {
		return nil, err
	}
	if !ok {
		return errorRedirect("/update", message), nil
	}
	if enabled {
		return successRedirect("/update", on), nil
	}
	return successRedirect("/update", off), nil
}

// saveAutoSecurity is security-lessons J3's opt-in: the router installs
// signed security releases by itself.
func (s *Server) saveAutoSecurity(q *request) (*answer, error) {
	return s.saveUpdateSetting(q, "auto_install_security",
		"Security releases will be installed automatically", "Automatic install of security releases is off")
}

// saveKernelUpdates is ROADMAP SEC-14: whether Debian's newer kernel is
// fetched (on by default); trying one stays the admin's.
func (s *Server) saveKernelUpdates(q *request) (*answer, error) {
	return s.saveUpdateSetting(q, "kernel_updates",
		"Debian's kernel fixes are fetched daily, ready to try", "Kernel updates are off")
}

// kernelAction is _kernel_action: one of the Update screen's kernel
// buttons, sent to the update-helper (ROADMAP SEC-14), and back to the
// screen with what it answered.
func (s *Server) kernelAction(cmd, failed string) (*answer, error) {
	result, err := s.helper.Kernel(cmd)
	if err != nil {
		var he *HelperError
		text := err.Error()
		if errors.As(err, &he) {
			text = he.Msg
		}
		return errorRedirect("/update", failed+": "+text), nil
	}
	if config.Truthy(field(result, "ok")) {
		if m := field(result, "message"); config.Truthy(m) {
			return successRedirect("/update", pyStr(m)), nil
		}
		return successRedirect("/update", "Done"), nil
	}
	if m := field(result, "message"); config.Truthy(m) {
		return errorRedirect("/update", pyStr(m)), nil
	}
	return errorRedirect("/update", failed), nil
}

// kernelCheck looks for Debian's newer kernel now instead of at the
// daily check.
func (s *Server) kernelCheck(q *request) (*answer, error) {
	return s.kernelAction("kernel_check", "Could not start the check")
}

// kernelTry stages the kernel that is ready and reboots into its trial
// (ROADMAP SEC-14): an admin's decision only (a viewer is refused every
// POST). The router keeps it only if it comes up on it.
func (s *Server) kernelTry(q *request) (*answer, error) {
	return s.kernelAction("kernel_try", "Could not start the trial")
}

func (s *Server) kernelCancel(q *request) (*answer, error) {
	return s.kernelAction("kernel_cancel", "Could not remove the staged kernel")
}
