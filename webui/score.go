package webui

import (
	"fmt"
	"math"
	"os"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// The security checklist (security-lessons K8, 1.x's
// frfw.security_score): K1-K7 and friends in one place, as a score and a
// list of what is still open. A check whose facts aren't available (the
// apply-helper didn't answer, no update check yet) is "unknown" and
// counts neither for nor against the score.

const (
	checkOK      = "ok"
	checkFail    = "fail"
	checkUnknown = "unknown"
)

type check struct {
	ID, Title, State, Detail, Link, Lesson string
}

type score struct{ Checks []check }

func (s *score) Passed() int {
	n := 0
	for _, c := range s.Checks {
		if c.State == checkOK {
			n++
		}
	}
	return n
}

func (s *score) Known() int {
	n := 0
	for _, c := range s.Checks {
		if c.State != checkUnknown {
			n++
		}
	}
	return n
}

// Percent is round(100 * passed / known), rounding half to even.
func (s *score) Percent() int {
	if s.Known() == 0 {
		return 0
	}
	return int(math.RoundToEven(100 * float64(s.Passed()) / float64(s.Known())))
}

// Open are the failed checks.
func (s *score) Open() []check {
	var out []check
	for _, c := range s.Checks {
		if c.State == checkFail {
			out = append(out, c)
		}
	}
	return out
}

// tri is a check's fact: true, false, or not known.
type tri int

const (
	unknown tri = iota
	yes
	no
)

func triOf(b bool) tri {
	if b {
		return yes
	}
	return no
}

func newCheck(id, title string, ok tri, good, bad, link, lesson string) check {
	switch ok {
	case yes:
		return check{id, title, checkOK, good, link, lesson}
	case no:
		return check{id, title, checkFail, bad, link, lesson}
	}
	return check{id, title, checkUnknown, "not known right now", link, lesson}
}

// readUpdateCheck is frfw.update.read_check_cache: the periodic check's
// cache, or nil when there is none or it is about another version than
// the running one.
func readUpdateCheck(path, version string) *config.Map {
	data, err := os.ReadFile(path)
	if err != nil {
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
	if cur, _ := m.Get("current_version"); cur != config.Value(version) {
		return nil
	}
	return m
}

// scoreInput is what evaluate works from. Lint is nil and Surface nil
// when they couldn't be worked out (SurfaceKnown false).
type scoreInput struct {
	config       *config.Config
	accounts     map[string]*Account
	requireMFA   bool
	updateCheck  *config.Map
	lint         []finding
	surface      []*surfaceRow
	surfaceKnown bool
}

// evaluate is frfw.security_score.evaluate. FR_OS 2 has no installed-file
// record to check yet, so the integrity check is always unknown
// (testdata/reference/decisions.md).
func evaluate(in scoreInput) *score {
	var admins []*Account
	var reserved, noMFA []string
	for _, a := range in.accounts {
		if a.IsAdmin() {
			admins = append(admins, a)
			if !a.HasMFA() {
				noMFA = append(noMFA, a.Username)
			}
		}
		if reservedUsernames[a.Username] {
			reserved = append(reserved, a.Username)
		}
	}
	slices.Sort(reserved)
	slices.Sort(noMFA)
	mfaGood := "every admin signs in with a second factor"
	if in.requireMFA {
		mfaGood += " (required)"
	}
	s := &score{Checks: []check{
		newCheck("default-user", "No default account names", triOf(len(reserved) == 0),
			"no account is called admin, root or similar",
			fmt.Sprintf("account(s) with a default name: %s -- attackers try those first", strings.Join(reserved, ", ")),
			"/users", "K1/G1"),
		newCheck("mfa", "A second factor for every admin", triOf(len(noMFA) == 0 && len(admins) > 0),
			mfaGood, "admin(s) without a second factor: "+strings.Join(noMFA, ", "), "/account/mfa", "G5"),
	}}
	c := in.config
	if c == nil {
		s.Checks = append(s.Checks, check{"config", "A valid configuration", checkFail,
			"the saved config doesn't parse, so the rest can't be checked", "/", "-"})
		return s
	}
	wanGood := "the webUI and SSH aren't reachable from the WAN"
	if c.Wireguard.Enabled {
		wanGood += " -- remote management goes through the VPN"
	}
	s.Checks = append(s.Checks, newCheck("wan-management", "Management closed to the internet",
		triOf(!c.Management.AllowWan), wanGood,
		"management.allow_wan is on: the webUI and SSH are open to the internet", "/system", "F2/G4/K5"))

	updates := unknown
	latest, security := config.Value(nil), false
	if in.updateCheck != nil {
		available, _ := in.updateCheck.Get("update_available")
		updates = triOf(!config.Truthy(available))
		latest, _ = in.updateCheck.Get("latest_version")
		sec, _ := in.updateCheck.Get("security")
		security = config.Truthy(sec)
	}
	updateBad := fmt.Sprintf("FR_OS %s is available", pyStr(latest))
	if security {
		updateBad += " -- a security release"
	}
	s.Checks = append(s.Checks, newCheck("updates", "Up to date", updates,
		"no newer release than the one running", updateBad, "/update", "G10/K3"))
	s.Checks = append(s.Checks, newCheck("auto-security", "Security updates install themselves",
		triOf(c.Update.AutoInstallSecurity), "signed security releases are installed automatically",
		"turn on automatic install of security releases", "/update", "J3"))

	rules := unknown
	var badRules []string
	nBad := 0
	if in.lint != nil {
		for _, f := range in.lint {
			if f.Kind == "any-to-any" || f.Kind == "open-from-internet" || f.Kind == "shadowed" {
				nBad++
				if !slices.Contains(badRules, f.Rule) {
					badRules = append(badRules, f.Rule)
				}
			}
		}
		slices.Sort(badRules)
		rules = triOf(nBad == 0)
	}
	s.Checks = append(s.Checks, newCheck("rules", "No any-to-any, internet-wide or shadowed rules", rules,
		"the rule check finds none",
		fmt.Sprintf("%d rule(s) to fix: %s", nBad, strings.Join(badRules, ", ")), "/rules", "K2"))
	s.Checks = append(s.Checks, newCheck("logging", "Firewall drops are logged", triOf(c.Logging.Drops),
		"what the firewall drops is logged (rate-limited, kept 90 days)", "logging.drops is off", "/", "K6"))
	segmented := c.Iot.Enabled || c.Zones.Has("iot") || c.Zones.Has("guest")
	s.Checks = append(s.Checks, newCheck("segments", "Devices are segmented", triOf(segmented),
		"IoT isolation or IoT/guest segments are on",
		"every device shares one network: add IoT/guest segments", "/segments", "K4"))

	listening := unknown
	var stray []string
	if in.surfaceKnown {
		for _, r := range in.surface {
			if r.unneeded() {
				stray = append(stray, fmt.Sprintf("%s/%d", r.Listener.Proto, r.Listener.Port))
			}
		}
		listening = triOf(len(stray) == 0)
	}
	s.Checks = append(s.Checks, newCheck("listening", "Nothing unneeded listens", listening,
		"every reachable service is one the configuration needs",
		"services nothing needs are listening: "+strings.Join(stray, ", "), "/surface", "K7"))
	s.Checks = append(s.Checks, newCheck("integrity", "FR_OS's own files are intact", unknown,
		"every installed file matches its recorded hash", "", "/system", "G9"))
	return s
}
