// Package systemd holds FR_OS 2's systemd units; this test checks the
// sandbox each service must have (security-lessons I1), as 1.x's
// tests/test_systemd_sandbox.py does: a new unit without one fails.
package systemd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// everywhere is what every service has, however broad its job.
var everywhere = map[string][]string{
	"NoNewPrivileges":         {"yes"},
	"ProtectHome":             {"yes", "read-only"},
	"ProtectKernelLogs":       {"yes"},
	"ProtectClock":            {"yes"},
	"RestrictNamespaces":      {"yes"},
	"RestrictRealtime":        {"yes"},
	"RestrictSUIDSGID":        {"yes"},
	"LockPersonality":         {"yes"},
	"SystemCallArchitectures": {"native"},
	"PrivateDevices":          {"yes"},
	"ProtectKernelModules":    {"yes"},
	"ProtectControlGroups":    {"yes"},
	"ProtectHostname":         {"yes"},
	"MemoryDenyWriteExecute":  {"yes"},
	"SystemCallErrorNumber":   {"EPERM"},
	"ProtectSystem":           {"strict"},
}

// root is the services that run as root, and why. Every other service
// runs as its own unprivileged account.
var root = map[string]string{
	"fr-apply-helper.service": "the privilege boundary: applies the network config",
	"fr-apply-revert.service": "a revert is an apply: the apply-helper's own sandbox",
}

// never is no service's to have.
var never = []string{"CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME",
	"CAP_MKNOD", "CAP_LINUX_IMMUTABLE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL", "CAP_SYSLOG",
	"CAP_SYS_TTY_CONFIG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND"}

// exposure is the `systemd-analyze security` budget (0 best, 10 worst).
var exposure = map[string]float64{"fr-apply-helper.service": 4.5, "fr-apply-revert.service": 4.5}

// service is a unit's [Service]: each key and every value it is given.
func service(t *testing.T, name string) map[string][]string {
	text, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	section := ""
	for _, raw := range strings.Split(string(text), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = line
		case section == "[Service]":
			key, value, _ := strings.Cut(line, "=")
			out[key] = append(out[key], value)
		}
	}
	return out
}

func last(settings map[string][]string, key string) string {
	v := settings[key]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func services(t *testing.T) []string {
	names, err := filepath.Glob("*.service")
	if err != nil || len(names) == 0 {
		t.Fatalf("no services: %v", err)
	}
	return names
}

func TestSandbox(t *testing.T) {
	for _, name := range services(t) {
		s := service(t, name)
		for key, allowed := range everywhere {
			if v := last(s, key); !contains(allowed, v) {
				t.Errorf("%s: %s=%q, want one of %q", name, key, v, allowed)
			}
		}
		if len(s["SystemCallFilter"]) == 0 {
			t.Errorf("%s: no SystemCallFilter", name)
		}
		for _, family := range strings.Fields(last(s, "RestrictAddressFamilies")) {
			if !contains([]string{"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"}, family) {
				t.Errorf("%s: socket family %s", name, family)
			}
		}
		if last(s, "RestrictAddressFamilies") == "" {
			t.Errorf("%s: no RestrictAddressFamilies", name)
		}
		caps, ok := s["CapabilityBoundingSet"]
		if !ok {
			t.Errorf("%s: no CapabilityBoundingSet", name)
		}
		for _, c := range strings.Fields(strings.Join(caps, " ")) {
			if contains(never, c) {
				t.Errorf("%s: %s in its bounding set", name, c)
			}
		}
		if _, ok := s["User"]; !ok && root[name] == "" {
			t.Errorf("%s runs as root without a reason in root", name)
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var overall = regexp.MustCompile(`Overall exposure level for \S+: ([0-9.]+)`)

func TestExposure(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("needs systemd-analyze")
	}
	for _, name := range services(t) {
		budget, ok := exposure[name]
		if !ok {
			budget = 2.5
		}
		out, _ := exec.Command("systemd-analyze", "security", "--offline=true", name).CombinedOutput()
		m := overall.FindSubmatch(out)
		if m == nil {
			t.Skipf("systemd-analyze security --offline gave no score (systemd < 252?): %.200s", out)
		}
		score, _ := strconv.ParseFloat(string(m[1]), 64)
		if score > budget {
			t.Errorf("%s: exposure %.1f, budget %.1f", name, score, budget)
		}
	}
}
