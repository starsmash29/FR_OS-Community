// Package systemd holds FR_OS 2's systemd units; this test checks the
// sandbox each service must have (security-lessons I1), as 1.x's
// tests/test_systemd_sandbox.py does: a new unit without one fails.
package systemd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
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
	"fr-apply-helper.service":    "the privilege boundary: applies the network config",
	"fr-apply-revert.service":    "a revert is an apply: the apply-helper's own sandbox",
	"fr-firewall.service":        "the boot's apply: the apply-helper's own sandbox",
	"fr-schedule-check.service":  "reads nft's counters, and a refresh is an apply: the apply-helper's sandbox",
	"fr-accounts.service":        "useradd, groupadd, usermod and gpasswd write the account files; no network",
	"fr-dns-log-trim.service":    "empties dnsmasq's query log with CAP_DAC_OVERRIDE alone; no network",
	"fr-adblock-refresh.service": "writes the lists under /etc/fr_os, with no capability at all",
	"fr-adblock-dns.service":     "dnsmasq binds port 53, then becomes its own user",
	"fr-dhcp6.service":           "dhcpcd sets addresses and routes, then privilege-separates itself",
	"fr-tls-fp.service":          "opens a pinned BPF map, then becomes fr_os-sensor (fros_xdp::privdrop)",
	"fr-xdp-sni-logger.service":  "opens a pinned BPF map and its event file, then becomes fr_os-sensor",
}

// never is no service's to have.
var never = []string{"CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME",
	"CAP_MKNOD", "CAP_LINUX_IMMUTABLE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL", "CAP_SYSLOG",
	"CAP_SYS_TTY_CONFIG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND"}

// exposure is the `systemd-analyze security` budget (0 best, 10 worst).
var exposure = map[string]float64{"fr-apply-helper.service": 4.5, "fr-apply-revert.service": 4.5,
	"fr-firewall.service": 4.5, "fr-schedule-check.service": 4.5, "fr-dhcp6.service": 3.0, "fr-webui.service": 2.5}

// service is a unit's [Service]: each key and every value it is given.
func service(t *testing.T, name string) map[string][]string {
	return section(t, name, "[Service]")
}

// section is one section of a unit file: each key and every value it
// is given.
func section(t *testing.T, name, want string) map[string][]string {
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
		case section == want:
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

// The webUI writes only its own state, with private files, and talks
// only TCP and to the helpers' sockets (as 1.x's
// test_the_webui_writes_only_its_own_state).
func TestTheWebUIWritesOnlyItsOwnState(t *testing.T) {
	s := service(t, "fr-webui.service")
	if got := last(s, "ReadWritePaths"); got != "/etc/fr_os/webui" {
		t.Errorf("ReadWritePaths=%q", got)
	}
	if got := last(s, "UMask"); got != "0077" {
		t.Errorf("UMask=%q", got)
	}
	if got := strings.Fields(last(s, "RestrictAddressFamilies")); !slices.Equal(slices.Sorted(slices.Values(got)),
		[]string{"AF_INET", "AF_INET6", "AF_UNIX"}) {
		t.Errorf("RestrictAddressFamilies=%q", got)
	}
	if got := last(s, "CapabilityBoundingSet"); got != "CAP_NET_BIND_SERVICE" {
		t.Errorf("CapabilityBoundingSet=%q", got)
	}
	if got := last(s, "User"); got != "fr_os-webui" {
		t.Errorf("User=%q", got)
	}
}

// The pinned-map readers hold only what opening a map and giving up root
// take, and talk only to Unix sockets (as 1.x's
// test_bpf_readers_hold_only_what_opening_a_map_and_dropping_root_take).
func TestBPFReadersHoldOnlyWhatOpeningAMapAndDroppingRootTake(t *testing.T) {
	for _, name := range []string{"fr-tls-fp.service", "fr-xdp-sni-logger.service"} {
		s := service(t, name)
		got := slices.Sorted(slices.Values(strings.Fields(last(s, "CapabilityBoundingSet"))))
		if !slices.Equal(got, []string{"CAP_BPF", "CAP_SETGID", "CAP_SETUID"}) {
			t.Errorf("%s: CapabilityBoundingSet=%q", name, got)
		}
		if got := last(s, "RestrictAddressFamilies"); got != "AF_UNIX" {
			t.Errorf("%s: RestrictAddressFamilies=%q", name, got)
		}
		if _, ok := s["AmbientCapabilities"]; ok {
			t.Errorf("%s: ambient capabilities", name)
		}
	}
	if got := last(service(t, "fr-tls-fp.service"), "ReadWritePaths"); got != "-/etc/fr_os/sensors" {
		t.Errorf("fr-tls-fp.service: ReadWritePaths=%q", got)
	}
	if got := service(t, "fr-xdp-sni-logger.service")["ReadWritePaths"]; len(got) != 0 {
		t.Errorf("fr-xdp-sni-logger.service: ReadWritePaths=%q", got)
	}
}

// The log-reading sensor daemons run as fr_os-sensor from the start,
// with no capability at all, read their logs through fr_os-feeds, talk
// only to Unix sockets and write only under /etc/fr_os/sensors (as
// 1.x's units for fr-appid and fr-ai-ids).
func TestLogReadingSensorDaemonsHoldNothing(t *testing.T) {
	for _, name := range []string{"fr-appid.service", "fr-ai-ids.service"} {
		s := service(t, name)
		for key, want := range map[string]string{"User": "fr_os-sensor", "Group": "fr_os-sensor",
			"SupplementaryGroups": "fr_os-feeds", "CapabilityBoundingSet": "", "RestrictAddressFamilies": "AF_UNIX",
			"ReadWritePaths": "-/etc/fr_os/sensors", "ProtectKernelTunables": "yes", "ProtectProc": "invisible",
			"ExecStart": "/usr/libexec/fr_os/" + strings.TrimSuffix(name, ".service")} {
			if got := last(s, key); got != want {
				t.Errorf("%s: %s=%q, want %q", name, key, got, want)
			}
		}
		if _, ok := s["AmbientCapabilities"]; ok {
			t.Errorf("%s: ambient capabilities", name)
		}
		if !slices.Contains(s["SystemCallFilter"], "~@privileged") {
			t.Errorf("%s: SystemCallFilter=%q, want ~@privileged too", name, s["SystemCallFilter"])
		}
	}
}

// The IoT scan parses mDNS answers and DHCP hostnames, so it runs as
// fr_os-sensor from the start with no capability at all, asks the
// apply-helper for its two privileged steps, talks UDP only for mDNS
// and writes only under /etc/fr_os/sensors (as 1.x's
// fr-iot-scan.service); its timer starts it as 1.x's does.
func TestTheIoTScanHoldsNothing(t *testing.T) {
	s := service(t, "fr-iot-scan.service")
	for key, want := range map[string]string{"Type": "oneshot", "User": "fr_os-sensor", "Group": "fr_os-sensor",
		"SupplementaryGroups": "fr_os-feeds", "CapabilityBoundingSet": "", "ReadWritePaths": "-/etc/fr_os/sensors",
		"ProtectKernelTunables": "yes", "ExecStart": "/usr/libexec/fr_os/fr-iot-scan"} {
		if got := last(s, key); got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	if got := strings.Fields(last(s, "RestrictAddressFamilies")); !slices.Equal(slices.Sorted(slices.Values(got)),
		[]string{"AF_INET", "AF_INET6", "AF_UNIX"}) {
		t.Errorf("RestrictAddressFamilies=%q", got)
	}
	if _, ok := s["AmbientCapabilities"]; ok {
		t.Error("ambient capabilities")
	}
	if !slices.Contains(s["SystemCallFilter"], "~@privileged") {
		t.Errorf("SystemCallFilter=%q, want ~@privileged too", s["SystemCallFilter"])
	}
	timer := section(t, "fr-iot-scan.timer", "[Timer]")
	for key, want := range map[string]string{"OnBootSec": "2min", "OnUnitActiveSec": "10min",
		"RandomizedDelaySec": "30"} {
		if got := last(timer, key); got != want {
			t.Errorf("fr-iot-scan.timer: %s=%q, want %q", key, got, want)
		}
	}
	if got := last(section(t, "fr-iot-scan.timer", "[Install]"), "WantedBy"); got != "timers.target" {
		t.Errorf("fr-iot-scan.timer: WantedBy=%q", got)
	}
}

// The logger opens the event file as root, in a directory systemd makes
// root:fr_os-feeds 0750, under a umask that leaves the file 0640: its
// readers (fr_os-webui and fr_os-sensor, both in fr_os-feeds) read it,
// none of them can write it (ROADMAP SEC-4, SEC-11; as 1.x's
// test_the_sni_event_file_is_written_by_its_logger_and_read_by_one_group).
func TestTheSNIEventFileIsWrittenByItsLoggerAndReadByOneGroup(t *testing.T) {
	s := service(t, "fr-xdp-sni-logger.service")
	for key, want := range map[string]string{"User": "", "Group": "fr_os-feeds", "LogsDirectory": "fr_os-sni",
		"LogsDirectoryMode": "0750", "UMask": "0027"} {
		if got := last(s, key); got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	if got := last(service(t, "fr-webui.service"), "SupplementaryGroups"); got != "fr_os-feeds" {
		t.Errorf("fr-webui.service: SupplementaryGroups=%q", got)
	}
}

// firewall-cli's units run it from where the image installs it, with
// 1.x's arguments, and its timers start them as 1.x's do; the scheduled
// ad-block refresh holds no capability and fetches only while
// ad-blocking is on (--scheduled), the log trim and ensure-accounts have
// no network (as 1.x's units).
func TestFirewallCLIUnits(t *testing.T) {
	const cli = "/usr/libexec/fr_os/firewall-cli"
	for name, want := range map[string]string{
		"fr-firewall.service":        cli + " apply --fail-closed /etc/fr_os/config.yaml",
		"fr-accounts.service":        cli + " ensure-accounts",
		"fr-schedule-check.service":  cli + " schedule-check /etc/fr_os/config.yaml",
		"fr-dns-log-trim.service":    cli + " dns-log-trim",
		"fr-adblock-refresh.service": cli + " adblock-refresh --scheduled /etc/fr_os/config.yaml",
	} {
		s := service(t, name)
		if got := last(s, "ExecStart"); got != want {
			t.Errorf("%s: ExecStart=%q, want %q", name, got, want)
		}
		if got := last(s, "Type"); got != "oneshot" {
			t.Errorf("%s: Type=%q", name, got)
		}
	}
	for name, want := range map[string]map[string]string{
		"fr-adblock-refresh.service": {"CapabilityBoundingSet": "", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6"},
		"fr-dns-log-trim.service": {"CapabilityBoundingSet": "CAP_DAC_OVERRIDE", "PrivateNetwork": "yes",
			"RestrictAddressFamilies": "AF_UNIX", "ReadWritePaths": "-/var/log/fr_os-dns"},
		"fr-accounts.service": {"PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX AF_NETLINK"},
		"fr-firewall.service": {"RemainAfterExit": "yes", "StandardInput": "null"},
	} {
		s := service(t, name)
		for key, v := range want {
			if got := last(s, key); got != v {
				t.Errorf("%s: %s=%q, want %q", name, key, got, v)
			}
		}
	}
	if got := last(section(t, "fr-firewall.service", "[Install]"), "WantedBy"); got != "sysinit.target" {
		t.Errorf("fr-firewall.service: WantedBy=%q", got)
	}
	for name, want := range map[string]map[string]string{
		"fr-schedule-check.timer":  {"OnCalendar": "*-*-* *:02:00", "Persistent": "true"},
		"fr-dns-log-trim.timer":    {"OnCalendar": "hourly", "Persistent": "true"},
		"fr-adblock-refresh.timer": {"OnCalendar": "*-*-* 04:15:00", "Persistent": "true", "RandomizedDelaySec": "1800"},
	} {
		timer := section(t, name, "[Timer]")
		for key, v := range want {
			if got := last(timer, key); got != v {
				t.Errorf("%s: %s=%q, want %q", name, key, got, v)
			}
		}
		if got := last(section(t, name, "[Install]"), "WantedBy"); got != "timers.target" {
			t.Errorf("%s: WantedBy=%q", name, got)
		}
	}
}

// The resolvers the apply configures run as 1.x's: the ad-block dnsmasq
// writes its query log into a directory read through fr_os-feeds, the
// RA instance runs as its own dynamic account with only the two
// capabilities RAs take.
func TestTheResolverUnits(t *testing.T) {
	s := service(t, "fr-adblock-dns.service")
	for key, want := range map[string]string{"Group": "fr_os-feeds", "LogsDirectory": "fr_os-dns",
		"LogsDirectoryMode": "0750",
		"ExecStart":         "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/fr_os/dnsmasq_adblock.conf"} {
		if got := last(s, key); got != want {
			t.Errorf("fr-adblock-dns.service: %s=%q, want %q", key, got, want)
		}
	}
	s = service(t, "fr-ra.service")
	for key, want := range map[string]string{"DynamicUser": "yes", "User": "fr_os-ra",
		"AmbientCapabilities": "CAP_NET_RAW CAP_NET_ADMIN", "CapabilityBoundingSet": "CAP_NET_RAW CAP_NET_ADMIN",
		"ExecStart": "/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/fr_os/dnsmasq_ra.conf"} {
		if got := last(s, key); got != want {
			t.Errorf("fr-ra.service: %s=%q, want %q", key, got, want)
		}
	}
	if got := last(service(t, "fr-dhcp6.service"), "ExecStart"); got != "/usr/sbin/dhcpcd --nobackground --config /etc/fr_os/dhcpcd6.conf" {
		t.Errorf("fr-dhcp6.service: ExecStart=%q", got)
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
