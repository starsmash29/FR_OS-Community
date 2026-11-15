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
	"fr-apply-helper.service":      "the privilege boundary: applies the network config",
	"fr-apply-revert.service":      "a revert is an apply: the apply-helper's own sandbox",
	"fr-firewall.service":          "the boot's apply: the apply-helper's own sandbox",
	"fr-schedule-check.service":    "reads nft's counters, and a refresh is an apply: the apply-helper's sandbox",
	"fr-accounts.service":          "useradd, groupadd, usermod and gpasswd write the account files; no network",
	"fr-dns-log-trim.service":      "empties dnsmasq's query log with CAP_DAC_OVERRIDE alone; no network",
	"fr-adblock-refresh.service":   "writes the lists under /etc/fr_os, with no capability at all",
	"fr-adblock-dns.service":       "dnsmasq binds port 53, then becomes its own user",
	"fr-dhcp6.service":             "dhcpcd sets addresses and routes, then privilege-separates itself",
	"fr-tls-fp.service":            "opens a pinned BPF map, then becomes fr_os-sensor (fros_xdp::privdrop)",
	"fr-xdp-sni-logger.service":    "opens a pinned BPF map and its event file, then becomes fr_os-sensor",
	"fr-first-boot.service":        "once per machine: writes /etc (accounts, config, console), probes each port for DHCP",
	"fr-persistence-setup.service": "partitions and formats the boot medium's free space and mounts it; no network",
	"fr-initial-password.service":  "reads the webUI's account file with CAP_DAC_READ_SEARCH alone; no network",
	"fr-console-ports.service":     "reads root's applied config and writes root's console files, with no capability",
	"fr-kernel-confirm.service":    "writes the boot environment on the persistence partition, reads the ruleset (SEC-14)",
	"fr-kernel-prepare.service":    "dpkg installs Debian's kernel package into the persistent root (SEC-14)",
	"fr-update-helper.service":     "stages a kernel on the persistence partition, with no capability at all (SEC-14)",
}

// broader is what a service holds beyond everywhere, and why: the
// setting's value it has instead.
var broader = map[string]map[string]string{
	// The raw block devices: it partitions and formats the boot medium.
	"fr-persistence-setup.service": {"PrivateDevices": "no"},
	// dpkg writes /boot, /usr/lib/modules, /var/lib/dpkg and /etc, and
	// runs the kernel package's maintainer scripts (as 1.x's unit).
	"fr-kernel-prepare.service": {"ProtectSystem": "", "ProtectKernelModules": "", "MemoryDenyWriteExecute": ""},
}

// families is the socket families a service may have beyond AF_UNIX,
// AF_NETLINK, AF_INET and AF_INET6, and why.
var families = map[string]map[string]string{
	"fr-first-boot.service": {"AF_PACKET": "detect-wan-lan's DHCP probe, before a port has an address (SEC-8)"},
}

// never is no service's to have.
var never = []string{"CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_BOOT", "CAP_SYS_RAWIO", "CAP_SYS_TIME",
	"CAP_MKNOD", "CAP_LINUX_IMMUTABLE", "CAP_MAC_ADMIN", "CAP_MAC_OVERRIDE", "CAP_AUDIT_CONTROL", "CAP_SYSLOG",
	"CAP_SYS_TTY_CONFIG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND"}

// exposure is the `systemd-analyze security` budget (0 best, 10 worst).
var exposure = map[string]float64{"fr-apply-helper.service": 4.5, "fr-apply-revert.service": 4.5,
	"fr-firewall.service": 4.5, "fr-schedule-check.service": 4.5, "fr-dhcp6.service": 3.0, "fr-webui.service": 2.5,
	"fr-first-boot.service": 3.0, "fr-kernel-prepare.service": 3.5}

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
			if v, ok := broader[name][key]; ok {
				allowed = []string{v}
			}
			if v := last(s, key); !contains(allowed, v) {
				t.Errorf("%s: %s=%q, want one of %q", name, key, v, allowed)
			}
		}
		if len(s["SystemCallFilter"]) == 0 {
			t.Errorf("%s: no SystemCallFilter", name)
		}
		for _, family := range strings.Fields(last(s, "RestrictAddressFamilies")) {
			if !contains([]string{"AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"}, family) && families[name][family] == "" {
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
		"fr-firewall.service":          cli + " apply --fail-closed /etc/fr_os/config.yaml",
		"fr-accounts.service":          cli + " ensure-accounts",
		"fr-schedule-check.service":    cli + " schedule-check /etc/fr_os/config.yaml",
		"fr-dns-log-trim.service":      cli + " dns-log-trim",
		"fr-adblock-refresh.service":   cli + " adblock-refresh --scheduled /etc/fr_os/config.yaml",
		"fr-persistence-setup.service": cli + " persistence auto --reboot",
		"fr-initial-password.service":  cli + " initial-password",
		"fr-console-ports.service":     cli + " console-ports --watch",
		"fr-first-boot.service":        "/usr/libexec/fr_os/fr-first-boot.sh",
	} {
		s := service(t, name)
		if got := last(s, "ExecStart"); got != want {
			t.Errorf("%s: ExecStart=%q, want %q", name, got, want)
		}
		if name == "fr-console-ports.service" {
			if got := last(s, "Type"); got != "simple" {
				t.Errorf("%s: Type=%q", name, got)
			}
			continue
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
		"fr-persistence-setup.service": {"PrivateNetwork": "yes", "CapabilityBoundingSet": "CAP_SYS_ADMIN",
			"RestrictAddressFamilies": "AF_UNIX AF_NETLINK"},
		"fr-initial-password.service": {"PrivateNetwork": "yes", "CapabilityBoundingSet": "CAP_DAC_READ_SEARCH",
			"RestrictAddressFamilies": "AF_UNIX", "ReadWritePaths": "-/etc/issue.d -/etc/issue"},
		"fr-console-ports.service": {"CapabilityBoundingSet": "", "IPAddressDeny": "any",
			"RestrictAddressFamilies": "AF_UNIX AF_NETLINK"},
		"fr-first-boot.service": {"RemainAfterExit": "yes"},
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

// ROADMAP SEC-14: fr-kernel-confirm writes the GRUB environment block
// on the persistence partition's own root (outside the overlay) and a
// security alert; it reads the ruleset, and asks systemd -- never the
// kernel itself -- to reboot after a failed trial. It runs only on a
// boot FR_OS's GRUB started, after the router has had its chance to
// come up.
func TestKernelConfirmUnit(t *testing.T) {
	const name = "fr-kernel-confirm.service"
	s := service(t, name)
	for key, want := range map[string]string{
		"ExecStart":             "/usr/libexec/fr_os/firewall-cli kernel confirm-boot",
		"Type":                  "oneshot",
		"RemainAfterExit":       "yes",
		"ReadWritePaths":        "-/run/live/persistence -/var/log/fr_os",
		"CapabilityBoundingSet": "CAP_NET_ADMIN",
		"IPAddressDeny":         "any",
		"IPAddressAllow":        "localhost",
	} {
		if got := last(s, key); got != want {
			t.Errorf("%s: %s=%q, want %q", name, key, got, want)
		}
	}
	if got := strings.Fields(last(s, "SystemCallFilter")); !slices.Contains(got, "@reboot") ||
		!strings.HasPrefix(last(s, "SystemCallFilter"), "~") {
		t.Errorf("%s: SystemCallFilter=%q does not deny @reboot", name, last(s, "SystemCallFilter"))
	}
	unit := section(t, name, "[Unit]")
	if got := last(unit, "ConditionKernelCommandLine"); got != "fr_os.kernel" {
		t.Errorf("%s: ConditionKernelCommandLine=%q", name, got)
	}
	after := strings.Fields(last(unit, "After"))
	for _, u := range []string{"fr-accounts.service", "fr-firewall.service", "fr-webui.service",
		"fr-persistence-setup.service"} {
		if !slices.Contains(after, u) {
			t.Errorf("%s: After=%q lacks %s", name, after, u)
		}
	}
	if got := last(section(t, name, "[Install]"), "WantedBy"); got != "multi-user.target" {
		t.Errorf("%s: WantedBy=%q", name, got)
	}
}

// First boot runs as 1.x's: before fr-first-boot.service on a live image
// booted for persistence (which may reboot once), never again once its
// marker is there; the webUI pulls in the unit that takes the generated
// password off the console (security-lessons G1), which watches the
// account file.
func TestFirstBootUnits(t *testing.T) {
	unit := section(t, "fr-persistence-setup.service", "[Unit]")
	if got := unit["ConditionKernelCommandLine"]; !slices.Equal(got, []string{"boot=live", "persistence"}) {
		t.Errorf("fr-persistence-setup.service: ConditionKernelCommandLine=%q", got)
	}
	if got := last(unit, "Before"); got != "fr-first-boot.service" {
		t.Errorf("fr-persistence-setup.service: Before=%q", got)
	}
	unit = section(t, "fr-first-boot.service", "[Unit]")
	if got := last(unit, "ConditionPathExists"); got != "!/etc/fr_os/.first-boot-done" {
		t.Errorf("fr-first-boot.service: ConditionPathExists=%q", got)
	}
	if got := strings.Fields(last(unit, "After")); !slices.Contains(got, "fr-persistence-setup.service") {
		t.Errorf("fr-first-boot.service: After=%q", got)
	}
	// Both run ensure-accounts, which makes the audit log's directory
	// under /var/log on a fresh system; under ProtectSystem=strict only
	// systemd can make it (an optional ReadWritePaths= entry for it
	// leaves /var read-only, and first boot fails with EROFS).
	for _, name := range []string{"fr-accounts.service", "fr-first-boot.service"} {
		svc := section(t, name, "[Service]")
		if got := last(svc, "LogsDirectory"); got != "fr_os" {
			t.Errorf("%s: LogsDirectory=%q, want fr_os", name, got)
		}
		if got := last(svc, "LogsDirectoryMode"); got != "0750" {
			t.Errorf("%s: LogsDirectoryMode=%q, want 0750", name, got)
		}
	}
	wants := strings.Fields(last(section(t, "fr-webui.service", "[Unit]"), "Wants"))
	for _, w := range []string{"fr-initial-password.path", "fr-initial-password.service"} {
		if !slices.Contains(wants, w) {
			t.Errorf("fr-webui.service doesn't want %s", w)
		}
	}
	path := section(t, "fr-initial-password.path", "[Path]")
	if got := last(path, "PathChanged"); got != "/etc/fr_os/webui/auth.json" {
		t.Errorf("fr-initial-password.path: PathChanged=%q", got)
	}
	if got := last(path, "Unit"); got != "fr-initial-password.service" {
		t.Errorf("fr-initial-password.path: Unit=%q", got)
	}
}

// fr-first-boot.sh starts only units this directory has, keeps the
// generated password out of the shell (it goes to the console's
// root-only file), and runs firewall-cli from where the image installs
// it.
func TestFirstBootScript(t *testing.T) {
	text, err := os.ReadFile("../scripts/fr-first-boot.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(text)
	loop := regexp.MustCompile(`(?s)for unit in \\\n(.*?)\ndo\n`).FindStringSubmatch(script)
	if loop == nil {
		t.Fatal("no unit loop")
	}
	for _, unit := range strings.Fields(strings.ReplaceAll(loop[1], `\`, "")) {
		name := unit
		if !strings.Contains(name, ".") {
			name += ".service"
		}
		if _, err := os.Stat(name); err != nil {
			t.Errorf("fr-first-boot.sh starts %s, which isn't here", unit)
		}
	}
	if !strings.Contains(script, "set-admin-password --generate --show-on-console") || strings.Contains(script, "PASSWORD") {
		t.Error("the generated password must go to the console only")
	}
	if !strings.Contains(script, "FIREWALL_CLI=${FIREWALL_CLI:-/usr/libexec/fr_os/firewall-cli}") {
		t.Error("firewall-cli not from /usr/libexec/fr_os")
	}
}

// ROADMAP SEC-14, step 3: fr-kernel-prepare installs Debian's newer
// kernel, on a live router with persistence only, daily and in the
// background (its timer as 1.x's); it never reboots. The update-helper
// stages the prepared kernel for the webUI's "Try it" and asks systemd
// to reboot: root with no capability, the socket the webUI's alone.
func TestKernelPrepareAndUpdateHelperUnits(t *testing.T) {
	s := service(t, "fr-kernel-prepare.service")
	for key, want := range map[string]string{"ExecStart": "/usr/libexec/fr_os/firewall-cli kernel prepare",
		"Type": "oneshot", "Nice": "10", "IOSchedulingClass": "idle", "TimeoutStartSec": "45min"} {
		if got := last(s, key); got != want {
			t.Errorf("fr-kernel-prepare.service: %s=%q, want %q", key, got, want)
		}
	}
	unit := section(t, "fr-kernel-prepare.service", "[Unit]")
	if got := unit["ConditionKernelCommandLine"]; !slices.Equal(got, []string{"boot=live", "persistence"}) {
		t.Errorf("fr-kernel-prepare.service: ConditionKernelCommandLine=%q", got)
	}
	timer := section(t, "fr-kernel-prepare.timer", "[Timer]")
	for key, want := range map[string]string{"OnBootSec": "30min", "OnUnitActiveSec": "1d",
		"RandomizedDelaySec": "1h", "Persistent": "true"} {
		if got := last(timer, key); got != want {
			t.Errorf("fr-kernel-prepare.timer: %s=%q, want %q", key, got, want)
		}
	}
	if got := last(section(t, "fr-kernel-prepare.timer", "[Install]"), "WantedBy"); got != "timers.target" {
		t.Errorf("fr-kernel-prepare.timer: WantedBy=%q", got)
	}

	s = service(t, "fr-update-helper.service")
	for key, want := range map[string]string{"ExecStart": "/usr/libexec/fr_os/fr-update-helper",
		"ReadWritePaths": "-/run/live/persistence -/var/log/fr_os", "CapabilityBoundingSet": "",
		"IPAddressDeny": "any", "RestrictAddressFamilies": "AF_UNIX AF_NETLINK"} {
		if got := last(s, key); got != want {
			t.Errorf("fr-update-helper.service: %s=%q, want %q", key, got, want)
		}
	}
	if !slices.Contains(strings.Fields(last(s, "SystemCallFilter")), "@reboot") {
		t.Errorf("fr-update-helper.service: SystemCallFilter=%q does not deny @reboot", last(s, "SystemCallFilter"))
	}
	socket := section(t, "fr-update-helper.socket", "[Socket]")
	for key, want := range map[string]string{"ListenStream": "/run/fr_os/update.sock", "SocketMode": "0600",
		"SocketUser": "fr_os-webui", "SocketGroup": "root"} {
		if got := last(socket, key); got != want {
			t.Errorf("fr-update-helper.socket: %s=%q, want %q", key, got, want)
		}
	}
}
