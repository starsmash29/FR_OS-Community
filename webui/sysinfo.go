package webui

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// What the dashboard shows of the machine (1.x's frfw.sysinfo,
// frfw.netdetect, frfw.persistence.status): unprivileged reads of /proc,
// /sys and statvfs, nothing that waits. Every figure is absent when its
// source can't be read, and the page then shows "-".

type systemSnapshot struct {
	Kernel   string
	CPUModel string
	CPUCount int // 0: not known
	Load     []float64
	// Uptime is seconds; HasUptime false when /proc/uptime can't be read.
	Uptime             float64
	HasUptime          bool
	RAMUsed, RAMTotal  int64
	HasRAM             bool
	DiskUsed, DiskTotl int64
	HasDisk            bool
}

func readText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Path.read_text(): universal newlines; text that isn't UTF-8 is an
	// error 1.x doesn't catch.
	if !isUTF8(data) {
		return "", errInternal
	}
	return strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n"), nil
}

func isUTF8(b []byte) bool { return strings.ToValidUTF8(string(b), "�") == string(b) }

// readOptional is a read whose OSError 1.x catches: ok false then; a
// decoding error still fails the page.
func readOptional(path string) (string, bool, error) {
	text, err := readText(path)
	if errors.Is(err, errInternal) {
		return "", false, err
	}
	return text, err == nil, nil
}

func (s *Server) snapshot() (*systemSnapshot, error) {
	p := s.env.Paths
	snap := &systemSnapshot{Kernel: s.env.Kernel(), CPUCount: s.env.CPUs()}
	if text, ok, err := readOptional(p.at("/proc/meminfo")); err != nil {
		return nil, err
	} else if ok {
		values := map[string]int64{}
		for _, line := range config.PySplitlines(text) {
			key, rest, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			rest = config.PyStrip(rest)
			if !strings.HasSuffix(rest, "kB") {
				continue
			}
			n, ok := config.PyInt(config.PyStrip(strings.TrimSuffix(rest, "kB")))
			if !ok || !n.IsInt64() {
				continue
			}
			values[config.PyStrip(key)] = n.Int64() * 1024
		}
		total, okT := values["MemTotal"]
		avail, okA := values["MemAvailable"]
		if okT && okA {
			snap.RAMUsed, snap.RAMTotal, snap.HasRAM = max(0, total-avail), total, true
		}
	}
	if used, total, ok := s.env.Disk("/"); ok {
		snap.DiskUsed, snap.DiskTotl, snap.HasDisk = used, total, true
	}
	if text, ok, err := readOptional(p.at("/proc/cpuinfo")); err != nil {
		return nil, err
	} else if ok {
		for _, line := range config.PySplitlines(text) {
			if strings.HasPrefix(line, "model name") {
				_, model, found := strings.Cut(line, ":")
				if !found {
					return nil, errInternal // 1.x: IndexError
				}
				snap.CPUModel = config.PyStrip(model)
				break
			}
		}
	}
	if text, ok, err := readOptional(p.at("/proc/loadavg")); err != nil {
		return nil, err
	} else if ok {
		parts := config.PySplit(text)
		if len(parts) >= 3 {
			var load []float64
			for _, part := range parts[:3] {
				f, ok := config.PyFloat(part)
				if !ok {
					load = nil
					break
				}
				load = append(load, f)
			}
			snap.Load = load
		}
	}
	if text, ok, err := readOptional(p.at("/proc/uptime")); err != nil {
		return nil, err
	} else if ok {
		if parts := config.PySplit(text); len(parts) > 0 {
			snap.Uptime, snap.HasUptime = config.PyFloat(parts[0])
		}
	}
	return snap, nil
}

// pyPercent is "%d%%" % (ratio * 100): the percentage, truncated.
func pyPercent(ratio float64) string { return fmt.Sprintf("%d%%", int64(ratio*100)) }

// width is `(ratio or 0) * 100` as Jinja prints it: an int 0 for none
// (or a zero ratio), else the float's repr.
func width(ratio float64, known bool) string {
	if !known || ratio == 0 {
		return "0"
	}
	return config.FloatRepr(ratio * 100)
}

type meter struct{ Label, Percent, Width string }

func (snap *systemSnapshot) meters() []meter {
	var out []meter
	label := "CPU load (1 min)"
	if len(snap.Load) == 3 {
		label += fmt.Sprintf(" · %.2f / %.2f / %.2f", snap.Load[0], snap.Load[1], snap.Load[2])
	}
	m := meter{Label: label, Percent: "-", Width: "0"}
	if len(snap.Load) == 3 && snap.CPUCount != 0 {
		r := math.Min(1.0, snap.Load[0]/float64(snap.CPUCount))
		m.Percent, m.Width = pyPercent(r), width(r, true)
	}
	out = append(out, m)

	ram := meter{Label: "Memory · " + formatBytes(snap.RAMUsed, snap.HasRAM) + " / " + formatBytes(snap.RAMTotal, snap.HasRAM),
		Percent: "-", Width: "0"}
	if snap.HasRAM && snap.RAMTotal != 0 {
		r := float64(snap.RAMUsed) / float64(snap.RAMTotal)
		ram.Percent, ram.Width = pyPercent(r), width(r, true)
	}
	out = append(out, ram)

	disk := meter{Label: "Root filesystem · " + formatBytes(snap.DiskUsed, snap.HasDisk) + " / " +
		formatBytes(snap.DiskTotl, snap.HasDisk), Percent: "-", Width: "0"}
	if snap.HasDisk && snap.DiskTotl != 0 {
		r := float64(snap.DiskUsed) / float64(snap.DiskTotl)
		disk.Percent, disk.Width = pyPercent(r), width(r, true)
	}
	return append(out, disk)
}

// formatBytes is frfw.sysinfo.format_bytes.
func formatBytes(value int64, known bool) string {
	if !known {
		return "-"
	}
	size := float64(value)
	for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if size < 1024 || unit == "TiB" {
			if unit == "B" {
				return fmt.Sprintf("%.0f B", size)
			}
			return fmt.Sprintf("%.1f %s", size, unit)
		}
		size /= 1024
	}
	return ""
}

// formatDuration is frfw.sysinfo.format_duration.
func formatDuration(seconds float64, known bool) string {
	if !known {
		return "-"
	}
	minutes := int64(math.Floor(seconds / 60))
	days, minutes := pyDivmod(minutes, 24*60)
	hours, minutes := pyDivmod(minutes, 60)
	switch {
	case days != 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	case hours != 0:
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func pyDivmod(a, b int64) (int64, int64) {
	q, r := a/b, a%b
	if r != 0 && (r < 0) != (b < 0) {
		q, r = q-1, r+b
	}
	return q, r
}

// linkStates is frfw.netdetect.list_interfaces(include_virtual=True)'s
// carrier per device: true up, false down; a device not listed, or whose
// carrier can't be read, is absent.
func (s *Server) linkStates() (map[string]*bool, error) {
	dir := s.env.Paths.at("/sys/class/net")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return map[string]*bool{}, nil
	}
	out := map[string]*bool{}
	for _, e := range entries {
		text, ok, err := readOptional(filepath.Join(dir, e.Name(), "carrier"))
		if err != nil {
			return nil, err
		}
		if !ok {
			out[e.Name()] = nil
			continue
		}
		up := config.PyStrip(text) == "1"
		out[e.Name()] = &up
	}
	return out, nil
}

// liveWithoutPersistence: a live system (boot=live) with no persistence
// file system mounted, whose changes a reboot loses
// (frfw.persistence.status: live and not active).
func (s *Server) liveWithoutPersistence() (bool, error) {
	cmdline, _, err := readOptional(s.env.Paths.at("/proc/cmdline"))
	if err != nil {
		return false, err
	}
	if !slices.Contains(config.PySplit(cmdline), "boot=live") {
		return false, nil
	}
	mounts, _, err := readOptional(s.env.Paths.at("/proc/mounts"))
	if err != nil {
		return false, err
	}
	for _, line := range config.PySplitlines(mounts) {
		parts := config.PySplit(line)
		if len(parts) >= 2 && strings.HasPrefix(strings.ReplaceAll(parts[1], `\040`, " "), "/run/live/persistence/") {
			return false, nil
		}
	}
	return true, nil
}

// countBlockedDomains is frfw.adblock.count_blocked_domains: the
// non-blank, non-comment lines of the hosts file; 0 when there is none.
func countBlockedDomains(path string) (int, error) {
	text, err := readText(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, errInternal
	}
	n := 0
	for _, line := range config.PySplitlines(text) {
		if config.PyStrip(line) != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n, nil
}

// tlsGroups is frfw.pqc.read_configured_tls_groups: the Groups= of the
// webUI's OpenSSL fragment, ok false when there is none.
func tlsGroups(path string) (string, bool, error) {
	text, err := readText(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errInternal
	}
	for _, line := range config.PySplitlines(text) {
		line = config.PyStrip(line)
		if strings.HasPrefix(line, "Groups") {
			_, value, _ := strings.Cut(line, "=")
			return config.PyStrip(value), true, nil
		}
	}
	return "", false, nil
}

// thousands is "{:,}".format(n).
func thousands(n int) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
