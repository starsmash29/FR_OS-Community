// Package installer holds the FR_OS image's build (live-build tree,
// scripts) and its QEMU boot test; this test checks what can be checked
// without building it.
package installer

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// GRUB's menu has no templating of its own: every entry's kernel command
// line carries auto/config's --bootappend-live, so a UEFI boot gets the
// same live-boot session as a BIOS one (as 1.x's
// tests/test_installer_bootparams.py).
func TestGrubMenuHasTheLiveBootOptions(t *testing.T) {
	m := regexp.MustCompile(`--bootappend-live "([^"]+)"`).FindStringSubmatch(read(t, "live-build/auto/config"))
	if m == nil {
		t.Fatal("no --bootappend-live in auto/config")
	}
	lines := regexp.MustCompile(`(?m)^\s*linux .*$`).FindAllString(read(t, "live-build/config/includes.binary/boot/grub/grub.cfg"), -1)
	if len(lines) != 3 {
		t.Fatalf("%d linux lines in grub.cfg, want 3", len(lines))
	}
	for _, line := range lines {
		if !strings.Contains(line, " boot=live config "+m[1]+" ") {
			t.Errorf("grub.cfg: %q lacks %q", strings.TrimSpace(line), m[1])
		}
	}
}

// build-binaries.sh builds every Go command and every Rust binary there
// is: a new daemon can't be left out of the image by accident.
func TestEveryBinaryIsBuilt(t *testing.T) {
	script := read(t, "build-binaries.sh")
	list := func(name string) []string {
		m := regexp.MustCompile(name + `=\(([^)]*)\)`).FindStringSubmatch(script)
		if m == nil {
			t.Fatalf("no %s in build-binaries.sh", name)
		}
		return slices.Sorted(slices.Values(strings.Fields(m[1])))
	}
	var commands, crates []string
	dirs, _ := filepath.Glob("../cmd/*")
	for _, d := range dirs {
		commands = append(commands, filepath.Base(d))
	}
	bins, _ := filepath.Glob("../crates/*/src/bin/*.rs")
	for _, b := range bins {
		crates = append(crates, strings.TrimSuffix(filepath.Base(b), ".rs"))
	}
	slices.Sort(commands)
	slices.Sort(crates)
	if got := list("GO_BINARIES"); !slices.Equal(got, commands) {
		t.Errorf("GO_BINARIES %q, cmd/ has %q", got, commands)
	}
	if got := list("RUST_BINARIES"); !slices.Equal(got, crates) {
		t.Errorf("RUST_BINARIES %q, the crates have %q", got, crates)
	}
}

// Nothing on the router runs Python (FR_OS 2 is Go and Rust), and fr-xdp
// loads the XDP program itself: the image installs neither Python nor
// 1.x's bpftool and libbpf.
func TestTheImageInstallsNoPython(t *testing.T) {
	for _, line := range strings.Split(read(t, "live-build/config/package-lists/fr_os.list.chroot"), "\n") {
		pkg := strings.TrimSpace(line)
		if pkg == "" || strings.HasPrefix(pkg, "#") {
			continue
		}
		if strings.HasPrefix(pkg, "python") || pkg == "bpftool" || strings.HasPrefix(pkg, "libbpf") {
			t.Errorf("the image installs %s", pkg)
		}
	}
}
