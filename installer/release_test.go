package installer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/release"
)

// installer/package-release.sh packs a stage into the tarball
// release.TarballName names, the same bytes every time for the same
// stage, everything under fr_os-<VERSION>/ and owned by root, and lists
// it in SHA256SUMS as release.ExpectedSHA256 reads it.
func TestPackageRelease(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	stage := t.TempDir()
	version := strings.TrimSpace(read(t, "../VERSION"))
	for name, mode := range map[string]os.FileMode{"bin/firewall-cli": 0o755, "systemd/fr-webui.service": 0o644,
		"bpf/xdp_sni_filter.o": 0o644, "scripts/fr-first-boot.sh": 0o755, "VERSION": 0o644} {
		path := filepath.Join(stage, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		body := name
		if name == "VERSION" {
			body = version + "\n"
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	name := release.TarballName(version)
	var tarballs [][]byte
	for range 2 {
		out := t.TempDir()
		cmd := exec.Command("bash", "package-release.sh", stage, out)
		cmd.Env = append(os.Environ(), "SOURCE_DATE_EPOCH=1700000000")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, b)
		}
		data, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		sums := read(t, filepath.Join(out, release.SumsName))
		want, err := release.ExpectedSHA256(sums, name)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := release.SHA256Of(bytes.NewReader(data)); got != want {
			t.Errorf("SHA256SUMS lists %s, the tarball is %s", want, got)
		}
		tarballs = append(tarballs, data)
	}
	if !bytes.Equal(tarballs[0], tarballs[1]) {
		t.Error("two packings of one stage differ")
	}
	gz, err := gzip.NewReader(bytes.NewReader(tarballs[0]))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 1700000000 {
			t.Errorf("%s: owner %d:%d, mtime %v", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		if h.Name == "fr_os-"+version+"/bin/firewall-cli" && h.Mode&0o777 != 0o755 {
			t.Errorf("firewall-cli is mode %o", h.Mode)
		}
		names = append(names, h.Name)
	}
	prefix := "fr_os-" + version + "/"
	for _, n := range names {
		if n != prefix && !strings.HasPrefix(n, prefix) {
			t.Errorf("%s is outside %s", n, prefix)
		}
	}
	if !slices.Contains(names, prefix+"systemd/fr-webui.service") || !slices.IsSorted(names) {
		t.Errorf("entries %q", names)
	}
}

// The signing key stays in the `release` environment (1.x's review
// v0.2.1 FR-NEW-002): only the jobs that sign name the secret, each runs
// there and only for a release, the jobs that build and boot never do,
// and only `publish` may write to the repository.
func TestTheSigningKeyStaysInItsJobs(t *testing.T) {
	doc, err := config.LoadYAML(read(t, "../.github/workflows/build-installer.yml"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(v config.Value, key string) config.Value {
		m, ok := v.(*config.Map)
		if !ok {
			return nil
		}
		x, _ := m.Get(key)
		return x
	}
	jobs, ok := get(doc, "jobs").(*config.Map)
	if !ok {
		t.Fatal("no jobs")
	}
	signing := map[string]bool{}
	for _, key := range jobs.Keys() {
		name, _ := key.(string)
		job := get(jobs, name)
		text, err := config.DumpYAML(job)
		if err != nil {
			t.Fatal(err)
		}
		usesKey := strings.Contains(text, "FROS_RELEASE_SIGNING_KEY")
		inRelease := get(job, "environment") == "release"
		if usesKey != inRelease {
			t.Errorf("job %s: names the key %v, in the release environment %v", name, usesKey, inRelease)
		}
		if usesKey {
			signing[name] = true
			if get(job, "if") != "${{ inputs.release_tag != '' }}" {
				t.Errorf("job %s holds the key on a test build too", name)
			}
		}
		writes := strings.Contains(text, "write")
		if writes != (name == "publish") {
			t.Errorf("job %s: asks to write %v", name, writes)
		}
	}
	if len(signing) != 2 || !signing["sign-stage"] || !signing["publish"] {
		t.Errorf("the jobs with the key are %v, want sign-stage and publish", signing)
	}
}

// A test build's throwaway key (phase 4f-4b) and the release it signs
// for the boot test are a test build's only: every step that makes, uses
// or names them runs only without release_tag, so a release's image
// trusts the release keys alone and is never built from a test version.
func TestTheBootTestKeyIsATestBuildsOnly(t *testing.T) {
	doc, err := config.LoadYAML(read(t, "../.github/workflows/build-installer.yml"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(v config.Value, key string) config.Value {
		m, ok := v.(*config.Map)
		if !ok {
			return nil
		}
		x, _ := m.Get(key)
		return x
	}
	jobs, _ := get(doc, "jobs").(*config.Map)
	found := map[string]bool{}
	for _, key := range jobs.Keys() {
		name, _ := key.(string)
		steps, _ := get(get(jobs, name), "steps").([]config.Value)
		for _, step := range steps {
			text, err := config.DumpYAML(step)
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range []string{"boot-test.key", "boot-test.pem", "FROS_TEST_VERSION", "release-next"} {
				if !strings.Contains(text, marker) {
					continue
				}
				found[marker] = true
				if get(step, "if") != "${{ inputs.release_tag == '' }}" && !strings.Contains(text, "[ -d release-next ]") {
					t.Errorf("job %s: a step with %s runs on a release too:\n%s", name, marker, text)
				}
			}
			if strings.Contains(text, "boot-test.key") && strings.Contains(text, "sign-sums") &&
				!strings.Contains(text, `rm -f \"$RUNNER_TEMP/boot-test.key\"`) && !strings.Contains(text, `rm -f "$RUNNER_TEMP/boot-test.key"`) {
				t.Errorf("job %s: the throwaway key outlives its signatures", name)
			}
		}
	}
	for _, marker := range []string{"boot-test.key", "boot-test.pem", "FROS_TEST_VERSION", "release-next"} {
		if !found[marker] {
			t.Errorf("no step has %s", marker)
		}
	}
}

// Every action the image workflow uses is pinned to a commit: a moved tag
// can't change what runs next to the signing key (1.x's
// tests/test_release_workflow.py).
func TestTheWorkflowsActionsArePinned(t *testing.T) {
	uses := regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	found := uses.FindAllStringSubmatch(read(t, "../.github/workflows/build-installer.yml"), -1)
	if len(found) == 0 {
		t.Fatal("no actions found")
	}
	for _, m := range found {
		if !pinned.MatchString(m[1]) {
			t.Errorf("%s is not pinned to a commit", m[1])
		}
	}
}
