package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/config"
)

// Security-lessons J2, as 1.x's tests/test_release_review.py: no release
// without an adversarial review on record -- two different models, the
// reviewed commit part of the release and newer than the previous one,
// no critical or high finding left open.

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func repo(t *testing.T) string {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	run(t, dir, "init", "-q", "-b", "main")
	run(t, dir, "config", "user.email", "t@example.com")
	run(t, dir, "config", "user.name", "t")
	write(t, filepath.Join(dir, "a"), "1")
	run(t, dir, "add", "a")
	run(t, dir, "commit", "-qm", "first")
	run(t, dir, "tag", "v0.1.0")
	write(t, filepath.Join(dir, "a"), "2")
	run(t, dir, "commit", "-qam", "second")
	return dir
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func record(t *testing.T, dir, commit, models string, rows ...string) {
	if commit == "" {
		commit = run(t, dir, "rev-parse", "HEAD")
	}
	if rows == nil {
		rows = []string{"| R1 | high | login bypass | fixed in abc123 | A #1, B #4 |",
			"| R2 | low | typo | accepted: cosmetic | B #9 |"}
	}
	write(t, filepath.Join(dir, "docs", "reviews", "v0.2.0.md"), strings.Join(append([]string{
		"# Adversarial review – v0.2.0", "",
		"- **Reviewed commit:** `" + commit + "`", "- **Models:** " + models, "",
		"| ID | Severity | Finding | Status | Sources |", "|---|---|---|---|---|"}, append(rows, "")...), "\n"))
}

func says(problems []string, text string) bool {
	return slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, text) })
}

func TestACompleteRecordPasses(t *testing.T) {
	dir := repo(t)
	record(t, dir, "", "Model A, Model B")
	for _, v := range []string{"0.2.0", "v0.2.0"} {
		if p := check(v, dir); len(p) != 0 {
			t.Errorf("%s: %v", v, p)
		}
	}
}

func TestNoRecordNoRelease(t *testing.T) {
	if p := check("0.2.0", repo(t)); !says(p, "is missing") {
		t.Errorf("%v", p)
	}
}

func TestOneModelIsNotEnough(t *testing.T) {
	dir := repo(t)
	record(t, dir, "", "Model A, model a")
	if p := check("0.2.0", dir); !says(p, "two different models") {
		t.Errorf("%v", p)
	}
}

func TestAnOpenHighFindingBlocks(t *testing.T) {
	for _, status := range []string{"open", "reported", "needs verification", ""} {
		dir := repo(t)
		record(t, dir, "", "A, B", "| R1 | high | login bypass | "+status+" | A #1 |")
		if p := check("0.2.0", dir); !says(p, "open high finding R1") {
			t.Errorf("%q: %v", status, p)
		}
	}
}

func TestOpenMediumFindingsDontBlock(t *testing.T) {
	dir := repo(t)
	record(t, dir, "", "A, B", "| R1 | medium | slow page | open | A #1 |")
	if p := check("0.2.0", dir); len(p) != 0 {
		t.Errorf("%v", p)
	}
}

func TestTheReviewMustBeOfThisRelease(t *testing.T) {
	dir := repo(t)
	first := run(t, dir, "rev-list", "--max-parents=0", "HEAD")
	record(t, dir, first, "A, B")
	if p := check("0.2.0", dir); !says(p, "before the previous release v0.1.0") {
		t.Errorf("before the previous release: %v", p)
	}
	run(t, dir, "checkout", "-qb", "side", first)
	write(t, filepath.Join(dir, "b"), "x")
	run(t, dir, "add", "b")
	run(t, dir, "commit", "-qm", "side")
	side := run(t, dir, "rev-parse", "HEAD")
	run(t, dir, "checkout", "-q", "main")
	record(t, dir, side, "A, B")
	if p := check("0.2.0", dir); !says(p, "not part of this release") {
		t.Errorf("never merged: %v", p)
	}
	record(t, dir, strings.Repeat("0", 40), "A, B")
	if p := check("0.2.0", dir); !says(p, "doesn't exist") {
		t.Errorf("no such commit: %v", p)
	}
}

// A beta is reviewed as any release, and is a previous release to the
// final one (decisions.md, "phase 4f-4b").
func TestABetaIsAReleaseToo(t *testing.T) {
	dir := repo(t)
	beta := run(t, dir, "rev-parse", "HEAD")
	run(t, dir, "tag", "v0.2.0-beta.1")
	write(t, filepath.Join(dir, "a"), "3")
	run(t, dir, "commit", "-qam", "third")
	record(t, dir, beta, "A, B")
	if p := check("0.2.0", dir); !says(p, "before the previous release v0.2.0-beta.1") {
		t.Errorf("reviewed the beta, not the release: %v", p)
	}
	write(t, filepath.Join(dir, "docs", "reviews", "v0.2.0-beta.2.md"), strings.ReplaceAll(
		read(t, filepath.Join(dir, "docs", "reviews", "v0.2.0.md")), "`"+beta+"`", "`"+run(t, dir, "rev-parse", "HEAD")+"`"))
	if p := check("v0.2.0-beta.2", dir); len(p) != 0 {
		t.Errorf("beta.2: %v", p)
	}
	if p := check("0.2.0-rc.1", dir); !says(p, "not a version") {
		t.Errorf("rc: %v", p)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestATableIsRequired(t *testing.T) {
	dir := repo(t)
	write(t, filepath.Join(dir, "docs", "reviews", "v0.2.0.md"),
		"- **Reviewed commit:** "+run(t, dir, "rev-parse", "HEAD")+"\n- **Models:** A, B\n\nNothing found.\n")
	if p := check("0.2.0", dir); !says(p, "findings table") {
		t.Errorf("%v", p)
	}
}

func TestTheTemplateIsTheDocumentedFormat(t *testing.T) {
	data, err := os.ReadFile("../../docs/reviews/TEMPLATE.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if field(text, "Models") == "" || field(text, "Reviewed commit") == "" {
		t.Error("the template lacks Models or Reviewed commit")
	}
	var severities []string
	for _, r := range findings(text) {
		severities = append(severities, r["severity"])
	}
	if !slices.Equal(severities, []string{"high", "medium", "low"}) {
		t.Errorf("severities %v", severities)
	}
}

// The release workflow runs the gate first, on a release only, before
// anything is built, with the tags it compares against.
func TestTheReleaseWorkflowRunsItFirst(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/build-installer.yml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := config.LoadYAML(string(data))
	if err != nil {
		t.Fatal(err)
	}
	steps, _ := lookup(t, doc, "jobs", "stage", "steps").([]config.Value)
	if len(steps) == 0 {
		t.Fatal("the stage job has no steps")
	}
	if depth := lookup(t, steps[0], "with", "fetch-depth"); config.Repr(depth) != "0" {
		t.Errorf("the first step must check out with fetch-depth 0: %s", config.Repr(steps[0]))
	}
	gate := -1
	for i, step := range steps {
		run, _ := lookup(t, step, "run").(string)
		switch {
		case strings.Contains(run, "go run ./release/reviewgate"):
			gate = i
			if lookup(t, step, "if") != "${{ inputs.release_tag != '' }}" {
				t.Errorf("the review gate must run on a release: %s", config.Repr(step))
			}
		case run != "" && gate < 0:
			t.Errorf("step %d runs before the review gate: %q", i, run)
		}
	}
	if gate < 0 {
		t.Error("the stage job doesn't run the review gate")
	}
}

func lookup(t *testing.T, v config.Value, keys ...string) config.Value {
	t.Helper()
	for _, k := range keys {
		m, ok := v.(*config.Map)
		if !ok {
			t.Fatalf("no %q", k)
		}
		v, _ = m.Get(k)
	}
	return v
}
