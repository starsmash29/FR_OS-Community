// Command reviewgate says whether an adversarial review of a release is
// on record (security-lessons J2), as 1.x's scripts/check_release_review.py:
// every release is reviewed first by at least two different AI models,
// and the findings are triaged into docs/reviews/v<VERSION>.md (format:
// docs/reviews/TEMPLATE.md). The release workflow runs it before it
// builds anything, and refuses to publish when:
//
//   - the record is missing;
//   - it names fewer than two different models;
//   - the reviewed commit isn't part of the release, or is older than the
//     previous release (the review would be about other code);
//   - a critical or high finding is still open: fixed, accepted (with the
//     reason), not a bug or a duplicate are the ways to close one.
//
// Not installed on the router.
//
//	go run ./release/reviewgate VERSION [-root DIR]
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// closed is how a critical or high finding may end; anything else
// ("open", "reported", "needs verification", "in progress") blocks.
var closed = []string{"fixed", "accepted", "not a bug", "duplicate"}

var blocking = []string{"critical", "high"}

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func main() {
	root := flag.String("root", ".", "the repository")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: reviewgate VERSION [-root DIR]")
		os.Exit(2)
	}
	problems := check(flag.Arg(0), *root)
	for _, p := range problems {
		fmt.Println("::error::" + p)
	}
	if len(problems) > 0 {
		os.Exit(1)
	}
	fmt.Printf("adversarial review for v%s is on record and closed\n", strings.TrimPrefix(flag.Arg(0), "v"))
}

func git(root string, args ...string) (string, bool) {
	out, err := exec.Command("git", append([]string{"-C", root}, args...)...).Output()
	return string(out), err == nil
}

// field is a "- **Name:** value" (or "Name: value") line's value.
func field(text, name string) string {
	re := regexp.MustCompile(`(?im)^\s*[-*]?\s*\**` + regexp.QuoteMeta(name) + `\**\s*:\s*\**\s*(.+?)\s*$`)
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return strings.Trim(m[1], "`* ")
}

// findings are the rows of every markdown table with Severity and
// Status columns, each by its lowercased header.
func findings(text string) []map[string]string {
	var rows []map[string]string
	var header []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			header = nil
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if header == nil {
			lowered := make([]string, len(cells))
			hasSeverity, hasStatus := false, false
			for i, c := range cells {
				lowered[i] = strings.ToLower(c)
				hasSeverity = hasSeverity || lowered[i] == "severity"
				hasStatus = hasStatus || lowered[i] == "status"
			}
			if hasSeverity && hasStatus {
				header = lowered
			}
			continue
		}
		if strings.Trim(strings.Join(cells, ""), "-: ") == "" {
			continue // the |---|---| line
		}
		row := map[string]string{}
		for i := 0; i < len(header) && i < len(cells); i++ {
			row[header[i]] = cells[i]
		}
		rows = append(rows, row)
	}
	return rows
}

func parse(m []string) [3]int {
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// previousRelease is the newest v* tag older than version.
func previousRelease(root string, version [3]int) string {
	out, _ := git(root, "tag", "-l", "v*")
	best, found := "", [3]int{}
	for _, tag := range strings.Fields(out) {
		m := versionRE.FindStringSubmatch(tag)
		if m == nil {
			continue
		}
		v := parse(m)
		if less(v, version) && (best == "" || less(found, v)) {
			best, found = tag, v
		}
	}
	return best
}

func check(version, root string) []string {
	m := versionRE.FindStringSubmatch(version)
	if m == nil {
		return []string{fmt.Sprintf("not a version: %q", version)}
	}
	plain := m[1] + "." + m[2] + "." + m[3]
	rel := filepath.Join("docs", "reviews", "v"+plain+".md")
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return []string{"no adversarial review on record: " + rel + " is missing (docs/RELEASING.md, 'Before tagging')"}
	}
	text := string(data)
	var problems []string

	models := map[string]bool{}
	for _, s := range regexp.MustCompile(`[,;]`).Split(field(text, "Models"), -1) {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			models[s] = true
		}
	}
	if len(models) < 2 {
		problems = append(problems, `the record must name at least two different models ("Models: a, b")`)
	}

	commit := field(text, "Reviewed commit")
	switch {
	case commit == "":
		problems = append(problems, `the record must say which commit was reviewed ("Reviewed commit: <sha>")`)
	default:
		if _, ok := git(root, "cat-file", "-e", commit+"^{commit}"); !ok {
			problems = append(problems, "reviewed commit "+commit+" doesn't exist in this repository")
			break
		}
		if _, ok := git(root, "merge-base", "--is-ancestor", commit, "HEAD"); !ok {
			problems = append(problems, "reviewed commit "+commit+" is not part of this release (not an ancestor of HEAD)")
		}
		if previous := previousRelease(root, parse(m)); previous != "" {
			if _, ok := git(root, "merge-base", "--is-ancestor", commit, previous); ok {
				problems = append(problems, "reviewed commit "+commit+" is from before the previous release "+previous)
			}
		}
	}

	if !regexp.MustCompile(`(?im)\|\s*severity\s*\|`).MatchString(text) {
		problems = append(problems, "the record needs a findings table with Severity and Status columns "+
			"(an empty table if the reviews found nothing)")
	}
	for _, row := range findings(text) {
		severity, status := strings.ToLower(row["severity"]), strings.ToLower(row["status"])
		isBlocking, isClosed := false, false
		for _, b := range blocking {
			isBlocking = isBlocking || strings.Contains(severity, b)
		}
		for _, c := range closed {
			isClosed = isClosed || strings.HasPrefix(status, c)
		}
		if isBlocking && !isClosed {
			id, ok := row["id"]
			if !ok {
				id = "?"
			}
			finding, shown := []rune(row["finding"]), row["status"]
			if len(finding) > 80 {
				finding = finding[:80]
			}
			if shown == "" {
				shown = "none"
			}
			problems = append(problems, fmt.Sprintf("open %s finding %s: %s (status: %s)", severity, id, string(finding), shown))
		}
	}
	return problems
}
