package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/starsmash29/fr_os-community/config"
	"github.com/starsmash29/fr_os-community/nft"
)

// Where the previous rulesets are kept, and how many (frfw.paths).
const (
	BackupDir       = "/etc/fr_os/backups"
	BackupRetention = 10
)

// NftError is nft refusing a ruleset or failing to load it.
type NftError struct{ Msg string }

func (e *NftError) Error() string { return e.Msg }

// nftEnv is TZ=UTC for every load and listing: nft converts `meta hour`
// between its text and the kernel's UTC value in its own zone, the
// builder writes schedules in UTC already, and a backup listed and later
// restored must round-trip through the same zone.
var nftEnv = []string{"TZ=UTC"}

func runNft(run Runner, stdin string, args ...string) (Result, error) {
	res, err := run(Cmd{Argv: NftArgv(args...), Stdin: stdin, Env: nftEnv})
	if errors.Is(err, ErrNotFound) {
		return Result{}, &NftError{"'nft' binary not found; install the nftables package"}
	}
	if err != nil {
		return Result{}, err
	}
	if res.Code != 0 {
		if msg := config.PyStrip(res.Stderr); msg != "" {
			return res, &NftError{msg}
		}
		return res, &NftError{fmt.Sprintf("nft exited with status %d", res.Code)}
	}
	return res, nil
}

// CheckSyntax checks ruleset with `nft -c`, changing nothing in the
// kernel: its syntax and every set and chain it refers to.
func CheckSyntax(run Runner, ruleset string) error {
	_, err := runNft(run, ruleset, "-c", "-f", "-")
	return err
}

// CaptureRuleset is the ruleset loaded now (`nft list ruleset`).
func CaptureRuleset(run Runner) (string, error) {
	res, err := runNft(run, "", "list", "ruleset")
	return res.Stdout, err
}

// geteuid is os.Geteuid; the replay of 1.x's applies answers 0.
var geteuid = os.Geteuid

func requireRoot() error {
	if geteuid() != 0 {
		return &NftError{"This operation requires root privileges (got syntax-checked OK, but not loaded). " +
			"Re-run as root, or use --dry-run."}
	}
	return nil
}

// ApplyRuleset checks ruleset and, unless dryRun, loads it after backing
// up the one running (frfw.apply.apply_ruleset). The check comes first,
// so a bad ruleset never replaces part of the running one; the load
// (`nft -f`) is one kernel transaction. It returns the message the apply
// reports and the backup's path ("" when nothing was loaded before).
func ApplyRuleset(run Runner, ruleset string, dryRun bool, backupDir string, retention int, now time.Time) (string, string, error) {
	if err := CheckSyntax(run, ruleset); err != nil {
		return "", "", err
	}
	if dryRun {
		return "Syntax OK (dry-run, not applied)", "", nil
	}
	if err := requireRoot(); err != nil {
		return "", "", err
	}
	backup, err := backupRunning(run, backupDir, retention, now)
	if err != nil {
		return "", "", err
	}
	if _, err := runNft(run, ruleset, "-f", "-"); err != nil {
		return "", backup, err
	}
	message := "Ruleset applied"
	if backup != "" {
		message += " (previous ruleset backed up to " + backup + ")"
	}
	return message, backup, nil
}

// backupRunning writes the running ruleset to backupDir, with `flush
// ruleset` first: a listing has none, and loaded as it is it would merge
// into whatever runs then instead of replacing it. Only the newest
// retention backups are kept.
func backupRunning(run Runner, backupDir string, retention int, now time.Time) (string, error) {
	current, err := CaptureRuleset(run)
	if err != nil {
		return "", err
	}
	if config.PyStrip(current) == "" {
		return "", nil // nothing loaded yet
	}
	if err := os.MkdirAll(backupDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(backupDir, "ruleset-"+now.UTC().Format("20060102T150405Z")+".nft")
	if err := os.WriteFile(path, []byte("flush ruleset\n\n"+current), 0o644); err != nil {
		return "", err
	}
	backups, err := ListBackups(backupDir)
	if err != nil {
		return "", err
	}
	for _, old := range backups[:max(len(backups)-retention, 0)] {
		if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return path, nil
}

// ListBackups are the ruleset backups, oldest first.
func ListBackups(backupDir string) ([]string, error) {
	if st, err := os.Stat(backupDir); err != nil || !st.IsDir() {
		return nil, nil
	}
	found, err := filepath.Glob(filepath.Join(globEscape(backupDir), "ruleset-*.nft"))
	if err != nil {
		return nil, err
	}
	slices.Sort(found)
	return found, nil
}

func globEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(s)
}

// RollbackLast loads the newest backup and returns its path.
func RollbackLast(run Runner, backupDir string) (string, error) {
	if err := requireRoot(); err != nil {
		return "", err
	}
	backups, err := ListBackups(backupDir)
	if err != nil {
		return "", err
	}
	if len(backups) == 0 {
		return "", &NftError{"No ruleset backups found in " + backupDir}
	}
	latest := backups[len(backups)-1]
	_, err = runNft(run, "", "-f", latest)
	return latest, err
}

// BaselineRuleset is what the router enforces with no usable config:
// nothing in but loopback, replies to connections the router opened and
// the IPv6 neighbour discovery those need; nothing forwarded. Loaded at
// boot when config.yaml is missing, or when an apply fails and no FR_OS
// ruleset is loaded yet; never over a working one.
var BaselineRuleset = `flush ruleset

table inet ` + nft.Table + ` {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
`

// TableLoaded reports whether an FR_OS ruleset (the real one or the
// baseline) is in the kernel now.
func TableLoaded(run Runner) bool {
	_, err := runNft(run, "", "list", "table", "inet", nft.Table)
	return err == nil
}

// LoadBaseline loads BaselineRuleset over whatever is loaded.
func LoadBaseline(run Runner) error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := runNft(run, BaselineRuleset, "-f", "-")
	return err
}

// LoadCaptured puts back a ruleset CaptureRuleset read, as a whole
// replacement, set members with the time they had left (nft reads its
// own `expires`): an apply's rollback when no config was recorded as
// applied before it (ROADMAP SEC-5).
func LoadCaptured(run Runner, listing string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	_, err := runNft(run, "flush ruleset\n\n"+listing, "-f", "-")
	return err
}
