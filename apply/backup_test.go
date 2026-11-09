package apply

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Two backups in one second each keep a file, the newest sorts last, and
// retention still keeps the newest ones (1.x replaced the first).
func TestBackupsInOneSecond(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 9, 9, 7, 4, 0, time.UTC)
	n := 0
	run := func(Cmd) (Result, error) {
		n++
		return Result{Stdout: fmt.Sprintf("table inet fr_os { # %d\n}\n", n)}, nil
	}
	var made []string
	for range 4 {
		path, err := backupRunning(run, dir, 3, now)
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, filepath.Base(path))
	}
	want := []string{"ruleset-20261109T090704Z.nft", "ruleset-20261109T090704Z_01.nft",
		"ruleset-20261109T090704Z_02.nft", "ruleset-20261109T090704Z_03.nft"}
	if fmt.Sprint(made) != fmt.Sprint(want) {
		t.Fatalf("backups made: %v, want %v", made, want)
	}
	kept, err := ListBackups(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || filepath.Base(kept[2]) != want[3] {
		t.Fatalf("kept %v, want the newest 3 ending with %s", kept, want[3])
	}
	last, err := os.ReadFile(kept[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(last) != "flush ruleset\n\ntable inet fr_os { # 4\n}\n" {
		t.Fatalf("newest backup holds %q", last)
	}
	// A later second starts again without a suffix and sorts after them.
	path, err := backupRunning(run, dir, 3, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "ruleset-20261109T090705Z.nft" {
		t.Fatalf("next second's backup is %s", path)
	}
	kept, _ = ListBackups(dir)
	if kept[len(kept)-1] != path {
		t.Fatalf("newest backup %s does not sort last in %v", path, kept)
	}
}
