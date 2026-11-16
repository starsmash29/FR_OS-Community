package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Without a signature from a trusted key nothing verifies, whatever the
// files: CI never publishes what a router refuses.
func TestRunRefuses(t *testing.T) {
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("x", "x")
	write("SHA256SUMS", "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881  x\n")
	if err := run(sums); err == nil || !strings.Contains(err.Error(), "SHA256SUMS.sig") {
		t.Errorf("no signature file: %v", err)
	}
	write("SHA256SUMS.sig", strings.Repeat("\x00", 64))
	if err := run(sums); err == nil || !strings.Contains(err.Error(), "matches none of the") {
		t.Errorf("a signature from no trusted key: %v", err)
	}
	write("SHA256SUMS", "# nothing\n")
	if err := run(sums); err == nil || !strings.Contains(err.Error(), "lists no file") {
		t.Errorf("an empty list: %v", err)
	}
}
