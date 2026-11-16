// Command verify checks a SHA256SUMS signature with the keys this build
// of FR_OS trusts (release.TrustedKeys), as a router's updater will, and
// every file the list names that is next to it: scripts/sign-sums.sh
// runs it in CI, so a release that every router would refuse is never
// published. Not installed on the router.
//
//	go run ./release/verify DIR/SHA256SUMS
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/starsmash29/fr_os-community/release"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: verify DIR/SHA256SUMS")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(sumsPath string) error {
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(sumsPath + ".sig")
	if err != nil {
		return err
	}
	dir := filepath.Dir(sumsPath)
	checked := 0
	var key release.Key
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		key, err = release.VerifyRelease(f, sums, signature, name, nil)
		f.Close()
		if err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("%s lists no file", sumsPath)
	}
	fmt.Printf("%s signed by %s; %d file(s) match it\n", sumsPath, key.Name, checked)
	return nil
}
