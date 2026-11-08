// Command fr-apply-revert is fr-apply-revert.service (ROADMAP SEC-26):
// the apply-helper starts it when an Apply from the webUI is held for
// confirmation; it waits for the deadline and goes back to the config
// applied before, unless the apply is confirmed (or reverted) first
// (1.x's `firewall-cli apply-revert --wait`).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/starsmash29/fr_os-community/helper"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("fr-apply-revert", flag.ContinueOnError)
	s := helper.NewServer()
	flags.StringVar(&s.Env.ConfigPath, "config", s.Env.ConfigPath, "config.yaml")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fr-apply-revert: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	messages, err := s.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-apply-revert: %v\n", err)
		return 1
	}
	for _, m := range messages {
		fmt.Println(m)
	}
	return 0
}
