// Command fr-update-helper is FR_OS's root update-helper (package
// helper, UpdateServer): the root side of the webUI's Update screen --
// installing and rolling back a signed release, and the kernel's --
// over /run/fr_os/update.sock, for root and fr_os-webui only. systemd
// starts it by socket activation (systemd/fr-update-helper.socket); run
// by hand, it binds the socket itself.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/starsmash29/fr_os-community/apply"
	"github.com/starsmash29/fr_os-community/helper"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("fr-update-helper", flag.ContinueOnError)
	socket := flags.String("socket", helper.UpdateSocketPath, "the socket to bind when systemd passes none")
	repo := flags.String("repo", apply.DefaultUpdateRepo, "the GitHub repository releases are installed from")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fr-update-helper: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	u := helper.NewUpdateServer()
	u.Repo = *repo
	l, err := helper.Listen(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-update-helper: %v\n", err)
		return 1
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		l.Close()
	}()
	if err := u.Serve(l); err != nil {
		fmt.Fprintf(os.Stderr, "fr-update-helper: %v\n", err)
		return 1
	}
	return 0
}
