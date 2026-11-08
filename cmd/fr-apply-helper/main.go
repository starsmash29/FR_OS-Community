// Command fr-apply-helper is FR_OS's root apply-helper (package helper):
// the one process the webUI and the parser daemons ask for privileged
// work, over /run/fr_os/apply.sock. systemd starts it by socket
// activation (systemd/fr-apply-helper.socket); run by hand, it binds the
// socket itself.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/starsmash29/fr_os-community/helper"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("fr-apply-helper", flag.ContinueOnError)
	socket := flags.String("socket", helper.SocketPath, "the socket to bind when systemd passes none")
	s := helper.NewServer()
	flags.StringVar(&s.Env.ConfigPath, "config", s.Env.ConfigPath, "config.yaml")
	flags.StringVar(&s.Env.BackupDir, "backup-dir", s.Env.BackupDir, "where applied configs are kept")
	flags.StringVar(&s.Env.KeaConfigPath, "kea-config", s.Env.KeaConfigPath, "Kea's DHCPv4 config")
	flags.StringVar(&s.Env.ZtnaStatePath, "ztna-state", s.Env.ZtnaStatePath, "who authorized which ZTNA client")
	flags.StringVar(&s.Env.AdblockHostsPath, "adblock-hosts", s.Env.AdblockHostsPath, "the ad-block list")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "fr-apply-helper: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	l, err := helper.Listen(*socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr-apply-helper: %v\n", err)
		return 1
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		l.Close() // Serve returns once the requests already running are done
	}()
	if err := s.Serve(l); err != nil {
		fmt.Fprintf(os.Stderr, "fr-apply-helper: %v\n", err)
		return 1
	}
	return 0
}
