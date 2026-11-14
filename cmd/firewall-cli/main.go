// Command firewall-cli is the router's own command line (1.x's
// frfw.cli), run as root by its units: the boot's apply in fail-closed
// mode (fr-firewall.service), fr-accounts.service, the hourly schedule
// check, the DNS query log trim and the daily ad-block refresh; and by
// the admin on the console (validate, render, apply).
//
//	firewall-cli validate [CONFIG]
//	firewall-cli render [CONFIG]
//	firewall-cli apply [CONFIG] [--dry-run] [--fail-closed] [--confirm-within SECONDS]
//	firewall-cli schedule-check [CONFIG]
//	firewall-cli dns-log-trim
//	firewall-cli adblock-refresh [CONFIG] [--scheduled]
//	firewall-cli ensure-accounts
package main

import (
	"os"

	"github.com/starsmash29/fr_os-community/helper"
)

func main() {
	s := helper.NewServer()
	os.Exit(s.CLI(os.Args[1:], os.Stdout, os.Stderr))
}
