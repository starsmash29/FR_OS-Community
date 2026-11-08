package apply

import (
	"fmt"
	"net/netip"
	"regexp"

	"github.com/starsmash29/fr_os-community/config"
)

// The values an apply puts on a command line, checked once more where
// they are used (frfw.validate, security-lessons F1): the config package
// has checked them, and these keep a value that would read as an option
// or a second argument off the command line whatever its source.
var (
	ifnameRE = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\z`)
	unitRE   = regexp.MustCompile(`\A[A-Za-z0-9][A-Za-z0-9:_.@-]{0,254}\z`)
)

// systemctlActions are the verbs FR_OS uses.
var systemctlActions = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true, "try-restart": true,
	"try-reload-or-restart": true, "reload-or-restart": true, "enable": true, "disable": true,
	"is-active": true, "is-enabled": true,
}

// ArgumentError is a value refused before it could reach a command line.
type ArgumentError struct{ Msg string }

func (e *ArgumentError) Error() string { return e.Msg }

func refused(format string, v string) error {
	return &ArgumentError{fmt.Sprintf(format, config.Repr(v))}
}

// Ifname is a Linux interface name: 1-15 characters of letters, digits
// and `_.-`, starting with a letter or digit (never an option), not `.`
// or `..`.
func Ifname(v string) (string, error) {
	if !ifnameRE.MatchString(v) || v == "." || v == ".." {
		return "", refused("invalid interface name %s", v)
	}
	return v, nil
}

// SystemdUnit is a unit name.
func SystemdUnit(v string) (string, error) {
	if !unitRE.MatchString(v) {
		return "", refused("invalid systemd unit name %s", v)
	}
	return v, nil
}

// SystemctlAction is one of the verbs FR_OS uses.
func SystemctlAction(v string) (string, error) {
	if !systemctlActions[v] {
		return "", refused("systemctl action %s is not one frfw uses", v)
	}
	return v, nil
}

// IPv4Interface is an address with its prefix length in its canonical
// text, e.g. 192.168.1.1/24.
func IPv4Interface(v string) (string, error) {
	p, err := netip.ParsePrefix(v)
	if err != nil || !p.Addr().Is4() || p.String() != v {
		return "", refused("invalid IPv4 address/prefix %s", v)
	}
	return v, nil
}

// NftArgv is nft's argv with `--` between FR_OS's own leading options
// (`-j`, `-c`, `-f FILE`) and everything else, so no later value can be
// read as an option (frfw.validate.nft_argv).
func NftArgv(args ...string) []string {
	var options []string
	rest := args
	for len(rest) > 0 && len(rest[0]) > 0 && rest[0][0] == '-' && rest[0] != "-" {
		options = append(options, rest[0])
		rest = rest[1:]
		if options[len(options)-1] == "-f" && len(rest) > 0 {
			options = append(options, rest[0])
			rest = rest[1:]
		}
	}
	argv := append([]string{"nft"}, options...)
	if len(rest) > 0 {
		argv = append(append(argv, "--"), rest...)
	}
	return argv
}
