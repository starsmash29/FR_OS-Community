// Package version is the release a build of FR_OS is, and its codename.
package version

import (
	"regexp"
	"strings"

	"github.com/starsmash29/fr_os-community/config"
)

// Version is this build's release. installer/build-binaries.sh sets it
// from the repository's VERSION file
// (-ldflags "-X github.com/starsmash29/fr_os-community/version.Version=...");
// a binary built any other way is a development build.
var Version = "0.0.0-dev"

// codenamesByMajor are the release codenames (1.x's
// frfw._CODENAMES_BY_MAJOR).
var codenamesByMajor = map[string]string{"0": "Ice Breaker", "1": "Idun", "2": "Ivar", "3": "Inari", "4": "Ingemar"}

var releaseRE = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// Codename is frfw.codename_for: the codename of a release version, ""
// for an unparsable one or a major version without a name. 0.1.0 up to
// 1.0.0 included is Ice Breaker.
func Codename(v string) string {
	m := releaseRE.FindStringSubmatch(config.PyStrip(v))
	if m == nil {
		return ""
	}
	major, minor, patch := trimZeros(m[1]), trimZeros(m[2]), trimZeros(m[3])
	if major == "1" && minor == "0" && patch == "0" {
		return codenamesByMajor["0"]
	}
	return codenamesByMajor[major]
}

// WithCodename is the version with its codename in quotes, as 1.x shows
// it (the webUI's with_codename filter, `firewall-cli --version`).
func WithCodename(v string) string {
	if name := Codename(v); name != "" {
		return v + " “" + name + "”"
	}
	return v
}

func trimZeros(digits string) string {
	digits = strings.TrimLeft(digits, "0")
	if digits == "" {
		return "0"
	}
	return digits
}
