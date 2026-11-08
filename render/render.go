// Package render writes the text of the files an apply writes or hands
// a program: Kea's DHCPv4 config, the ad-block resolver's dnsmasq
// config, dhcpcd's and the Router Advertisement instance's configs, the
// kernel's IPv6 settings, the WireGuard tunnel's `wg syncconf` text,
// sshd's drop-ins and the webUI's OpenSSL fragment.
//
// Each is held to what FR_OS 1.x renders from the same config, byte for
// byte (AGENTS.md, "Differential tests": reference_test.go replays
// testdata/reference/render.jsonl). Nothing here reads or writes a file:
// the apply does, and what a renderer needs from the router's state (the
// generated ULA prefix, the WireGuard key) is handed to it.
package render

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Where 1.x keeps the files the renderers name (frfw.paths).
const (
	AdblockHostsPath   = "/etc/fr_os/adblock.hosts"
	AdblockCategoryDir = "/etc/fr_os/adblock.d"
	DNSQueryLogPath    = "/var/log/fr_os-dns/queries.log"
	// SSHGroup is the group whose members may log in over SSH
	// (security-lessons F3).
	SSHGroup = "fr_os-ssh"
)

// pythonJSON is Python's json.dumps(v, indent=2): two-space indent,
// ": " after a name, and every character outside printable ASCII as a
// \u escape (ensure_ascii), past U+FFFF as a UTF-16 surrogate pair.
// encoding/json/v2 writes the same layout but leaves non-ASCII as it is;
// in its output that can only be inside a string, so it is escaped
// afterwards.
func pythonJSON(v any) (string, error) {
	b, err := json.Marshal(v, jsontext.Multiline(true), jsontext.WithIndent("  "), jsontext.SpaceAfterColon(true))
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		switch {
		case r < 0x7f:
			out.WriteRune(r)
		case r > 0xffff:
			r -= 0x10000
			fmt.Fprintf(&out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		default:
			fmt.Fprintf(&out, `\u%04x`, r)
		}
	}
	return out.String(), nil
}
