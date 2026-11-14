package helper

import "testing"

// firewall-cli reads its command line as argparse does: options
// anywhere, "--opt=value", any unambiguous prefix, "--" before a
// positional; what argparse refuses is refused.
func TestParseCLI(t *testing.T) {
	const def = "/etc/fr_os/config.yaml"
	for _, tc := range []struct {
		args    []string
		config  string
		flags   []string
		within  int64
		refused bool
	}{
		{args: []string{"apply"}, config: def},
		{args: []string{"apply", "--fail-closed", "/x.yaml"}, config: "/x.yaml", flags: []string{"--fail-closed"}},
		{args: []string{"apply", "/x.yaml", "--dry"}, config: "/x.yaml", flags: []string{"--dry-run"}},
		{args: []string{"apply", "--confirm-within=120"}, config: def, within: 120},
		{args: []string{"apply", "--confirm-within", " 90 "}, config: def, within: 90},
		{args: []string{"apply", "--", "-odd.yaml"}, config: "-odd.yaml"},
		{args: []string{"adblock-refresh", "--scheduled"}, config: def, flags: []string{"--scheduled"}},
		{args: nil, refused: true},
		{args: []string{"bogus"}, refused: true},
		{args: []string{"apply", "--confirm-within"}, refused: true},
		{args: []string{"apply", "--confirm-within", "x"}, refused: true},
		{args: []string{"apply", "--dry-run=yes"}, refused: true},
		{args: []string{"apply", "a", "b"}, refused: true},
		{args: []string{"dns-log-trim", "x"}, refused: true},
		{args: []string{"validate", "--dry-run"}, refused: true},
	} {
		a, err := parseCLI(tc.args, def)
		if tc.refused {
			if err == nil {
				t.Errorf("%q: not refused", tc.args)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.args, err)
			continue
		}
		if a.config != tc.config {
			t.Errorf("%q: config %q, want %q", tc.args, a.config, tc.config)
		}
		for _, f := range tc.flags {
			if !a.flags[f] {
				t.Errorf("%q: %s not set", tc.args, f)
			}
		}
		if n := a.numbers["--confirm-within"]; (n == nil) != (tc.within == 0) || (n != nil && *n != tc.within) {
			t.Errorf("%q: --confirm-within %v, want %d", tc.args, n, tc.within)
		}
	}
}
