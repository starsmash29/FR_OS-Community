package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const smallConfig = "version: 1\nhostname: fr-router\nzones: {wan: {}, lan: {}}\n" +
	"interfaces:\n  wan: {device: eth0, zone: wan}\n  lan: {device: eth1, zone: lan, address: 10.0.0.1/24}\n"

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Path.read_text() turns "\r\n" and a lone "\r" into "\n"; the text
	// returned is that one.
	crlf := strings.ReplaceAll(smallConfig, "\n", "\r\n")
	c, text, err := ReadFile(write("crlf.yaml", crlf))
	if err != nil {
		t.Fatal(err)
	}
	if text != smallConfig || c.Hostname != "fr-router" || c.Interfaces.Len() != 2 {
		t.Fatalf("got %q, %+v", text, c)
	}
	if _, _, err := ReadFile(write("cr.yaml", strings.ReplaceAll(smallConfig, "\n", "\r"))); err != nil {
		t.Fatal(err)
	}

	// A YAML error says where, as 1.x's ConfigError does.
	bad := write("bad.yaml", "a: [1\n")
	_, _, err = ReadFile(bad)
	if err == nil || !strings.HasPrefix(err.Error(), "Invalid YAML in "+bad+": while parsing a flow sequence\n") {
		t.Fatalf("got %v", err)
	}

	// A check error is parse_config's.
	_, _, err = ReadFile(write("v2.yaml", strings.Replace(smallConfig, "version: 1", "version: 2", 1)))
	if err == nil || strings.HasPrefix(err.Error(), "Invalid YAML") {
		t.Fatalf("got %v", err)
	}

	// The size limit, and text that isn't UTF-8.
	big := write("big.yaml", smallConfig+"# "+strings.Repeat("x", MaxConfigBytes)+"\n")
	if _, _, err := ReadFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
	if _, _, err := ReadFile(write("latin1.yaml", smallConfig+"# \xe9\n")); err == nil {
		t.Fatal("accepted a text that isn't UTF-8")
	}
	if _, _, err := ReadFile(filepath.Join(dir, "missing.yaml")); !os.IsNotExist(err) {
		t.Fatalf("got %v", err)
	}
}

func TestYAMLLimits(t *testing.T) {
	deep := strings.Repeat("[", 64) + strings.Repeat("]", 64)
	if _, err := LoadYAML(deep); err != nil {
		t.Fatalf("64 levels: %v", err)
	}
	if _, err := LoadYAML("[" + deep + "]"); err == nil {
		t.Fatal("65 levels accepted")
	}
	// Ten levels of ten aliases each: 10**10 nodes from a few lines.
	var b strings.Builder
	b.WriteString("a0: &a0 [x]\n")
	for i := 1; i <= 10; i++ {
		ref := strings.TrimSuffix(strings.Repeat(fmt.Sprintf("*a%d, ", i-1), 10), ", ")
		fmt.Fprintf(&b, "a%d: &a%d [%s]\n", i, i, ref)
	}
	if _, err := LoadYAML(b.String()); err == nil || !strings.Contains(err.Error(), "expand to more than") {
		t.Fatalf("got %v", err)
	}
	if _, err := LoadYAML("a: &x [*x]\n"); err == nil {
		t.Fatal("a recursive alias accepted")
	}
}
