package release_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/release"
)

// The keys this build trusts: release/keys/ is not empty, and every file
// in it is an Ed25519 public key (a broken one would leave a router
// trusting fewer keys than the repository says).
func TestTrustedKeys(t *testing.T) {
	keys := release.TrustedKeys()
	if len(keys) == 0 {
		t.Fatal("release/keys/ has no key: no update could ever verify")
	}
	for _, k := range keys {
		block, _ := pem.Decode(k.Data)
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Errorf("%s is not a PEM public key", k.Name)
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if _, ok := pub.(ed25519.PublicKey); err != nil || !ok {
			t.Errorf("%s is not an Ed25519 key: %v", k.Name, err)
		}
	}
}

// scripts/sign-sums.sh: a test build without the key stays unsigned, a
// release without it fails, and a key whose public half the repository
// doesn't ship signs nothing a router would accept, so it fails too.
func TestSignSums(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("no openssl")
	}
	dir := t.TempDir()
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte("00  x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	foreign := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for _, c := range []struct {
		name, key, tag string
		code           int
		says           string
	}{
		{"a test build", "", "", 0, "stays unsigned"},
		{"a release without the key", "", "v9.9.9", 1, "refusing to publish an unsigned release"},
		{"a key the repository doesn't ship", foreign, "v9.9.9", 1, "is not in release/keys/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command("sh", "../scripts/sign-sums.sh", sums)
			cmd.Env = append(os.Environ(), "SIGNING_KEY="+c.key, "RELEASE_TAG="+c.tag)
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != c.code || !strings.Contains(string(out), c.says) {
				t.Errorf("exit %d, want %d, saying %q:\n%s", code, c.code, c.says, out)
			}
		})
	}
}
