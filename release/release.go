// Package release checks that a release really comes from FR_OS's
// maintainers (1.x's frfw.release_signing). An update replaces the
// router's programs and units as root, so nothing from a release is
// used before it verifies. Every release publishes, next to the ISO:
//
//   - fr_os-<version>-amd64.tar.gz: the programs, the XDP object, the
//     scripts and the units, as installer/build-binaries.sh stages them;
//   - SHA256SUMS: sha256sum's list of the tarball and the ISO;
//   - SHA256SUMS.sig: an Ed25519 signature over SHA256SUMS, made in CI
//     with the private key held as the FROS_RELEASE_SIGNING_KEY secret of
//     the repository's `release` environment (docs/RELEASING.md).
//
// The public keys this build trusts are the PEM files of keys/, compiled
// into the binary: on the router there is no file to add a key to. A
// signature from no trusted key, a missing or mismatching checksum, is
// refused (security-lessons G3).
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/starsmash29/fr_os-community/config"
)

// SumsName and SignatureName are the checksum list and its signature.
const (
	SumsName      = "SHA256SUMS"
	SignatureName = "SHA256SUMS.sig"
)

//go:embed keys/*.pem
var keysFS embed.FS

// Key is one trusted public key, as a PEM (or DER) file holds it.
type Key struct {
	Name string
	Data []byte
}

// TrustedKeys are the keys this build accepts release signatures from,
// in their names' order (1.x: sorted(release_keys/*.pem)).
func TrustedKeys() []Key {
	entries, err := keysFS.ReadDir("keys")
	if err != nil {
		return nil
	}
	var keys []Key
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".pem" {
			continue
		}
		data, err := keysFS.ReadFile("keys/" + e.Name())
		if err != nil {
			continue
		}
		keys = append(keys, Key{e.Name(), data})
	}
	slices.SortFunc(keys, func(a, b Key) int { return strings.Compare(a.Name, b.Name) })
	return keys
}

// SignatureError is a release that failed verification: nothing from it
// may be used.
type SignatureError struct{ Msg string }

func (e *SignatureError) Error() string { return e.Msg }

// ErrNotText is SHA256SUMS that isn't UTF-8 (1.x: read_text's
// UnicodeDecodeError, which isn't a SignatureError and goes through).
var ErrNotText = errors.New("SHA256SUMS is not UTF-8 text")

// TarballName is a release's tarball for version ("v" or not).
func TarballName(version string) string {
	return "fr_os-" + strings.TrimPrefix(version, "v") + "-amd64.tar.gz"
}

// publicKey is the Ed25519 key a file holds, as `openssl pkeyutl
// -pubin -inkey` reads it: the first PEM block (text before it
// skipped), or the whole file as DER; nil for anything else (a private
// key, a key of another kind, garbage).
func publicKey(data []byte) ed25519.PublicKey {
	der := data
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil
		}
		der = block.Bytes
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil
	}
	k, _ := key.(ed25519.PublicKey)
	return k
}

// VerifySignature is verify_signature: the key that signed data (named
// name in the error), or a SignatureError. OpenSSL signs and checks
// nothing for empty data, so 1.x accepts no signature over it.
func VerifySignature(name string, data, signature []byte, keys []Key) (Key, error) {
	if len(keys) == 0 {
		return Key{}, &SignatureError{"this build trusts no release signing key (release/keys/ is empty), " +
			"so it can't verify any update -- see docs/RELEASING.md"}
	}
	for _, key := range keys {
		pub := publicKey(key.Data)
		if pub != nil && len(data) > 0 && ed25519.Verify(pub, data, signature) {
			return key, nil
		}
	}
	return Key{}, &SignatureError{name + ": the signature matches none of the " + strconv.Itoa(len(keys)) +
		" trusted key(s)"}
}

// ExpectedSHA256 is expected_sha256: the checksum SHA256SUMS's text
// lists for name, in sha256sum's format (`#` lines are comments; the
// first line naming it counts).
func ExpectedSHA256(text, name string) (string, error) {
	for _, line := range config.PySplitlines(text) {
		if config.PyStrip(line) == "" || strings.HasPrefix(config.PyLstrip(line), "#") {
			continue
		}
		digest, listed, _ := strings.Cut(config.PyStrip(line), " ")
		if strings.TrimLeft(listed, " *") == name {
			return config.PyLower(digest), nil
		}
	}
	return "", &SignatureError{SumsName + " lists no checksum for " + name}
}

// SHA256Of is sha256_of: tarball's checksum, in hex.
func SHA256Of(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyRelease is verify_release: the signature over sums first, then
// the tarball (named name in SHA256SUMS) against it. It returns the key
// that signed; keys nil means TrustedKeys.
func VerifyRelease(tarball io.Reader, sums, signature []byte, name string, keys []Key) (Key, error) {
	if keys == nil {
		keys = TrustedKeys()
	}
	key, err := VerifySignature(SumsName, sums, signature, keys)
	if err != nil {
		return Key{}, err
	}
	if !utf8.Valid(sums) {
		return Key{}, ErrNotText
	}
	want, err := ExpectedSHA256(string(sums), name)
	if err != nil {
		return Key{}, err
	}
	got, err := SHA256Of(tarball)
	if err != nil {
		return Key{}, err
	}
	if got != want {
		return Key{}, &SignatureError{fmt.Sprintf("%s: sha256 %s does not match the signed %s (%s)", name, got,
			SumsName, want)}
	}
	return key, nil
}
