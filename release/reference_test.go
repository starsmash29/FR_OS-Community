package release_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/starsmash29/fr_os-community/internal/reference"
	"github.com/starsmash29/fr_os-community/release"
)

// TestReferenceRelease holds the release check to 1.x's
// frfw.release_signing: which trusted key verifies a signature (keys
// of every shape, signatures damaged at random), the checksum
// SHA256SUMS lists for a name, and whole releases, with 1.x's error
// texts (but for the keys' directory: decisions.md, "phase 4f-4a").
func TestReferenceRelease(t *testing.T) {
	cases, err := reference.ReleaseCases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no release cases")
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			var keys []release.Key
			for n, k := range c.Keys {
				keys = append(keys, release.Key{Name: fmt.Sprintf("k%d.pem", n), Data: unhex(t, k)})
			}
			var got string
			switch c.Op {
			case "signature":
				key, err := release.VerifySignature(release.SumsName, unhex(t, c.Data), unhex(t, c.Signature), keys)
				got = outcome(key, err)
			case "release":
				key, err := release.VerifyRelease(bytes.NewReader(unhex(t, c.Tarball)), unhex(t, c.Data),
					unhex(t, c.Signature), c.Name, keys)
				got = outcome(key, err)
			case "expected":
				digest, err := release.ExpectedSHA256(c.Text, c.Name)
				if err != nil {
					got = outcome(release.Key{}, err)
				} else {
					got = "digest " + digest
				}
			default:
				t.Fatalf("unknown op %q", c.Op)
			}
			if want := wanted(c); got != want {
				t.Errorf("got  %s\nwant %s", got, want)
			}
		})
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func outcome(key release.Key, err error) string {
	var se *release.SignatureError
	switch {
	case errors.As(err, &se):
		return "error " + se.Msg
	case errors.Is(err, release.ErrNotText):
		return "raised UnicodeDecodeError"
	case err != nil:
		return "raised " + err.Error()
	}
	return "key " + key.Name
}

func wanted(c reference.ReleaseCase) string {
	switch {
	case c.Digest != nil:
		return "digest " + *c.Digest
	case c.Key != nil:
		return "key " + *c.Key
	case c.Error != nil:
		return "error " + strings.Replace(*c.Error, "frfw/release_keys/", "release/keys/", 1)
	case c.Raised != nil:
		return "raised " + *c.Raised
	}
	return "nothing"
}
