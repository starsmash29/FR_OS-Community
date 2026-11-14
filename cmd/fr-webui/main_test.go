package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/starsmash29/fr_os-community/apply"
)

func TestRecordedListenIsReadAs1xReadsIt(t *testing.T) {
	dir := t.TempDir()
	for text, want := range map[string][]string{
		`{"addresses": ["127.0.0.1", "192.168.1.1"]}`: {"127.0.0.1", "192.168.1.1"},
		`{"addresses": ["FD00:0:0:0::1"]}`:            {"fd00::1"},
		`{"addresses": [3232235777]}`:                 {"192.168.1.1"}, // ip_address takes an int
		`{"addresses": []}`:                           nil,
		`{"addresses": ["192.168.1.300"]}`:            nil,
		`{"addresses": "127.0.0.1"}`:                  nil,
		`["127.0.0.1"]`:                               nil,
		`{}`:                                          nil,
		`not json`:                                    nil,
	} {
		path := filepath.Join(dir, "listen.json")
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := apply.RecordedWebUIListen(path); !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", text, got, want)
		}
	}
	if got := apply.RecordedWebUIListen(filepath.Join(dir, "none.json")); got != nil {
		t.Errorf("no record: %q", got)
	}
}

func TestWithoutAConfigOnlyLoopbackListens(t *testing.T) {
	if got := listenAddresses(nil, filepath.Join(t.TempDir(), "none.json")); !slices.Equal(got, []string{"127.0.0.1"}) {
		t.Errorf("%q", got)
	}
}

func TestTheSelfSignedCertificateNamesTheRouter(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	made, err := ensureSelfSignedCert(cert, key, []string{"gw", "bad,name", "gw"},
		[]string{"192.168.1.1", "not-an-ip", "fd00::1", "192.168.1.1"})
	if err != nil || !made {
		t.Fatalf("made %v, %v", made, err)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "fr-router" || !slices.Equal(c.DNSNames, []string{"fr-router", "gw"}) ||
		len(c.IPAddresses) != 1 || !c.IPAddresses[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("CN %q, DNS %q, IPs %v", c.Subject.CommonName, c.DNSNames, c.IPAddresses)
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", fi.Mode().Perm())
	}
	// An existing pair is kept.
	if made, err := ensureSelfSignedCert(cert, key, nil, nil); made || err != nil {
		t.Errorf("remade: %v, %v", made, err)
	}
}

// writeCert writes a self-signed certificate with cn and dnsNames.
func writeCert(t *testing.T, path, cn string, dnsNames []string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: dnsNames}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyThe1xAutoCertificateIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	writeCert(t, path, "fr-router", nil)
	if !isLegacyAutoCert(path) {
		t.Error("1.x's certificate without a subjectAltName is not replaced")
	}
	writeCert(t, path, "fr-router", []string{"fr-router"})
	if isLegacyAutoCert(path) {
		t.Error("a certificate with a subjectAltName would be replaced")
	}
	writeCert(t, path, "router.example.com", nil)
	if isLegacyAutoCert(path) {
		t.Error("an admin's own certificate would be replaced")
	}
}

func TestAnAddressNotYetOnTheHostCanBeBound(t *testing.T) {
	// IP_FREEBIND: 192.0.2.1 (TEST-NET-1) is on no interface here.
	ls, err := bind([]string{"127.0.0.1", "192.0.2.1"}, 0)
	if err != nil {
		t.Skipf("binding: %v", err)
	}
	for _, l := range ls {
		l.Close()
	}
	if len(ls) != 2 {
		t.Fatalf("%d listeners", len(ls))
	}
	_ = strconv.Itoa
}
