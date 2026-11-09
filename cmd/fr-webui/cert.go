package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/starsmash29/fr_os-community/config"
)

// autoCertCN is the common name of the certificate fr-webui makes.
const autoCertCN = "fr-router"

// ensureSelfSignedCert makes a self-signed certificate and key unless
// both exist (or replaces 1.x's own pre-phase-20 certificate, see
// isLegacyAutoCert); true when it made a new pair. 1.x ran
// `openssl req -x509 -newkey rsa:2048 -days 3650`; this makes the same
// kind of certificate with crypto/x509 (decisions.md). Its
// subjectAltName carries the common name, dnsNames and ips, because
// clients verify the SAN, not the CN: a Prometheus server scraping
// another site's /metrics with verification (phase 20) checks it.
func ensureSelfSignedCert(certPath, keyPath string, dnsNames, ips []string) (bool, error) {
	if isFile(certPath) && isFile(keyPath) && !isLegacyAutoCert(certPath) {
		return false, nil
	}
	for _, dir := range []string{filepath.Dir(certPath), filepath.Dir(keyPath)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, err
		}
	}
	// Security-lessons F1: only valid names and IPv4 addresses go in.
	names := []string{autoCertCN}
	for _, n := range dnsNames {
		if config.CheckHostname(n) == nil && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	var addrs []net.IP
	for _, a := range ips {
		if p, err := config.ParsePyIPv4(a); err == nil {
			ip := net.ParseIP(p.String())
			if !slices.ContainsFunc(addrs, ip.Equal) {
				addrs = append(addrs, ip)
			}
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return false, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: autoCertCN},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, 3650),
		DNSNames:              names,
		IPAddresses:           addrs,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return false, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return false, err
	}
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return false, err
	}
	if err := writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// isLegacyAutoCert is a certificate 1.x made before phase 20:
// self-signed with CN=fr-router and no subjectAltName, which modern
// clients can't verify (Go ignores the CN since 1.15). It is replaced
// once; any other certificate (an admin's own) is never touched.
func isLegacyAutoCert(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) {
			return false
		}
	}
	return cert.Subject.CommonName == autoCertCN && cert.Issuer.CommonName == autoCertCN
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("installing %s: %w", path, err)
	}
	return nil
}
