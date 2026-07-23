// SPDX-License-Identifier: GPL-3.0-or-later

// Package tlsutil provides helpers for serving the control-plane API over TLS.
//
// Public ACME certificate authorities cannot issue certificates for private-LAN
// names (the appliance's typical deployment), so this package supports serving
// TLS from an operator-provided cert/key pair or from a self-signed certificate
// that is generated once and persisted on first boot.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultValidity is how long a generated self-signed certificate is valid.
	// Appliances are long-lived and self-managed, so a long window avoids forcing
	// re-provisioning of trust on the LAN.
	DefaultValidity = 10 * 365 * 24 * time.Hour

	certFileName = "self-signed.crt"
	keyFileName  = "self-signed.key"
)

// GenerateSelfSigned creates a self-signed certificate and private key valid for
// the supplied hosts (DNS names and/or IP addresses). It returns PEM-encoded
// certificate and key bytes that load via tls.X509KeyPair. When hosts is empty,
// loopback names are used. A non-positive validFor falls back to DefaultValidity.
func GenerateSelfSigned(hosts []string, validFor time.Duration) (certPEM, keyPEM []byte, err error) {
	if validFor <= 0 {
		validFor = DefaultValidity
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"HydraDNS"},
			CommonName:   "HydraDNS Control Plane",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Self-signed leaf that operators may also import as a trust anchor.
		IsCA: true,
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// EnsureSelfSigned returns the certificate and key file paths within dir,
// generating and persisting a new self-signed pair on first boot if either file
// is missing. Subsequent calls reuse the persisted pair so the certificate is
// stable across restarts.
func EnsureSelfSigned(dir string, hosts []string) (certFile, keyFile string, err error) {
	if dir == "" {
		return "", "", fmt.Errorf("self-signed cert directory is empty")
	}
	certFile = filepath.Join(dir, certFileName)
	keyFile = filepath.Join(dir, keyFileName)

	if fileExists(certFile) && fileExists(keyFile) {
		return certFile, keyFile, nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", fmt.Errorf("create cert directory: %w", err)
	}

	certPEM, keyPEM, err := GenerateSelfSigned(hosts, DefaultValidity)
	if err != nil {
		return "", "", err
	}

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return "", "", fmt.Errorf("write certificate: %w", err)
	}
	// The private key is written with restrictive permissions.
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write private key: %w", err)
	}

	return certFile, keyFile, nil
}

// HostsForListenAddr derives the SAN host list for a self-signed certificate
// from a listen address such as "0.0.0.0:8080" or "192.168.1.10:8080". Loopback
// names are always included; a specific bind host is appended, while bind-all
// hosts (0.0.0.0, ::) contribute nothing beyond loopback.
func HostsForListenAddr(listenAddr string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		host = listenAddr
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		// bind-all: loopback SANs are sufficient for local trust.
	default:
		hosts = append(hosts, host)
	}
	return hosts
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
