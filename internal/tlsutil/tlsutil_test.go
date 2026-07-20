// SPDX-License-Identifier: GPL-3.0-or-later
package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestGenerateSelfSignedLoadable(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("GenerateSelfSigned returned error: %v", err)
	}

	// The core contract: the generated pair loads via tls.X509KeyPair.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("tls.X509KeyPair could not load generated pair: %v", err)
	}
}

func TestGenerateSelfSignedDefaultsAndSANs(t *testing.T) {
	// Empty hosts -> loopback SANs; non-positive validity -> DefaultValidity.
	certPEM, keyPEM, err := GenerateSelfSigned(nil, 0)
	if err != nil {
		t.Fatalf("GenerateSelfSigned returned error: %v", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("tls.X509KeyPair error: %v", err)
	}

	cert, err := parseLeaf(certPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(cert.IPAddresses) == 0 {
		t.Fatal("expected loopback IP SANs when hosts is empty")
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got < DefaultValidity {
		t.Fatalf("validity window %v shorter than DefaultValidity %v", got, DefaultValidity)
	}
}

func TestEnsureSelfSignedPersistsAndReuses(t *testing.T) {
	dir := t.TempDir()

	certFile, keyFile, err := EnsureSelfSigned(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("EnsureSelfSigned (first boot) error: %v", err)
	}

	// Loadable from disk.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		t.Fatalf("tls.LoadX509KeyPair error: %v", err)
	}

	firstCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	// Second call must reuse the persisted pair, not regenerate it.
	certFile2, keyFile2, err := EnsureSelfSigned(dir, []string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("EnsureSelfSigned (reuse) error: %v", err)
	}
	if certFile2 != certFile || keyFile2 != keyFile {
		t.Fatalf("paths changed between calls: (%s,%s) vs (%s,%s)", certFile, keyFile, certFile2, keyFile2)
	}
	secondCert, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert (second): %v", err)
	}
	if !bytes.Equal(firstCert, secondCert) {
		t.Fatal("certificate was regenerated on second boot; expected reuse")
	}

	// Key file must be persisted with restrictive permissions.
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file perm = %o, want 600", perm)
	}
}

func TestEnsureSelfSignedEmptyDir(t *testing.T) {
	if _, _, err := EnsureSelfSigned("", nil); err == nil {
		t.Fatal("expected error for empty dir, got nil")
	}
}

func TestHostsForListenAddr(t *testing.T) {
	tests := []struct {
		name  string
		addr  string
		extra string // host expected in addition to loopback, "" means none
	}{
		{name: "bind all v4", addr: "0.0.0.0:8080", extra: ""},
		{name: "bind all v6", addr: "[::]:8080", extra: ""},
		{name: "specific ip", addr: "192.168.1.10:8080", extra: "192.168.1.10"},
		{name: "hostname", addr: "hydra.local:8080", extra: "hydra.local"},
		{name: "no port", addr: "10.0.0.5", extra: "10.0.0.5"},
	}
	loopback := []string{"localhost", "127.0.0.1", "::1"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := HostsForListenAddr(tc.addr)
			want := append([]string{}, loopback...)
			if tc.extra != "" {
				want = append(want, tc.extra)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("HostsForListenAddr(%q) = %v, want %v", tc.addr, got, want)
			}
		})
	}
}

// parseLeaf extracts and parses the first certificate from a PEM bundle.
func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
