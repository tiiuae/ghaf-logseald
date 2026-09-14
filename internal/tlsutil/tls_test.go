// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package tlsutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStaticVerificationDoesNotRequireCurrentWallClock(t *testing.T) {
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2002, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "admin-vm"},
		DNSNames:     []string{"admin-vm"},
		NotBefore:    time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, leafPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	if err := verifyPeer([]*x509.Certificate{leaf}, roots, "admin-vm", x509.ExtKeyUsageServerAuth); err != nil {
		t.Fatalf("static verification rejected a valid expired chain: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:   "admin-vm",
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("wall-clock verification unexpectedly accepted a certificate that expired in 2001")
	}
	if err := verifyPeer([]*x509.Certificate{leaf}, roots, "wrong-name", x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("static verification skipped the peer name check")
	}
}

func TestRevocationBothPeersPoliciesAndResumedConnections(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"admin"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, denyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "denied")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []TimePolicy{StaticCert, WallClock} {
		for _, server := range []bool{false, true} {
			for _, denied := range []string{ChainID(leaf), "spki-sha256:" + strings.Repeat("0", 64), "malformed"} {
				if err := os.WriteFile(denyPath, []byte(denied), 0600); err != nil {
					t.Fatal(err)
				}
				var config *tls.Config
				if server {
					config, err = ServerConfig(certPath, keyPath, certPath, policy, denyPath)
				} else {
					config, err = ClientConfig(certPath, keyPath, certPath, "admin", policy, denyPath)
				}
				if denied == "malformed" {
					if err == nil {
						t.Fatal("malformed revocation policy accepted")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				for _, resumed := range []bool{false, true} {
					err = config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, DidResume: resumed})
					if (err != nil) != (denied == ChainID(leaf)) {
						t.Fatalf("policy=%s server=%v resumed=%v denied=%s: %v", policy, server, resumed, denied, err)
					}
				}
			}
		}
	}
}
