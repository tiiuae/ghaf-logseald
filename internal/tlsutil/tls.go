// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

// Package tlsutil builds TLS configurations whose identity checks can work
// before the system wall clock is trustworthy.
package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

type TimePolicy string

const (
	WallClock  TimePolicy = "wall-clock"
	StaticCert TimePolicy = "static-cert"
)

func ParseTimePolicy(value string) (TimePolicy, error) {
	policy := TimePolicy(value)
	if policy != WallClock && policy != StaticCert {
		return "", fmt.Errorf("unknown TLS time policy %q", value)
	}
	return policy, nil
}

func LoadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA bundle contains no certificates")
	}
	return pool, nil
}

func LoadLeaf(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate file contains no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func ChainID(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "spki-sha256:" + hex.EncodeToString(hash[:])
}

func ClientConfig(certFile, keyFile, caFile, serverName string, policy TimePolicy, denyFiles ...string) (*tls.Config, error) {
	if _, err := ParseTimePolicy(string(policy)); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}
	roots, err := LoadRoots(caFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   serverName,
	}
	if policy == StaticCert {
		config.InsecureSkipVerify = true // Verification is performed below with a clock-independent reference time.
		config.VerifyConnection = func(connection tls.ConnectionState) error {
			return verifyPeer(connection.PeerCertificates, roots, serverName, x509.ExtKeyUsageServerAuth)
		}
	}
	return withRevocations(config, denyFiles)
}

func ServerConfig(certFile, keyFile, caFile string, policy TimePolicy, denyFiles ...string) (*tls.Config, error) {
	if _, err := ParseTimePolicy(string(policy)); err != nil {
		return nil, err
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}
	roots, err := LoadRoots(caFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	if policy == StaticCert {
		config.ClientAuth = tls.RequireAnyClientCert
		config.VerifyConnection = func(connection tls.ConnectionState) error {
			return verifyPeer(connection.PeerCertificates, roots, "", x509.ExtKeyUsageClientAuth)
		}
	}
	return withRevocations(config, denyFiles)
}

func withRevocations(config *tls.Config, paths []string) (*tls.Config, error) {
	// Policy changes require a restart to reload keys and drop established sessions.
	if len(paths) > 1 {
		return nil, fmt.Errorf("expected one revoked-key file")
	}
	denied := make(map[string]bool)
	if len(paths) == 1 && paths[0] != "" {
		data, err := os.ReadFile(paths[0])
		if err != nil {
			return nil, fmt.Errorf("load revoked keys: %w", err)
		}
		for _, key := range strings.Fields(string(data)) {
			if !strings.HasPrefix(key, "spki-sha256:") || len(key) != len("spki-sha256:")+64 {
				return nil, fmt.Errorf("invalid revoked SPKI ID")
			}
			if _, err := hex.DecodeString(strings.TrimPrefix(key, "spki-sha256:")); err != nil || key != strings.ToLower(key) {
				return nil, fmt.Errorf("invalid revoked SPKI ID")
			}
			denied[key] = true
		}
	}
	previous := config.VerifyConnection
	config.VerifyConnection = func(connection tls.ConnectionState) error {
		if previous != nil {
			if err := previous(connection); err != nil {
				return err
			}
		}
		if len(connection.PeerCertificates) == 0 {
			return fmt.Errorf("TLS peer sent no certificate")
		}
		// The list identifies peer leaf keys, not certificate serial numbers.
		// Reissuing a certificate around the same key does not bypass it.
		if denied[ChainID(connection.PeerCertificates[0])] {
			return fmt.Errorf("TLS peer key is revoked")
		}
		return nil
	}
	return config, nil
}

func verifyPeer(peer []*x509.Certificate, roots *x509.CertPool, name string, usage x509.ExtKeyUsage) error {
	if len(peer) == 0 {
		return fmt.Errorf("TLS peer sent no certificate")
	}
	// An untrusted clock requires a common validity interval, not present-day expiry.
	notBefore, notAfter := peer[0].NotBefore, peer[0].NotAfter
	intermediates := x509.NewCertPool()
	for _, cert := range peer[1:] {
		intermediates.AddCert(cert)
		if cert.NotBefore.After(notBefore) {
			notBefore = cert.NotBefore
		}
		if cert.NotAfter.Before(notAfter) {
			notAfter = cert.NotAfter
		}
	}
	if !notBefore.Before(notAfter) {
		return fmt.Errorf("TLS certificate chain has no common validity interval")
	}
	verificationTime := notBefore.Add(notAfter.Sub(notBefore) / 2)
	_, err := peer[0].Verify(x509.VerifyOptions{
		DNSName:       name,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   verificationTime,
		KeyUsages:     []x509.ExtKeyUsage{usage},
	})
	if err != nil {
		return fmt.Errorf("verify TLS peer: %w", err)
	}
	return nil
}

func LeafFromTLSCertificate(cert tls.Certificate) (*x509.Certificate, error) {
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("TLS key pair has no leaf certificate")
	}
	return x509.ParseCertificate(cert.Certificate[0])
}
