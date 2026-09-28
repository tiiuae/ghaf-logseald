// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialEpochUsesCAAndProducerPublicKey(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte("ca-one"), 0o600); err != nil {
		t.Fatal(err)
	}
	producer, sealer := t.TempDir(), t.TempDir()
	leaf := &x509.Certificate{RawSubjectPublicKeyInfo: []byte("producer-key")}
	prepare := func() {
		t.Helper()
		if err := prepareCredentialEpoch(producer, "producer", caFile, leaf); err != nil {
			t.Fatal(err)
		}
		if err := prepareCredentialEpoch(sealer, "sealer", caFile, nil); err != nil {
			t.Fatal(err)
		}
	}
	marker := func(root string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(root, "credential-epoch"))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	prepare()
	p, s := marker(producer), marker(sealer)
	leaf.Raw = []byte("renewed certificate with the same public key")
	prepare()
	if marker(producer) != p || marker(sealer) != s {
		t.Fatal("renewal changed credential epoch")
	}
	leaf.RawSubjectPublicKeyInfo = []byte("new-producer-key")
	prepare()
	if marker(producer) == p || marker(sealer) != s {
		t.Fatal("leaf rotation reset the wrong state")
	}
	p = marker(producer)
	if err := os.WriteFile(caFile, []byte("ca-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepare()
	if marker(producer) == p || marker(sealer) == s {
		t.Fatal("CA change did not reset both roles")
	}
}

func TestInvalidCredentialsDoNotDiscardState(t *testing.T) {
	for _, role := range []string{"producer", "sealer"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "sealer-public-key")
			if role == "sealer" {
				path = filepath.Join(root, "sealer.key")
			}
			if err := os.WriteFile(path, []byte("retained"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--reset-on-credential-change", "--state-dir", root, "--cert", "missing", "--key", "missing", "--ca", "missing"}
			var err error
			if role == "producer" {
				err = runProducer(context.Background(), args)
			} else {
				err = runSealer(context.Background(), args)
			}
			if err == nil {
				t.Fatal("invalid credentials accepted")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "retained" {
				t.Fatal("invalid credentials discarded state")
			}
		})
	}
}
