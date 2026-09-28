// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/tiiuae/ghaf-logseald/internal/store"
)

func prepareCredentialEpoch(root, role, caFile string, producer *x509.Certificate) error {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read credential epoch CA: %w", err)
	}
	epoch := sha256.Sum256(ca)
	if producer != nil {
		epoch = sha256.Sum256(append(epoch[:], producer.RawSubjectPublicKeyInfo...))
	}
	id := fmt.Sprintf("%x", epoch)
	reset, err := store.PrepareCredentialEpoch(root, role, id)
	if reset {
		log.Printf("starting %s credential epoch %s; previous sealing state discarded", role, id)
	}
	return err
}
