// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialEpochRestartAndReset(t *testing.T) {
	for _, compact := range []bool{false, true} {
		t.Run(map[bool]string{false: "ledger", true: "compact"}[compact], func(t *testing.T) {
			producerRoot, sealerRoot := t.TempDir(), t.TempDir()
			oldEpoch, newEpoch := strings.Repeat("1", 64), strings.Repeat("2", 64)
			oldChain, newChain := "spki-sha256:"+oldEpoch, "spki-sha256:"+newEpoch
			for role, root := range map[string]string{"producer": producerRoot, "sealer": sealerRoot} {
				unlock, err := Lock(root, true)
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
				if reset, err := PrepareCredentialEpoch(root, role, oldEpoch); err != nil || !reset {
					t.Fatalf("initialize %s: %v, %v", role, reset, err)
				}
			}
			p, err := OpenProducer(producerRoot, oldChain, "vm")
			if err != nil {
				t.Fatal(err)
			}
			limits := SealerLimits()
			limits.Compact = compact
			s, err := OpenSealer(sealerRoot, limits)
			if err != nil {
				t.Fatal(err)
			}
			oldSigningKey := s.PublicKey()
			request := enqueueTestBlock(t, p, "sealed")
			response, err := s.Seal(oldChain, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.PersistSeal(request, response); err != nil {
				t.Fatal(err)
			}
			enqueueTestBlock(t, p, "pending")
			for role, root := range map[string]string{"producer": producerRoot, "sealer": sealerRoot} {
				if reset, err := PrepareCredentialEpoch(root, role, oldEpoch); err != nil || reset {
					t.Fatalf("restart %s: %v, %v", role, reset, err)
				}
			}
			p, err = OpenProducer(producerRoot, oldChain, "vm")
			if err != nil || p.NextSequence() != 3 || p.QueueDepth() != 1 || p.SealedCount() != 1 {
				t.Fatalf("restart lost producer history: %v", err)
			}
			if _, err := OpenProducer(producerRoot, newChain, "vm"); err == nil {
				t.Fatal("changed identity unexpectedly resumed without reset")
			}
			for role, root := range map[string]string{"producer": producerRoot, "sealer": sealerRoot} {
				if reset, err := PrepareCredentialEpoch(root, role, newEpoch); err != nil || !reset {
					t.Fatalf("reset %s: %v, %v", role, reset, err)
				}
			}
			p, err = OpenProducer(producerRoot, newChain, "vm")
			if err != nil {
				t.Fatal(err)
			}
			s, err = OpenSealer(sealerRoot, limits)
			if err != nil {
				t.Fatal(err)
			}
			if p.NextSequence() != 1 || p.QueueDepth() != 0 || p.SealedCount() != 0 || p.PinnedKey() != nil {
				t.Fatal("new producer epoch retained old state")
			}
			if bytes.Equal(oldSigningKey, s.PublicKey()) {
				t.Fatal("new sealer epoch reused signing key")
			}
			request = enqueueTestBlock(t, p, "new epoch")
			response, err = s.Seal(newChain, request)
			if err != nil || response.SealSequence != 1 {
				t.Fatalf("new chain: %v", err)
			}
			if err := p.PersistSeal(request, response); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCredentialEpochLegacyAndInterruptedReset(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"queue", "sealed"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"boundary.json", "sealer-public-key", "writer.lock", "unrelated"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("old"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	lockInfo, err := os.Stat(filepath.Join(root, "writer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	epoch := strings.Repeat("a", 64)
	if reset, err := PrepareCredentialEpoch(root, "producer", epoch); err != nil || !reset {
		t.Fatalf("legacy reset: %v, %v", reset, err)
	}
	for _, name := range []string{"queue", "sealed", "boundary.json", "sealer-public-key"} {
		if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatalf("retained %s", name)
		}
	}
	currentLock, _ := os.Stat(filepath.Join(root, "writer.lock"))
	if !os.SameFile(lockInfo, currentLock) {
		t.Fatal("reset replaced writer lock")
	}
	if _, err := os.Stat(filepath.Join(root, "unrelated")); err != nil {
		t.Fatal(err)
	}

	// A crash before the new marker commits leaves the previous epoch in place.
	if err := os.Mkdir(filepath.Join(root, "sealed"), 0o750); err != nil {
		t.Fatal(err)
	}
	if reset, err := PrepareCredentialEpoch(root, "producer", strings.Repeat("b", 64)); err != nil || !reset {
		t.Fatalf("resume interrupted cleanup: %v, %v", reset, err)
	}
	if err := os.WriteFile(filepath.Join(root, "credential-epoch"), []byte("broken"), 0o640); err != nil {
		t.Fatal(err)
	}
	if reset, err := PrepareCredentialEpoch(root, "producer", epoch); err == nil || reset {
		t.Fatal("invalid marker triggered reset")
	}
}
