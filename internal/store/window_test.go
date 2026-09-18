// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

func windowPair(t *testing.T, count int) (*ProducerStore, *SealerStore) {
	t.Helper()
	pl, sl := ProducerLimits(), SealerLimits()
	pl.WindowEntries, sl.Compact = count, true
	p, err := OpenProducer(t.TempDir(), "spki-sha256:"+strings.Repeat("1", 64), "vm", pl)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSealer(t.TempDir(), sl)
	if err != nil {
		t.Fatal(err)
	}
	return p, s
}

func sealNext(t *testing.T, p *ProducerStore, s *SealerStore, message string) (protocol.SealRequest, protocol.SealResponse) {
	t.Helper()
	r := enqueueTestBlock(t, p, message)
	seal, err := s.Seal(p.ChainID(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PersistSeal(r, seal); err != nil {
		t.Fatal(err)
	}
	return r, seal
}

func TestWindowRepeatedExpiryAndRestart(t *testing.T) {
	p, s := windowPair(t, 4)
	var request protocol.SealRequest
	var receipt protocol.SealResponse
	for n := 1; n <= 100; n++ {
		request, receipt = sealNext(t, p, s, fmt.Sprintf("record-%d", n))
		if p.SealedCount() > 4 {
			t.Fatal("window exceeded")
		}
		if n%7 == 0 {
			var err error
			p, err = OpenProducer(p.root, p.chainID, p.sourceName, p.limits)
			if err != nil {
				t.Fatal(err)
			}
			s, err = OpenSealer(s.root, s.limits)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if p.NextSequence() != 101 || p.ExpiredCount() != 96 || s.EntryCount() != 100 {
		t.Fatal("sequence reset during expiry")
	}
	retry, err := s.Seal(p.chainID, request)
	if err != nil || retry != receipt {
		t.Fatal("last response was not recoverable")
	}
	entries, err := os.ReadDir(s.ledgerDir())
	if err != nil || len(entries) != 0 {
		t.Fatal("sealer retained full blocks")
	}
	data, err := os.ReadFile(s.compactPath())
	if err != nil || bytes.Contains(data, []byte(request.Body)) || len(data) > 4096 {
		t.Fatal("compact state contains block content or is unexpectedly large")
	}
	if _, err := ReadProducer(p.root, p.chainID, p.sourceName, p.limits); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSealer(s.root, s.limits); err != nil {
		t.Fatal(err)
	}
}

func TestWindowDoesNotExpirePendingBlocks(t *testing.T) {
	p, s := windowPair(t, 2)
	for n := 0; n < 5; n++ {
		sealNext(t, p, s, "sealed")
	}
	for n := 0; n < 8; n++ {
		enqueueTestBlock(t, p, "offline")
	}
	p, err := OpenProducer(p.root, p.chainID, p.sourceName, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	if p.QueueDepth() != 8 || p.SealedCount() != 2 || p.NextSequence() != 14 {
		t.Fatal("pending evidence lost")
	}
	for p.QueueDepth() > 0 {
		r, found, err := p.Pending()
		if err != nil || !found {
			t.Fatal(err)
		}
		seal, err := s.Seal(p.chainID, r)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.PersistSeal(r, seal); err != nil {
			t.Fatal(err)
		}
	}
	if p.SealedCount() != 2 || p.ExpiredCount() != 11 {
		t.Fatal("offline recovery window incorrect")
	}
}

func TestCompactMigrationAndLostResponse(t *testing.T) {
	p, s := windowPair(t, 3)
	legacy, err := OpenSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var last protocol.SealRequest
	var response protocol.SealResponse
	for n := 0; n < 8; n++ {
		last, response = sealNext(t, p, legacy, "legacy")
	}
	limits := legacy.limits
	limits.Compact = true
	if _, err := ReadSealer(legacy.root, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy.compactPath()); !os.IsNotExist(err) {
		t.Fatal("verification migrated evidence")
	}
	s, err = OpenSealer(legacy.root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := s.Seal(p.chainID, last); err != nil || retry != response {
		t.Fatal("migration broke last retry")
	}
	next := enqueueTestBlock(t, p, "lost response")
	want, err := s.Seal(p.chainID, next)
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenSealer(s.root, limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Seal(p.chainID, next)
	if err != nil || got != want {
		t.Fatal("restart changed response")
	}
	if err := p.PersistSeal(next, got); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(p.chainID, last); err == nil {
		t.Fatal("expired request was resealed")
	}
	sealNext(t, p, s, "after recovery")
}

func TestWindowBoundaryCrashCleanup(t *testing.T) {
	p, s := windowPair(t, 2)
	sealNext(t, p, s, "first")
	oldPath := artifactPath(p.sealedDir(), 1)
	old, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	sealNext(t, p, s, "second")
	sealNext(t, p, s, "third")
	if err := os.WriteFile(oldPath, old, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProducer(p.root, p.chainID, p.sourceName, p.limits); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatal("verification deleted evidence")
	}
	p, err = OpenProducer(p.root, p.chainID, p.sourceName, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatal("expired crash leftover retained")
	}
	sealNext(t, p, s, "fourth")
}

func TestWindowTamperingFailsClosed(t *testing.T) {
	for _, target := range []string{"boundary", "checkpoint", "block", "missing-checkpoint", "missing-middle", "missing-key"} {
		t.Run(target, func(t *testing.T) {
			p, s := windowPair(t, 3)
			for n := 0; n < 6; n++ {
				sealNext(t, p, s, "evidence")
			}
			var path string
			switch target {
			case "boundary":
				path = filepath.Join(p.root, "boundary.json")
			case "checkpoint", "missing-checkpoint":
				path = s.compactPath()
			case "block", "missing-middle":
				path = artifactPath(p.sealedDir(), 5)
			case "missing-key":
				path = s.keyPath()
			}
			if strings.HasPrefix(target, "missing-") {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				data = bytes.Replace(data, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
				if err := os.WriteFile(path, data, 0o640); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			if target == "checkpoint" || target == "missing-checkpoint" || target == "missing-key" {
				_, err = OpenSealer(s.root, s.limits)
			} else {
				_, err = OpenProducer(p.root, p.chainID, p.sourceName, p.limits)
			}
			if err == nil {
				t.Fatal("tampering accepted")
			}
		})
	}
}

func TestCompactOtherProducersCannotEvictRetry(t *testing.T) {
	p, s := windowPair(t, 2)
	r, receipt := sealNext(t, p, s, "waiting")
	other, err := OpenProducer(t.TempDir(), "spki-sha256:"+strings.Repeat("2", 64), "other")
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 20; n++ {
		sealNext(t, other, s, "busy")
	}
	s, err = OpenSealer(s.root, s.limits)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Seal(p.chainID, r); err != nil || got != receipt {
		t.Fatal("another producer evicted retry")
	}
	if _, err := s.Seal(other.chainID, r); err == nil {
		t.Fatal("cross identity retry accepted")
	}
}

func TestWindowByteLimitAndChainLimit(t *testing.T) {
	p, s := windowPair(t, 100)
	p.limits.Bytes = 18000
	for n := 0; n < 30; n++ {
		sealNext(t, p, s, strings.Repeat("x", 512))
	}
	if p.ExpiredCount() == 0 || p.used+p.reserved > p.limits.Bytes {
		t.Fatal("byte limit did not advance the window")
	}
	s.limits.Entries = 1
	other, err := OpenProducer(t.TempDir(), "spki-sha256:"+strings.Repeat("3", 64), "other")
	if err != nil {
		t.Fatal(err)
	}
	r := enqueueTestBlock(t, other, "new identity")
	if _, err := s.Seal(other.chainID, r); err != ErrCapacity {
		t.Fatalf("chain bound: %v", err)
	}
	sealNext(t, p, s, "known identity continues")
}

func TestWindowClockJumpsAndTemporaryRecovery(t *testing.T) {
	p, s := windowPair(t, 2)
	for i, stamp := range []string{"2026-09-18T00:00:00Z", "2026-09-18T00:30:00Z", "2026-06-18T00:00:00Z", "2026-12-18T00:00:00Z", "2026-09-18T00:00:00Z"} {
		record, err := protocol.EncodeRecord(protocol.Record{Fields: []protocol.Field{
			{Name: "__CURSOR", Value: []byte(fmt.Sprintf("cursor-%d", i))},
			{Name: "_BOOT_ID", Value: []byte("boot")},
			{Name: "MESSAGE", Value: []byte(stamp)},
			{Name: "__REALTIME_TIMESTAMP", Value: []byte(stamp)},
		}})
		if err != nil {
			t.Fatal(err)
		}
		block := protocol.Block{ChainID: p.chainID, SourceName: p.sourceName, ProducerSequence: p.NextSequence(), PreviousBlockID: p.PreviousBlockID(), BootID: "boot", FirstCursor: fmt.Sprintf("cursor-%d", i), LastCursor: fmt.Sprintf("cursor-%d", i), Records: [][]byte{record}, MerkleRoot: protocol.MerkleRoot([][]byte{record})}
		r, err := p.Enqueue(block)
		if err != nil {
			t.Fatal(err)
		}
		seal, err := s.Seal(p.chainID, r)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.PersistSeal(r, seal); err != nil {
			t.Fatal(err)
		}
	}
	if p.TotalSealed() != 5 || p.ExpiredCount() != 3 {
		t.Fatal("timestamps affected retention order")
	}
	for _, dir := range []string{p.root, p.sealedDir(), p.queueDir(), s.root, s.ledgerDir()} {
		if err := os.WriteFile(filepath.Join(dir, ".logseald-crash"), []byte("incomplete"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	p, err = OpenProducer(p.root, p.chainID, p.sourceName, p.limits)
	if err != nil {
		t.Fatal(err)
	}
	s, err = OpenSealer(s.root, s.limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{p.root, p.sealedDir(), p.queueDir(), s.root, s.ledgerDir()} {
		if _, err := os.Stat(filepath.Join(dir, ".logseald-crash")); !os.IsNotExist(err) {
			t.Fatal("temporary evidence accumulated")
		}
	}
	sealNext(t, p, s, "after crash")
}

func TestWindowVerificationLockAndExclusiveWriter(t *testing.T) {
	p, s := windowPair(t, 2)
	sealNext(t, p, s, "initial")
	unlock, err := Lock(p.root, true)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Lock(p.root, true); err == nil {
		second()
		t.Fatal("second runtime writer accepted")
	}
	unlock()
	unlock, err = Lock(p.root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	done := make(chan error, 1)
	go func() {
		release, err := lockMutation(p.root)
		if err == nil {
			release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("mutation bypassed verification lock: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("mutation stayed blocked")
	}
}
