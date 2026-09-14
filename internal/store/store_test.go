// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

func TestOfflineQueueSealRetryAndRecovery(t *testing.T) {
	chainBytes := make([]byte, 32)
	for i := range chainBytes {
		chainBytes[i] = byte(255 - i)
	}
	chainID := "spki-sha256:" + hex.EncodeToString(chainBytes)
	producerDir, sealerDir := t.TempDir(), t.TempDir()
	producer, err := OpenProducer(producerDir, chainID, "test-vm")
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := OpenSealer(sealerDir)
	if err != nil {
		t.Fatal(err)
	}
	request1 := enqueueTestBlock(t, producer, "one")
	request2 := enqueueTestBlock(t, producer, "two")
	if producer.QueueDepth() != 2 {
		t.Fatalf("offline queue depth = %d, want 2", producer.QueueDepth())
	}
	response1, err := sealer.Seal(chainID, request1)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := sealer.Seal(chainID, request1)
	if err != nil || retry != response1 {
		t.Fatalf("idempotent retry changed: %#v, %v", retry, err)
	}
	if err := producer.PersistSeal(request1, response1); err != nil {
		t.Fatal(err)
	}
	response2, err := sealer.Seal(chainID, request2)
	if err != nil {
		t.Fatal(err)
	}
	if response2.SealSequence != 2 {
		t.Fatalf("seal sequence = %d, want 2", response2.SealSequence)
	}
	if err := producer.PersistSeal(request2, response2); err != nil {
		t.Fatal(err)
	}

	producer, err = OpenProducer(producerDir, chainID, "test-vm")
	if err != nil {
		t.Fatalf("recover producer: %v", err)
	}
	sealer, err = OpenSealer(sealerDir)
	if err != nil {
		t.Fatalf("recover sealer: %v", err)
	}
	if producer.SealedCount() != 2 || producer.QueueDepth() != 0 || sealer.EntryCount() != 2 {
		t.Fatalf("unexpected recovered state: sealed=%d queued=%d ledger=%d", producer.SealedCount(), producer.QueueDepth(), sealer.EntryCount())
	}

	conflict := request2
	conflict.RequestID = request1.RequestID
	if _, err := sealer.Seal(chainID, conflict); err == nil {
		t.Fatal("conflicting reuse of an idempotency ID was accepted")
	}
	if _, err := sealer.Seal("spki-sha256:"+hex.EncodeToString(make([]byte, 32)), request2); err == nil {
		t.Fatal("request from a different authenticated identity was accepted")
	}
}

func TestCapacityIsDurableAndRetriesRemainAvailable(t *testing.T) {
	chain := "spki-sha256:" + strings.Repeat("0", 64)
	for _, variant := range []string{"entries", "bytes", "chain-entries", "chain-bytes"} {
		t.Run(variant, func(t *testing.T) {
			p, err := OpenProducer(t.TempDir(), chain, "vm")
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenSealer(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			r1 := enqueueTestBlock(t, p, "one")
			response, err := s.Seal(chain, r1)
			if err != nil {
				t.Fatal(err)
			}
			r2 := enqueueTestBlock(t, p, "two")
			limits := s.limits
			switch variant {
			case "entries":
				limits.Entries = 1
			case "bytes":
				limits.Bytes = s.used
			case "chain-entries":
				limits.ChainEntries = 1
			case "chain-bytes":
				limits.ChainBytes = s.used
			}
			s.limits = limits
			if _, err := s.Seal(chain, r2); !errors.Is(err, ErrCapacity) {
				t.Fatalf("quota bypass: %v", err)
			}
			if retry, err := s.Seal(chain, r1); err != nil || retry != response {
				t.Fatalf("retry at capacity: %v", err)
			}
			s, err = OpenSealer(s.root, limits)
			if err != nil {
				t.Fatal(err)
			}
			if retry, err := s.Seal(chain, r1); err != nil || retry != response {
				t.Fatalf("restart retry: %v", err)
			}
			if _, err := s.Seal(chain, r2); !errors.Is(err, ErrCapacity) {
				t.Fatalf("restart bypass: %v", err)
			}
		})
	}
}

func TestProducerQuotaReservesSealAndSurvivesCrashDuplicate(t *testing.T) {
	chain := "spki-sha256:" + strings.Repeat("0", 64)
	p, err := OpenProducer(t.TempDir(), chain, "vm")
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := enqueueTestBlock(t, p, "one")
	queuePath := artifactPath(p.queueDir(), 1)
	queued, err := os.ReadFile(queuePath)
	if err != nil {
		t.Fatal(err)
	}
	p.limits.Bytes = p.used + p.reserved
	p.limits.Entries = 1
	block, _, err := protocol.DecodeSealRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	block.ProducerSequence = 2
	block.PreviousBlockID = p.PreviousBlockID()
	if _, err := p.Enqueue(block); !errors.Is(err, ErrCapacity) {
		t.Fatalf("producer quota bypass: %v", err)
	}
	response, err := s.Seal(chain, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.PersistSeal(r, response); err != nil {
		t.Fatalf("reserved seal space unavailable: %v", err)
	}
	if err := os.WriteFile(queuePath, queued, 0640); err != nil {
		t.Fatal(err)
	}
	p, err = OpenProducer(p.root, chain, "vm", p.limits)
	if err != nil {
		t.Fatal(err)
	}
	if p.QueueDepth() != 0 || p.NextSequence() != 2 {
		t.Fatal("crash duplicate incorrectly counted")
	}
	if _, err := OpenProducer(p.root, chain, "vm", Limits{Bytes: 1, Entries: 1}); !errors.Is(err, ErrCapacity) {
		t.Fatalf("startup byte limit bypass: %v", err)
	}
}

func TestLedgerRejectsRenamedEvidenceAndWrongSourceRetry(t *testing.T) {
	chain := "spki-sha256:" + strings.Repeat("0", 64)
	p, err := OpenProducer(t.TempDir(), chain, "vm")
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := enqueueTestBlock(t, p, "one")
	if _, err := s.Seal(chain, r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal("spki-sha256:"+strings.Repeat("1", 64), r); err == nil {
		t.Fatal("wrong identity retry accepted")
	}
	if err := os.Rename(artifactPath(s.ledgerDir(), 1), artifactPath(s.ledgerDir(), 2)); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealer(s.root); err == nil {
		t.Fatal("renamed ledger accepted")
	}
}

func TestPersistedSignatureTamperingIsDetected(t *testing.T) {
	chainID := "spki-sha256:" + hex.EncodeToString(make([]byte, 32))
	producerDir, sealerDir := t.TempDir(), t.TempDir()
	producer, err := OpenProducer(producerDir, chainID, "test-vm")
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := OpenSealer(sealerDir)
	if err != nil {
		t.Fatal(err)
	}
	request := enqueueTestBlock(t, producer, "tamper")
	response, err := sealer.Seal(chainID, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.PersistSeal(request, response); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(producerDir, "sealed", "00000000000000000001.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry protocol.LedgerEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Response.Signature[0] == 'A' {
		entry.Response.Signature = "B" + entry.Response.Signature[1:]
	} else {
		entry.Response.Signature = "A" + entry.Response.Signature[1:]
	}
	data, err = protocol.MarshalJSONLine(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenProducer(producerDir, chainID, "test-vm"); err == nil {
		t.Fatal("producer accepted a modified persisted signature")
	}
}

func enqueueTestBlock(t *testing.T, producer *ProducerStore, cursor string) protocol.SealRequest {
	t.Helper()
	record, err := protocol.EncodeRecord(protocol.Record{Fields: []protocol.Field{
		{Name: "__CURSOR", Value: []byte(cursor)},
		{Name: "_BOOT_ID", Value: []byte("boot")},
		{Name: "MESSAGE", Value: []byte(cursor)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.Block{
		ChainID:          producer.ChainID(),
		SourceName:       producer.SourceName(),
		ProducerSequence: producer.NextSequence(),
		PreviousBlockID:  producer.PreviousBlockID(),
		BootID:           "boot",
		FirstCursor:      cursor,
		LastCursor:       cursor,
		Records:          [][]byte{record},
		MerkleRoot:       protocol.MerkleRoot([][]byte{record}),
	}
	request, err := producer.Enqueue(block)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// Archived v1 evidence larger than the live admission limit remains readable.
// Keep this fixture small; near-64 MiB startup needs separately sized VM RAM.
func TestHistoricalBlockAboveLiveLimitRemainsVerifiable(t *testing.T) {
	chain := "spki-sha256:" + strings.Repeat("0", 64)
	p, err := OpenProducer(t.TempDir(), chain, "vm")
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record, err := protocol.EncodeRecord(protocol.Record{Fields: []protocol.Field{
		{Name: "__CURSOR", Value: []byte("legacy")},
		{Name: "_BOOT_ID", Value: []byte("boot")},
		{Name: "MESSAGE", Value: []byte(strings.Repeat("x", 2<<20))},
	}})
	if err != nil {
		t.Fatal(err)
	}
	block := protocol.Block{ChainID: chain, SourceName: "vm", ProducerSequence: 1,
		BootID: "boot", FirstCursor: "legacy", LastCursor: "legacy", Records: [][]byte{record},
		MerkleRoot: protocol.MerkleRoot([][]byte{record})}
	body, err := protocol.EncodeBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	request, _, err := protocol.NewSealRequest(strings.Repeat("0", 32), body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protocol.NewSealResponse(request, block, 1, s.publicKey, s.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	data, err := protocol.MarshalJSONLine(protocol.LedgerEntry{Request: request, Response: response})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.pinPath(), s.publicKey, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{artifactPath(p.sealedDir(), 1), artifactPath(s.ledgerDir(), 1)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OpenProducer(p.root, chain, "vm"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealer(s.root); err != nil {
		t.Fatal(err)
	}
}
