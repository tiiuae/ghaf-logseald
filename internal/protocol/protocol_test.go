// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRecordCanonicalizationPreservesBinaryDuplicates(t *testing.T) {
	record := Record{Fields: []Field{
		{Name: "MESSAGE", Value: []byte{'z', 0, 'x'}},
		{Name: "A", Value: []byte("second")},
		{Name: "A", Value: []byte("first")},
	}}
	encoded, err := EncodeRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Fields) != 3 || decoded.Fields[0].Name != "A" || string(decoded.Fields[0].Value) != "first" || !bytes.Equal(decoded.Fields[2].Value, []byte{'z', 0, 'x'}) {
		t.Fatalf("unexpected canonical fields: %#v", decoded.Fields)
	}
	encoded = append(encoded, 0)
	if _, err := DecodeRecord(encoded); err == nil {
		t.Fatal("modified canonical record was accepted")
	}
}

func benchmarkBlock(b *testing.B) []byte {
	b.Helper()
	record, err := EncodeRecord(Record{Fields: []Field{{Name: "MESSAGE", Value: bytes.Repeat([]byte{'x'}, 4<<10)}}})
	if err != nil {
		b.Fatal(err)
	}
	records := make([][]byte, 128)
	for i := range records {
		records[i] = record
	}
	body, err := EncodeBlock(Block{
		ChainID: "spki-sha256:" + strings.Repeat("0", 64), SourceName: "vm", ProducerSequence: 1,
		BootID: "boot", FirstCursor: "first", LastCursor: "last", Records: records, MerkleRoot: MerkleRoot(records),
	})
	if err != nil {
		b.Fatal(err)
	}
	return body
}

func BenchmarkDecodeBlock(b *testing.B) {
	body := benchmarkBlock(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := DecodeBlock(body); err != nil {
			b.Fatal(err)
		}
	}
}

func TestBlockDecoderRejectsNoncanonicalRecordsAndCorruptFraming(t *testing.T) {
	record, err := EncodeRecord(Record{Fields: []Field{{Name: "A", Value: []byte("first")}, {Name: "B", Value: []byte("other")}}})
	if err != nil {
		t.Fatal(err)
	}
	block := Block{ChainID: "spki-sha256:" + strings.Repeat("0", 64), SourceName: "vm", ProducerSequence: 1,
		BootID: "boot", FirstCursor: "first", LastCursor: "last", Records: [][]byte{record}, MerkleRoot: MerkleRoot([][]byte{record})}
	body, err := EncodeBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{body[:len(body)-1], append(append([]byte(nil), body...), 0), append([]byte(nil), body...)} {
		if len(data) == len(body) {
			data[len(data)-1] ^= 1
		}
		if _, err := DecodeBlock(data); err == nil {
			t.Fatal("corrupt block accepted")
		}
	}
	// Recompute the root so rejection must come from record canonicality.
	block.Records[0] = append([]byte(nil), record...)
	block.Records[0][12] = 'Z'
	block.MerkleRoot = MerkleRoot(block.Records)
	if _, err := EncodeBlock(block); err == nil {
		t.Fatal("noncanonical field order accepted")
	}
	malformed, err := encodeValidatedBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeBlock(malformed); err == nil {
		t.Fatal("decoder accepted noncanonical record with a valid root")
	}
}

func TestBlockAndSealBindAllSecurityFields(t *testing.T) {
	record, err := EncodeRecord(Record{Fields: []Field{{Name: "MESSAGE", Value: []byte("hello")}}})
	if err != nil {
		t.Fatal(err)
	}
	chainHash := make([]byte, 32)
	for i := range chainHash {
		chainHash[i] = byte(i)
	}
	block := Block{
		ChainID:          "spki-sha256:" + hex.EncodeToString(chainHash),
		SourceName:       "test-vm",
		ProducerSequence: 1,
		BootID:           "boot-one",
		FirstCursor:      "cursor-one",
		LastCursor:       "cursor-one",
		Records:          [][]byte{record},
		MerkleRoot:       MerkleRoot([][]byte{record}),
	}
	body, err := EncodeBlock(block)
	if err != nil {
		t.Fatal(err)
	}
	request, decoded, err := NewSealRequest("00000000000000000000000000000001", body)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	response, err := NewSealResponse(request, decoded, 1, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySealResponse(request, response, nil); err != nil {
		t.Fatal(err)
	}
	response.RequestID = "00000000000000000000000000000002"
	request.RequestID = response.RequestID
	if _, err := VerifySealResponse(request, response, nil); err == nil {
		t.Fatal("signature was not bound to the request ID")
	}

	block.MerkleRoot[0] ^= 1
	if _, err := EncodeBlock(block); err == nil {
		t.Fatal("block with altered Merkle root was accepted")
	}
}
