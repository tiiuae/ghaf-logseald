// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ProtocolVersion    = 1
	MaxBlockRecords    = 4096
	MaxBlockBodyBytes  = 64 << 20
	MaxLiveBlockBytes  = 1 << 20
	MaxChainIDBytes    = 96
	MaxSourceNameBytes = 128
	MaxBootIDBytes     = 64
	MaxCursorBytes     = 4096
)

var blockMagic = [8]byte{'L', 'O', 'G', 'S', 'E', 'A', 'L', '1'}
var chainIDPattern = regexp.MustCompile(`^spki-sha256:[0-9a-f]{64}$`)

type Block struct {
	ChainID          string
	SourceName       string
	ProducerSequence uint64
	PreviousBlockID  [32]byte
	BootID           string
	FirstCursor      string
	LastCursor       string
	Records          [][]byte
	MerkleRoot       [32]byte
}

func EncodeBlock(block Block) ([]byte, error) {
	if err := ValidateBlock(block); err != nil {
		return nil, err
	}
	return encodeValidatedBlock(block)
}

func encodeValidatedBlock(block Block) ([]byte, error) {
	// Callers must validate the block before encoding its canonical representation.
	var out bytes.Buffer
	out.Write(blockMagic[:])
	if err := binary.Write(&out, binary.BigEndian, uint16(ProtocolVersion)); err != nil {
		return nil, err
	}
	for _, value := range []string{block.ChainID, block.SourceName} {
		if err := writeBytes32(&out, []byte(value)); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&out, binary.BigEndian, block.ProducerSequence); err != nil {
		return nil, err
	}
	out.Write(block.PreviousBlockID[:])
	for _, value := range []string{block.BootID, block.FirstCursor, block.LastCursor} {
		if err := writeBytes32(&out, []byte(value)); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&out, binary.BigEndian, uint32(len(block.Records))); err != nil {
		return nil, err
	}
	for _, record := range block.Records {
		if err := writeBytes32(&out, record); err != nil {
			return nil, err
		}
		if out.Len() > MaxBlockBodyBytes {
			return nil, fmt.Errorf("block body exceeds %d bytes", MaxBlockBodyBytes)
		}
	}
	out.Write(block.MerkleRoot[:])
	if out.Len() > MaxBlockBodyBytes {
		return nil, fmt.Errorf("block body exceeds %d bytes", MaxBlockBodyBytes)
	}
	return out.Bytes(), nil
}

func DecodeBlock(encoded []byte) (Block, error) {
	if len(encoded) > MaxBlockBodyBytes {
		return Block{}, fmt.Errorf("block body exceeds %d bytes", MaxBlockBodyBytes)
	}
	reader := bytes.NewReader(encoded)
	magic := make([]byte, len(blockMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || !bytes.Equal(magic, blockMagic[:]) {
		return Block{}, fmt.Errorf("invalid block magic")
	}
	var version uint16
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil || version != ProtocolVersion {
		return Block{}, fmt.Errorf("unsupported block version %d", version)
	}
	chainID, err := readBytes32(reader, MaxChainIDBytes)
	if err != nil {
		return Block{}, fmt.Errorf("read chain ID: %w", err)
	}
	source, err := readBytes32(reader, MaxSourceNameBytes)
	if err != nil {
		return Block{}, fmt.Errorf("read source name: %w", err)
	}
	block := Block{ChainID: string(chainID), SourceName: string(source)}
	if err := binary.Read(reader, binary.BigEndian, &block.ProducerSequence); err != nil {
		return Block{}, fmt.Errorf("read producer sequence: %w", err)
	}
	if _, err := io.ReadFull(reader, block.PreviousBlockID[:]); err != nil {
		return Block{}, fmt.Errorf("read predecessor: %w", err)
	}
	values := make([]string, 3)
	limits := []int{MaxBootIDBytes, MaxCursorBytes, MaxCursorBytes}
	for i := range values {
		value, err := readBytes32(reader, limits[i])
		if err != nil {
			return Block{}, fmt.Errorf("read block string %d: %w", i, err)
		}
		values[i] = string(value)
	}
	block.BootID, block.FirstCursor, block.LastCursor = values[0], values[1], values[2]
	var count uint32
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return Block{}, fmt.Errorf("read record count: %w", err)
	}
	if count == 0 || count > MaxBlockRecords {
		return Block{}, fmt.Errorf("invalid record count %d", count)
	}
	block.Records = make([][]byte, 0, count)
	for range count {
		record, err := readBytes32(reader, MaxRecordBytes)
		if err != nil {
			return Block{}, fmt.Errorf("read canonical record: %w", err)
		}
		block.Records = append(block.Records, record)
	}
	if _, err := io.ReadFull(reader, block.MerkleRoot[:]); err != nil {
		return Block{}, fmt.Errorf("read Merkle root: %w", err)
	}
	if reader.Len() != 0 {
		return Block{}, fmt.Errorf("block has %d trailing bytes", reader.Len())
	}
	if err := ValidateBlock(block); err != nil {
		return Block{}, err
	}
	reencoded, err := encodeValidatedBlock(block)
	if err != nil {
		return Block{}, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return Block{}, fmt.Errorf("block encoding is not canonical")
	}
	return block, nil
}

func ValidateBlock(block Block) error {
	size := 8 + 2 + 8 + 32 + 4 + 32
	for _, value := range []string{block.ChainID, block.SourceName, block.BootID, block.FirstCursor, block.LastCursor} {
		if len(value) > MaxBlockBodyBytes-size-4 {
			return fmt.Errorf("block body is too large")
		}
		size += 4 + len(value)
	}
	for _, record := range block.Records {
		if len(record) > MaxBlockBodyBytes-size-4 {
			return fmt.Errorf("block body is too large")
		}
		size += 4 + len(record)
	}
	if !chainIDPattern.MatchString(block.ChainID) {
		return fmt.Errorf("invalid chain ID")
	}
	if len(block.SourceName) == 0 || len(block.SourceName) > MaxSourceNameBytes {
		return fmt.Errorf("invalid source name length %d", len(block.SourceName))
	}
	if !validMetadata(block.SourceName) {
		return fmt.Errorf("source name contains invalid characters")
	}
	if block.ProducerSequence == 0 {
		return fmt.Errorf("producer sequence must start at 1")
	}
	if len(block.BootID) == 0 || len(block.BootID) > MaxBootIDBytes {
		return fmt.Errorf("invalid boot ID length %d", len(block.BootID))
	}
	if len(block.FirstCursor) == 0 || len(block.FirstCursor) > MaxCursorBytes || len(block.LastCursor) == 0 || len(block.LastCursor) > MaxCursorBytes {
		return fmt.Errorf("invalid cursor length")
	}
	if !validMetadata(block.BootID) || !validMetadata(block.FirstCursor) || !validMetadata(block.LastCursor) {
		return fmt.Errorf("block metadata contains invalid characters")
	}
	if len(block.Records) == 0 || len(block.Records) > MaxBlockRecords {
		return fmt.Errorf("invalid record count %d", len(block.Records))
	}
	for _, record := range block.Records {
		if _, err := DecodeRecord(record); err != nil {
			return fmt.Errorf("invalid canonical record: %w", err)
		}
	}
	root := MerkleRoot(block.Records)
	if root != block.MerkleRoot {
		return fmt.Errorf("Merkle root mismatch")
	}
	return nil
}

func validMetadata(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func MerkleRoot(records [][]byte) [32]byte {
	if len(records) == 0 {
		return sha256.Sum256([]byte("logseald-merkle-empty-v1\x00"))
	}
	nodes := make([][32]byte, len(records))
	for i, record := range records {
		hasher := sha256.New()
		hasher.Write([]byte("logseald-record-v1\x00"))
		hasher.Write(record)
		copy(nodes[i][:], hasher.Sum(nil))
	}
	for len(nodes) > 1 {
		next := make([][32]byte, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			right := nodes[i]
			if i+1 < len(nodes) {
				right = nodes[i+1]
			}
			hasher := sha256.New()
			hasher.Write([]byte("logseald-merkle-node-v1\x00"))
			hasher.Write(nodes[i][:])
			hasher.Write(right[:])
			var parent [32]byte
			copy(parent[:], hasher.Sum(nil))
			next = append(next, parent)
		}
		nodes = next
	}
	return nodes[0]
}

func BlockID(encoded []byte) [32]byte {
	hasher := sha256.New()
	hasher.Write([]byte("logseald-block-id-v1\x00"))
	hasher.Write(encoded)
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result
}

func ParseBlockID(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, fmt.Errorf("invalid block ID")
	}
	copy(result[:], decoded)
	return result, nil
}
