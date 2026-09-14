// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

// Package journal parses the binary-safe Journal Export Format.
package journal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"

	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

type Reader struct {
	input  *bufio.Reader
	digest hash.Hash
	bytes  uint64
}

func NewReader(input io.Reader) *Reader {
	return &Reader{input: bufio.NewReaderSize(input, 32<<10), digest: sha256.New()}
}

// Write hashes exactly consumed bytes, not bufio read-ahead. io.CopyN can
// therefore drain a binary payload without allocating its declared size.
func (reader *Reader) Write(data []byte) (int, error) {
	reader.bytes += uint64(len(data))
	return reader.digest.Write(data)
}

func (reader *Reader) ReadRecord() (protocol.Record, error) {
	reader.digest.Reset()
	reader.bytes = 0
	record := protocol.Record{}
	metadata := map[string][]byte{}
	size, count := 8, 0
	omitted := false
	for {
		line, long, err := reader.readLine(protocol.MaxLiveRecordBytes - size)
		if err != nil {
			if errors.Is(err, io.EOF) && count == 0 && reader.bytes == 0 {
				return protocol.Record{}, io.EOF
			}
			return protocol.Record{}, fmt.Errorf("read journal export line: %w", err)
		}
		if len(line) == 0 && !long {
			if count == 0 {
				reader.digest.Reset()
				reader.bytes = 0
				continue
			}
			if !omitted {
				return record, nil
			}
			if len(metadata["__CURSOR"]) == 0 || len(metadata["_BOOT_ID"]) == 0 {
				return protocol.Record{}, fmt.Errorf("oversized journal record lacks cursor or boot ID")
			}
			// Explicit evidence representation, never silent truncation.
			// Hash the raw entry, binary framing and terminating blank line.
			return protocol.Record{Fields: []protocol.Field{
				{Name: "__CURSOR", Value: metadata["__CURSOR"]},
				{Name: "_BOOT_ID", Value: metadata["_BOOT_ID"]},
				{Name: "_LOGSEALD_RECORD_STATUS", Value: []byte("oversize-export-digest-v1")},
				{Name: "_LOGSEALD_EXPORT_SHA256", Value: []byte(hex.EncodeToString(reader.digest.Sum(nil)))},
				{Name: "_LOGSEALD_EXPORT_BYTES", Value: []byte(strconv.FormatUint(reader.bytes, 10))},
			}}, nil
		}
		if count <= protocol.MaxFieldsPerRecord {
			count++
		}
		nameBytes, value, text := bytes.Cut(line, []byte{'='})
		name := string(nameBytes)
		if err := protocol.ValidateFieldName(name); err != nil {
			return protocol.Record{}, err
		}
		tooLarge := long
		if !text {
			var framing [8]byte
			if _, err := io.ReadFull(reader.input, framing[:]); err != nil {
				return protocol.Record{}, fmt.Errorf("read binary length: %w", err)
			}
			reader.Write(framing[:])
			length := binary.LittleEndian.Uint64(framing[:])
			if length > 1<<63-1 {
				return protocol.Record{}, fmt.Errorf("binary field length overflows export reader")
			}
			budget := protocol.MaxLiveRecordBytes - size - 12 - len(name)
			// Retain bounded metadata even after content budget exhaustion.
			if name == "__CURSOR" {
				budget = protocol.MaxCursorBytes
			}
			if name == "_BOOT_ID" {
				budget = protocol.MaxBootIDBytes
			}
			tooLarge = budget < 0 || length > uint64(budget)
			if tooLarge {
				if _, err := io.CopyN(reader, reader.input, int64(length)); err != nil {
					return protocol.Record{}, fmt.Errorf("drain binary field: %w", err)
				}
			} else {
				value = make([]byte, int(length))
				if _, err := io.ReadFull(reader.input, value); err != nil {
					return protocol.Record{}, fmt.Errorf("read binary field: %w", err)
				}
				reader.Write(value)
			}
			end, err := reader.input.ReadByte()
			if err != nil || end != '\n' {
				return protocol.Record{}, fmt.Errorf("binary field has no newline terminator")
			}
			reader.Write([]byte{end})
		}
		if name == "__CURSOR" || name == "_BOOT_ID" {
			max := protocol.MaxCursorBytes
			if name == "_BOOT_ID" {
				max = protocol.MaxBootIDBytes
			}
			if _, duplicate := metadata[name]; duplicate || tooLarge || len(value) > max || len(value) == 0 {
				return protocol.Record{}, fmt.Errorf("invalid or duplicate journal metadata %s", name)
			}
			metadata[name] = append([]byte(nil), value...)
		}
		if tooLarge || count > protocol.MaxFieldsPerRecord || len(value) > protocol.MaxLiveRecordBytes-size-12-len(name) {
			omitted = true
			record.Fields = nil
		}
		if !omitted {
			size += 12 + len(name) + len(value)
			record.Fields = append(record.Fields, protocol.Field{Name: name, Value: value})
		}
	}
}

func (reader *Reader) readLine(budget int) ([]byte, bool, error) {
	// Keep enough prefix for metadata and field-name validation; drain and
	// hash the remainder without accumulating it.
	if budget < protocol.MaxCursorBytes+protocol.MaxFieldNameBytes+2 {
		budget = protocol.MaxCursorBytes + protocol.MaxFieldNameBytes + 2
	}
	var line []byte
	long := false
	for {
		fragment, err := reader.input.ReadSlice('\n')
		reader.Write(fragment)
		n := len(fragment)
		if n > budget-len(line) {
			n = budget - len(line)
			long = true
		}
		line = append(line, fragment[:n]...)
		if err == nil {
			if !long {
				line = line[:len(line)-1]
			}
			return line, long, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, long, err
		}
	}
}
