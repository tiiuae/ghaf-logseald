// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

const (
	MaxFieldNameBytes  = 64
	MaxFieldValueBytes = 16 << 20
	MaxFieldsPerRecord = 4096
	MaxRecordBytes     = 32 << 20
	// Live ingestion limits are separate from the v1 archival format limits.
	MaxLiveRecordBytes = 256 << 10
)

var recordMagic = [4]byte{'L', 'S', 'R', '1'}

// Field retains a journal field as raw bytes. Duplicate fields are meaningful
// and are deliberately not represented as a map.
type Field struct {
	Name  string
	Value []byte
}

type Record struct {
	Fields []Field
}

func ValidateFieldName(name string) error {
	if len(name) == 0 || len(name) > MaxFieldNameBytes {
		return fmt.Errorf("field name length %d is outside 1..%d", len(name), MaxFieldNameBytes)
	}
	for _, c := range []byte(name) {
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return fmt.Errorf("invalid journal field name %q", name)
		}
	}
	return nil
}

// EncodeRecord returns the canonical record encoding. Fields are sorted by
// raw name and then raw value; duplicate name/value pairs remain duplicated.
func EncodeRecord(record Record) ([]byte, error) {
	if len(record.Fields) == 0 || len(record.Fields) > MaxFieldsPerRecord {
		return nil, fmt.Errorf("field count %d is outside 1..%d", len(record.Fields), MaxFieldsPerRecord)
	}
	size := 8
	for _, field := range record.Fields {
		if err := ValidateFieldName(field.Name); err != nil {
			return nil, err
		}
		if len(field.Value) > MaxFieldValueBytes {
			return nil, fmt.Errorf("field %q value exceeds %d bytes", field.Name, MaxFieldValueBytes)
		}
		if len(field.Value) > MaxRecordBytes-size-12-len(field.Name) {
			return nil, fmt.Errorf("canonical record exceeds %d bytes", MaxRecordBytes)
		}
		size += 12 + len(field.Name) + len(field.Value)
	}
	// Sort only the field descriptors; values are not modified by encoding.
	fields := append([]Field(nil), record.Fields...)
	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].Name != fields[j].Name {
			return fields[i].Name < fields[j].Name
		}
		return bytes.Compare(fields[i].Value, fields[j].Value) < 0
	})

	var out bytes.Buffer
	out.Grow(size)
	out.Write(recordMagic[:])
	if err := binary.Write(&out, binary.BigEndian, uint32(len(fields))); err != nil {
		return nil, err
	}
	for _, field := range fields {
		if err := writeBytes32(&out, []byte(field.Name)); err != nil {
			return nil, err
		}
		if err := writeBytes64(&out, field.Value); err != nil {
			return nil, err
		}
		if out.Len() > MaxRecordBytes {
			return nil, fmt.Errorf("canonical record exceeds %d bytes", MaxRecordBytes)
		}
	}
	return out.Bytes(), nil
}

// DecodeRecord accepts only the canonical byte representation.
func DecodeRecord(encoded []byte) (Record, error) {
	if len(encoded) > MaxRecordBytes {
		return Record{}, fmt.Errorf("record exceeds %d bytes", MaxRecordBytes)
	}
	reader := bytes.NewReader(encoded)
	magic := make([]byte, len(recordMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || !bytes.Equal(magic, recordMagic[:]) {
		return Record{}, fmt.Errorf("invalid record magic")
	}
	var count uint32
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return Record{}, fmt.Errorf("read field count: %w", err)
	}
	if count == 0 || count > MaxFieldsPerRecord {
		return Record{}, fmt.Errorf("invalid field count %d", count)
	}
	record := Record{Fields: make([]Field, 0, count)}
	for range count {
		nameBytes, err := readBytes32(reader, MaxFieldNameBytes)
		if err != nil {
			return Record{}, fmt.Errorf("read field name: %w", err)
		}
		name := string(nameBytes)
		if err := ValidateFieldName(name); err != nil {
			return Record{}, err
		}
		value, err := readBytes64(reader, MaxFieldValueBytes)
		if err != nil {
			return Record{}, fmt.Errorf("read field %q value: %w", name, err)
		}
		record.Fields = append(record.Fields, Field{Name: name, Value: value})
	}
	if reader.Len() != 0 {
		return Record{}, fmt.Errorf("record has %d trailing bytes", reader.Len())
	}
	reencoded, err := EncodeRecord(record)
	if err != nil {
		return Record{}, err
	}
	if !bytes.Equal(encoded, reencoded) {
		return Record{}, fmt.Errorf("record encoding is not canonical")
	}
	return record, nil
}

func UniqueField(record Record, name string) (string, error) {
	var found []byte
	seen := false
	for _, field := range record.Fields {
		if field.Name != name {
			continue
		}
		if seen {
			return "", fmt.Errorf("record has duplicate %s fields", name)
		}
		seen = true
		found = field.Value
	}
	if !seen {
		return "", fmt.Errorf("record is missing %s", name)
	}
	return string(found), nil
}

func writeBytes32(writer io.Writer, data []byte) error {
	if uint64(len(data)) > uint64(^uint32(0)) {
		return fmt.Errorf("byte string is too large")
	}
	if err := binary.Write(writer, binary.BigEndian, uint32(len(data))); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func writeBytes64(writer io.Writer, data []byte) error {
	if err := binary.Write(writer, binary.BigEndian, uint64(len(data))); err != nil {
		return err
	}
	_, err := writer.Write(data)
	return err
}

func readBytes32(reader *bytes.Reader, max int) ([]byte, error) {
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if uint64(length) > uint64(max) || uint64(length) > uint64(reader.Len()) {
		return nil, fmt.Errorf("invalid byte string length %d", length)
	}
	data := make([]byte, int(length))
	_, err := io.ReadFull(reader, data)
	return data, err
}

func readBytes64(reader *bytes.Reader, max int) ([]byte, error) {
	var length uint64
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > uint64(max) || length > uint64(reader.Len()) {
		return nil, fmt.Errorf("invalid byte string length %d", length)
	}
	data := make([]byte, int(length))
	_, err := io.ReadFull(reader, data)
	return data, err
}
