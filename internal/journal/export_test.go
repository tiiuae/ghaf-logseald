// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
	"io"
	"strings"
	"testing"
)

func TestReadTextAndBinaryJournalFields(t *testing.T) {
	var export bytes.Buffer
	export.WriteString("__CURSOR=cursor-1\n_BOOT_ID=boot-1\nMESSAGE\n")
	if err := binary.Write(&export, binary.LittleEndian, uint64(5)); err != nil {
		t.Fatal(err)
	}
	export.Write([]byte{'a', 0, 'b', '\n', 'c'})
	export.WriteString("\n\n")
	record, err := NewReader(&export).ReadRecord()
	if err != nil {
		t.Fatal(err)
	}
	if len(record.Fields) != 3 || !bytes.Equal(record.Fields[2].Value, []byte{'a', 0, 'b', '\n', 'c'}) {
		t.Fatalf("binary field was not preserved: %#v", record.Fields)
	}
}

func TestOversizeRecordsAreBoundedDigestEvidence(t *testing.T) {
	for _, variant := range []string{"text", "binary", "aggregate", "field-count"} {
		t.Run(variant, func(t *testing.T) {
			var export bytes.Buffer
			export.WriteString("__CURSOR=one\n_BOOT_ID=boot\n")
			switch variant {
			case "text":
				export.WriteString("MESSAGE=" + strings.Repeat("x", protocol.MaxLiveRecordBytes) + "\n")
			case "binary":
				export.WriteString("MESSAGE\n")
				binary.Write(&export, binary.LittleEndian, uint64(protocol.MaxLiveRecordBytes))
				export.Write(bytes.Repeat([]byte{0}, protocol.MaxLiveRecordBytes))
				export.WriteByte('\n')
			case "aggregate":
				for i := 0; i < 5; i++ {
					fmt.Fprintf(&export, "FIELD_%d=%s\n", i, strings.Repeat("a", 64<<10))
				}
			case "field-count":
				for i := 0; i < protocol.MaxFieldsPerRecord; i++ {
					export.WriteString("A=\n")
				}
			}
			export.WriteByte('\n')
			expected := sha256.Sum256(export.Bytes())
			export.WriteString("__CURSOR=two\n_BOOT_ID=boot\nMESSAGE=normal\n\n")
			reader := NewReader(&export)
			record, err := reader.ReadRecord()
			if err != nil {
				t.Fatal(err)
			}
			digest, err := protocol.UniqueField(record, "_LOGSEALD_EXPORT_SHA256")
			if err != nil || digest != hex.EncodeToString(expected[:]) {
				t.Fatalf("digest mismatch: %s %v", digest, err)
			}
			encoded, err := protocol.EncodeRecord(record)
			if err != nil || len(encoded) > protocol.MaxLiveRecordBytes {
				t.Fatalf("invalid bounded marker: %v", err)
			}
			next, err := reader.ReadRecord()
			if err != nil {
				t.Fatal(err)
			}
			cursor, _ := protocol.UniqueField(next, "__CURSOR")
			if cursor != "two" {
				t.Fatalf("reader lost following entry: %s", cursor)
			}
			if _, err := reader.ReadRecord(); err != io.EOF {
				t.Fatalf("EOF = %v", err)
			}
		})
	}
}

func TestOversizeCannotHideMalformedOrDuplicateMetadata(t *testing.T) {
	for _, suffix := range []string{"__CURSOR=other\n\n", "BINARY\n\x01\x00", "BINARY\n\xff\xff\xff\xff\xff\xff\xff\xff"} {
		export := "__CURSOR=one\n_BOOT_ID=boot\nMESSAGE=" + strings.Repeat("x", protocol.MaxLiveRecordBytes) + "\n" + suffix
		if _, err := NewReader(strings.NewReader(export)).ReadRecord(); err == nil {
			t.Fatal("malformed export accepted")
		}
	}
}

func TestRejectTruncatedBinaryJournalField(t *testing.T) {
	var export bytes.Buffer
	export.WriteString("MESSAGE\n")
	if err := binary.Write(&export, binary.LittleEndian, uint64(8)); err != nil {
		t.Fatal(err)
	}
	export.WriteString("short")
	if _, err := NewReader(&export).ReadRecord(); err == nil {
		t.Fatal("truncated binary field was accepted")
	}
}
