// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package producer

import (
	"fmt"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
	"github.com/tiiuae/ghaf-logseald/internal/store"
	"strings"
	"testing"
)

func TestByteBatchingAndFinalQueueSlot(t *testing.T) {
	root := t.TempDir()
	chain := "spki-sha256:" + strings.Repeat("0", 64)
	engine, err := Open(root, chain, "vm", 256, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		record := protocol.Record{Fields: []protocol.Field{
			{Name: "__CURSOR", Value: []byte(fmt.Sprint(i))},
			{Name: "_BOOT_ID", Value: []byte("boot")},
			{Name: "MESSAGE", Value: []byte(strings.Repeat("x", 255<<10))},
		}}
		if err := engine.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	if engine.QueueDepth() != 1 || engine.CanRead() || !engine.HasBatch() {
		t.Fatal("byte flush did not retain the next bounded batch at capacity")
	}
	state, err := store.OpenProducer(root, chain, "vm")
	if err != nil {
		t.Fatal(err)
	}
	if state.LastCursor() != "2" {
		t.Fatalf("cursor advanced past durable block: %s", state.LastCursor())
	}
	request, found, err := state.Pending()
	if err != nil || !found {
		t.Fatal(err)
	}
	_, body, err := protocol.DecodeSealRequest(request)
	if err != nil || len(body) > protocol.MaxLiveBlockBytes {
		t.Fatalf("invalid live block: %v", err)
	}
}

func TestBootBoundaryFlush(t *testing.T) {
	engine, err := Open(t.TempDir(), "spki-sha256:"+strings.Repeat("0", 64), "vm", 256, 64)
	if err != nil {
		t.Fatal(err)
	}
	for _, boot := range []string{"old", "new"} {
		if err := engine.Append(protocol.Record{Fields: []protocol.Field{
			{Name: "__CURSOR", Value: []byte(boot)}, {Name: "_BOOT_ID", Value: []byte(boot)},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	if engine.QueueDepth() != 1 || !engine.HasBatch() {
		t.Fatal("boot boundary lost a record")
	}
	if err := engine.Flush(); err != nil {
		t.Fatal(err)
	}
}
