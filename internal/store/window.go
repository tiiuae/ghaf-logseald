// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tiiuae/ghaf-logseald/internal/durable"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

func (state *ProducerStore) ExpiredCount() uint64 { return state.boundary.ProducerSequence }

func (state *ProducerStore) TotalSealed() uint64 {
	return state.boundary.ProducerSequence + uint64(len(state.artifacts))
}

func (state *ProducerStore) loadBoundary() error {
	data, err := readArtifact(filepath.Join(state.root, "boundary.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if state.pinnedKey == nil {
		return fmt.Errorf("window boundary has no pinned signing key")
	}
	if err := decodeStrictJSON(data, &state.boundary); err != nil {
		return err
	}
	if _, err := protocol.VerifyReceipt(state.boundary, state.pinnedKey); err != nil {
		return err
	}
	if state.boundary.ChainID != state.chainID {
		return fmt.Errorf("window boundary belongs to another producer")
	}
	return nil
}

func (state *ProducerStore) cleanExpired() error {
	if state.boundary.ProducerSequence == 0 {
		return nil
	}
	names, _, err := artifactNames(state.sealedDir(), state.limits.Entries+1)
	if err != nil {
		return err
	}
	for _, name := range names {
		path := filepath.Join(state.sealedDir(), name)
		if path > artifactPath(state.sealedDir(), state.boundary.ProducerSequence) {
			break
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if err := durable.Remove(path); err != nil {
			return err
		}
		state.used -= info.Size()
	}
	return nil
}

func (state *ProducerStore) trimWindow(reserve int64, enqueue bool) error {
	if state.limits.WindowEntries == 0 {
		return nil
	}
	if reserve > state.limits.Bytes {
		return ErrCapacity
	}
	for len(state.artifacts) > 1 {
		full := enqueue && (reserve > state.limits.Bytes-state.used-state.reserved || len(state.artifacts)+len(state.queued) >= state.limits.Entries)
		if !full && len(state.artifacts) <= state.limits.WindowEntries {
			break
		}
		sequence := state.boundary.ProducerSequence + 1
		summary, found := state.artifacts[sequence]
		if !found {
			return fmt.Errorf("cannot expire a missing sealed block")
		}
		path := artifactPath(state.sealedDir(), sequence)
		data, err := readArtifact(path)
		if err != nil {
			return err
		}
		var entry protocol.LedgerEntry
		if err := decodeStrictJSON(data, &entry); err != nil {
			return err
		}
		if _, err := protocol.VerifySealResponse(entry.Request, entry.Response, state.pinnedKey); err != nil {
			return err
		}
		digest, err := protocol.RequestDigest(entry.Request)
		if err != nil || digest != summary.Digest {
			return fmt.Errorf("sealed block changed before expiry")
		}
		boundary, err := protocol.MarshalJSONLine(entry.Response)
		if err != nil {
			return err
		}
		// Commit the authenticated boundary before deleting its predecessor evidence.
		if err := durable.WriteFile(filepath.Join(state.root, "boundary.json"), boundary, 0o640); err != nil {
			state.writeFailed = true
			return err
		}
		state.boundary = entry.Response
		if err := durable.Remove(path); err != nil {
			state.writeFailed = true
			return err
		}
		delete(state.artifacts, sequence)
		state.used -= summary.Size
	}
	return nil
}
