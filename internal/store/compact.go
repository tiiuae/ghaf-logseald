// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/tiiuae/ghaf-logseald/internal/durable"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

const maxCompactChains = 256
const maxCompactBytes = 1 << 20

type compactState struct {
	Version  int                              `json:"version"`
	Sequence uint64                           `json:"sequence"`
	Heads    map[string]protocol.SealResponse `json:"heads"`
}

type compactCheckpoint struct {
	State     compactState `json:"state"`
	Signature string       `json:"signature"`
}

func compactPayload(state compactState) ([]byte, error) {
	data, err := json.Marshal(state)
	return append([]byte("logseald-compact-state-v1\x00"), data...), err
}

func (state *SealerStore) compactPath() string { return filepath.Join(state.root, "checkpoint.json") }

func (state *SealerStore) ensureCompactFormat() error {
	path := filepath.Join(state.root, "compact-format")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return durable.WriteFile(path, []byte("1\n"), 0o640)
	}
	if err != nil {
		return err
	}
	if string(data) != "1\n" {
		return fmt.Errorf("invalid compact format marker")
	}
	return nil
}

func (state *SealerStore) loadCompact() (bool, error) {
	info, err := os.Stat(state.compactPath())
	if errors.Is(err, os.ErrNotExist) {
		if _, markerErr := os.Stat(filepath.Join(state.root, "compact-format")); !errors.Is(markerErr, os.ErrNotExist) {
			return false, fmt.Errorf("compact checkpoint is missing; refusing to reset chains")
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxCompactBytes || info.Size() > state.limits.Bytes/2 {
		return false, ErrCapacity
	}
	data, err := readArtifact(state.compactPath())
	if err != nil {
		return false, err
	}
	var checkpoint compactCheckpoint
	if err := decodeStrictJSON(data, &checkpoint); err != nil {
		return false, err
	}
	payload, err := compactPayload(checkpoint.State)
	if err != nil {
		return false, err
	}
	signature, err := base64.StdEncoding.DecodeString(checkpoint.Signature)
	if err != nil || !ed25519.Verify(state.publicKey, payload, signature) {
		return false, fmt.Errorf("compact checkpoint signature is invalid")
	}
	if checkpoint.State.Version != 1 || len(checkpoint.State.Heads) > maxCompactChains || len(checkpoint.State.Heads) > state.limits.Entries {
		return false, fmt.Errorf("invalid compact checkpoint version or chain count")
	}
	var latest uint64
	sequences := make(map[uint64]bool)
	for chain, receipt := range checkpoint.State.Heads {
		if chain != receipt.ChainID {
			return false, fmt.Errorf("checkpoint chain identity mismatch")
		}
		if _, err := protocol.VerifyReceipt(receipt, state.publicKey); err != nil {
			return false, err
		}
		if sequences[receipt.SealSequence] {
			return false, fmt.Errorf("duplicate global sequence in checkpoint")
		}
		sequences[receipt.SealSequence] = true
		if receipt.SealSequence > latest {
			latest = receipt.SealSequence
		}
	}
	if checkpoint.State.Sequence != latest || latest == math.MaxUint64 {
		return false, fmt.Errorf("invalid compact global sequence")
	}
	state.compact = &checkpoint.State
	state.nextSeal = latest + 1
	return true, nil
}

func (state *SealerStore) saveCompact(next compactState) error {
	payload, err := compactPayload(next)
	if err != nil {
		return err
	}
	checkpoint := compactCheckpoint{State: next, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(state.privateKey, payload))}
	data, err := protocol.MarshalJSONLine(checkpoint)
	if err != nil {
		return err
	}
	// Reserve space for both generations during atomic replacement.
	if len(data) > maxCompactBytes || int64(len(data)) > state.limits.Bytes/2 {
		return ErrCapacity
	}
	if err := durable.WriteFile(state.compactPath(), data, 0o640); err != nil {
		state.writeFailed = true
		return err
	}
	state.compact = &next
	state.nextSeal = next.Sequence + 1
	return nil
}

func (state *SealerStore) migrateCompact() error {
	next := compactState{Version: 1, Sequence: state.nextSeal - 1, Heads: make(map[string]protocol.SealResponse)}
	for _, remembered := range state.requests {
		receipt := remembered.Response
		if receipt.ProducerSequence > next.Heads[receipt.ChainID].ProducerSequence {
			next.Heads[receipt.ChainID] = receipt
		}
	}
	if len(next.Heads) > maxCompactChains || len(next.Heads) > state.limits.Entries {
		return ErrCapacity
	}
	if err := state.saveCompact(next); err != nil {
		return err
	}
	if err := state.ensureCompactFormat(); err != nil {
		return err
	}
	if err := state.cleanLedger(); err != nil {
		return err
	}
	state.heads, state.requests = nil, nil
	state.used = 0
	return nil
}

func (state *SealerStore) cleanLedger() error {
	names, _, err := artifactNames(state.ledgerDir(), state.limits.Entries+1)
	if err != nil {
		return err
	}
	for _, name := range names {
		var sequence uint64
		if _, err := fmt.Sscanf(name, "%020d.json", &sequence); err != nil || sequence == 0 || name != filepath.Base(artifactPath(state.ledgerDir(), sequence)) || sequence > state.compact.Sequence {
			return fmt.Errorf("unexpected ledger artifact during migration: %s", name)
		}
	}
	for _, name := range names {
		if err := durable.Remove(filepath.Join(state.ledgerDir(), name)); err != nil {
			return err
		}
	}
	return nil
}

func (state *SealerStore) sealCompact(peer string, request protocol.SealRequest) (protocol.SealResponse, error) {
	if len(request.Body) > ((protocol.MaxLiveBlockBytes+2)/3)*4 {
		return protocol.SealResponse{}, fmt.Errorf("live block exceeds size limit")
	}
	block, body, err := protocol.DecodeSealRequest(request)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	if len(body) > protocol.MaxLiveBlockBytes || block.ChainID != peer {
		return protocol.SealResponse{}, fmt.Errorf("invalid live block size or authenticated chain")
	}
	previous, exists := state.compact.Heads[peer]
	if exists && block.ProducerSequence == previous.ProducerSequence {
		if request.RequestID != previous.RequestID || request.BlockID != previous.BlockID {
			return protocol.SealResponse{}, fmt.Errorf("conflicting retry")
		}
		return previous, nil
	}
	if !exists && (len(state.compact.Heads) >= maxCompactChains || len(state.compact.Heads) >= state.limits.Entries) {
		return protocol.SealResponse{}, ErrCapacity
	}
	if previous.ProducerSequence == math.MaxUint64 || state.nextSeal == math.MaxUint64 {
		return protocol.SealResponse{}, fmt.Errorf("sequence exhausted")
	}
	var previousID [32]byte
	if exists {
		previousID, err = protocol.ParseBlockID(previous.BlockID)
		if err != nil {
			return protocol.SealResponse{}, err
		}
	}
	if block.ProducerSequence != previous.ProducerSequence+1 || block.PreviousBlockID != previousID {
		return protocol.SealResponse{}, fmt.Errorf("block does not extend the durable chain head")
	}
	for _, receipt := range state.compact.Heads {
		if receipt.RequestID == request.RequestID {
			return protocol.SealResponse{}, fmt.Errorf("request ID conflicts with retained receipt")
		}
	}
	response, err := protocol.NewSealResponse(request, block, state.nextSeal, state.publicKey, state.privateKey)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	next := compactState{Version: 1, Sequence: state.nextSeal, Heads: make(map[string]protocol.SealResponse, len(state.compact.Heads)+1)}
	for chain, receipt := range state.compact.Heads {
		next.Heads[chain] = receipt
	}
	next.Heads[peer] = response
	if err := state.saveCompact(next); err != nil {
		return protocol.SealResponse{}, err
	}
	return response, nil
}

func (state *SealerStore) CompactChains() (int, bool) {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.compact == nil {
		return 0, false
	}
	return len(state.compact.Heads), true
}
