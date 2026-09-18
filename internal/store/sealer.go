// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/tiiuae/ghaf-logseald/internal/durable"
	"github.com/tiiuae/ghaf-logseald/internal/protocol"
)

type chainHead struct {
	Sequence uint64
	BlockID  [32]byte
	Bytes    int64
}

type rememberedRequest struct {
	Digest   [32]byte
	Response protocol.SealResponse
}

type SealerStore struct {
	mu          sync.Mutex
	root        string
	publicKey   ed25519.PublicKey
	privateKey  ed25519.PrivateKey
	nextSeal    uint64
	heads       map[string]chainHead
	requests    map[string]rememberedRequest
	limits      Limits
	used        int64
	writeFailed bool
	compact     *compactState
	readOnly    bool
}

func OpenSealer(root string, supplied ...Limits) (*SealerStore, error) {
	return openSealer(root, false, supplied...)
}

func ReadSealer(root string, supplied ...Limits) (*SealerStore, error) {
	return openSealer(root, true, supplied...)
}

func openSealer(root string, readOnly bool, supplied ...Limits) (*SealerStore, error) {
	limits, err := chooseLimits(SealerLimits(), supplied)
	if err != nil {
		return nil, err
	}
	if root == "" {
		return nil, fmt.Errorf("sealer state directory is required")
	}
	if !readOnly {
		if err := os.MkdirAll(root, 0o750); err != nil {
			return nil, err
		}
	}
	var unlock func()
	if readOnly {
		unlock, err = Lock(root, false)
	} else {
		unlock, err = lockMutation(root)
	}
	if err != nil {
		return nil, err
	}
	defer unlock()
	state := &SealerStore{
		root:     root,
		nextSeal: 1,
		heads:    make(map[string]chainHead),
		requests: make(map[string]rememberedRequest),
		limits:   limits,
		readOnly: readOnly,
	}
	if !readOnly {
		if err := os.MkdirAll(state.ledgerDir(), 0o750); err != nil {
			return nil, fmt.Errorf("create sealer state directory: %w", err)
		}
		for _, dir := range []string{root, state.ledgerDir()} {
			if err := durable.CleanTemporary(dir); err != nil {
				return nil, err
			}
		}
	}
	if err := state.loadOrCreateKey(); err != nil {
		return nil, err
	}
	if found, err := state.loadCompact(); err != nil {
		return nil, err
	} else if found {
		if !readOnly {
			if err := state.ensureCompactFormat(); err != nil {
				return nil, err
			}
			if err := state.cleanLedger(); err != nil {
				return nil, err
			}
		}
		return state, nil
	}
	state.used, err = evidenceBytes(limits, state.ledgerDir())
	if err != nil {
		return nil, err
	}
	if err := state.loadLedger(); err != nil {
		return nil, err
	}
	if limits.Compact && !readOnly {
		if err := state.migrateCompact(); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func (state *SealerStore) loadOrCreateKey() error {
	key, err := os.ReadFile(state.keyPath())
	if errors.Is(err, os.ErrNotExist) {
		if state.readOnly {
			return fmt.Errorf("sealer signing key is missing")
		}
		entries, err := os.ReadDir(state.ledgerDir())
		if err != nil {
			return err
		}
		if len(entries) != 0 {
			return fmt.Errorf("refusing to replace a missing signing key with existing evidence")
		}
		for _, name := range []string{"checkpoint.json", "compact-format"} {
			if _, err := os.Lstat(filepath.Join(state.root, name)); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("refusing to replace a missing compact-state signing key")
			}
		}
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate sealer key: %w", err)
		}
		if err := durable.WriteFile(state.keyPath(), privateKey, 0o600); err != nil {
			return fmt.Errorf("persist sealer key: %w", err)
		}
		state.publicKey, state.privateKey = publicKey, privateKey
		return nil
	}
	if err != nil {
		return fmt.Errorf("read sealer key: %w", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid sealer private key length")
	}
	state.privateKey = ed25519.PrivateKey(key)
	state.publicKey = append(ed25519.PublicKey(nil), state.privateKey.Public().(ed25519.PublicKey)...)
	return nil
}

func (state *SealerStore) loadLedger() error {
	return forEachArtifact(state.ledgerDir(), state.limits.Entries, func(path string, data []byte) error {
		var entry protocol.LedgerEntry
		if err := decodeStrictJSON(data, &entry); err != nil {
			return fmt.Errorf("decode ledger entry %s: %w", path, err)
		}
		sequence := state.nextSeal
		if path != artifactPath(state.ledgerDir(), sequence) {
			return fmt.Errorf("ledger filename mismatch or missing seal sequence %d", sequence)
		}
		block, body, err := protocol.DecodeSealRequest(entry.Request)
		if err != nil {
			return fmt.Errorf("validate ledger request %d: %w", sequence, err)
		}
		if _, err := protocol.VerifySealResponse(entry.Request, entry.Response, state.publicKey); err != nil {
			return fmt.Errorf("verify ledger response %d: %w", sequence, err)
		}
		if entry.Response.SealSequence != sequence {
			return fmt.Errorf("ledger response sequence mismatch")
		}
		head := state.heads[block.ChainID]
		if block.ProducerSequence != head.Sequence+1 || block.PreviousBlockID != head.BlockID {
			return fmt.Errorf("ledger chain %s is discontinuous at producer sequence %d", block.ChainID, block.ProducerSequence)
		}
		id := protocol.BlockID(body)
		if err := state.capacity(head, int64(len(data)), false); err != nil {
			return err
		}
		state.heads[block.ChainID] = chainHead{Sequence: block.ProducerSequence, BlockID: id, Bytes: head.Bytes + int64(len(data))}
		digest, err := protocol.RequestDigest(entry.Request)
		if err != nil {
			return err
		}
		if _, duplicate := state.requests[entry.Request.RequestID]; duplicate {
			return fmt.Errorf("duplicate request ID in ledger")
		}
		state.requests[entry.Request.RequestID] = rememberedRequest{Digest: digest, Response: entry.Response}
		state.nextSeal++
		return nil
	})
}

func (state *SealerStore) capacity(head chainHead, bytes int64, writing bool) error {
	if len(state.requests) >= state.limits.Entries ||
		(state.limits.ChainEntries > 0 && head.Sequence >= uint64(state.limits.ChainEntries)) ||
		(state.limits.ChainBytes > 0 && bytes > state.limits.ChainBytes-head.Bytes) ||
		(writing && bytes > state.limits.Bytes-state.used) {
		return ErrCapacity
	}
	return nil
}

// Seal validates and durably records one request. Identical retries return the
// original response without consuming another global sequence number.
func (state *SealerStore) Seal(peerChainID string, request protocol.SealRequest) (protocol.SealResponse, error) {
	state.mu.Lock()
	defer state.mu.Unlock()
	unlock, err := lockMutation(state.root)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	defer unlock()
	if state.readOnly {
		return protocol.SealResponse{}, fmt.Errorf("sealer state is read only")
	}
	if state.writeFailed {
		return protocol.SealResponse{}, fmt.Errorf("ledger write failed; restart to recover durable state")
	}
	if state.compact != nil {
		return state.sealCompact(peerChainID, request)
	}
	if _, retry := state.requests[request.RequestID]; !retry && len(request.Body) > ((protocol.MaxLiveBlockBytes+2)/3)*4 {
		return protocol.SealResponse{}, fmt.Errorf("live block exceeds size limit")
	}

	block, body, err := protocol.DecodeSealRequest(request)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	digest, err := protocol.RequestDigest(request)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	if remembered, found := state.requests[request.RequestID]; found {
		if remembered.Digest != digest || remembered.Response.ChainID != peerChainID {
			return protocol.SealResponse{}, fmt.Errorf("request ID was reused with different content or identity")
		}
		return remembered.Response, nil
	}
	if len(body) > protocol.MaxLiveBlockBytes {
		return protocol.SealResponse{}, fmt.Errorf("live block exceeds size limit")
	}
	if block.ChainID != peerChainID {
		return protocol.SealResponse{}, fmt.Errorf("block chain ID does not match authenticated client identity")
	}
	head := state.heads[peerChainID]
	if block.ProducerSequence != head.Sequence+1 {
		return protocol.SealResponse{}, fmt.Errorf("expected producer sequence %d, got %d", head.Sequence+1, block.ProducerSequence)
	}
	if block.PreviousBlockID != head.BlockID {
		return protocol.SealResponse{}, fmt.Errorf("producer predecessor does not match sealed chain head")
	}
	response, err := protocol.NewSealResponse(request, block, state.nextSeal, state.publicKey, state.privateKey)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	entry := protocol.LedgerEntry{Request: request, Response: response}
	data, err := protocol.MarshalJSONLine(entry)
	if err != nil {
		return protocol.SealResponse{}, err
	}
	if err := state.capacity(head, int64(len(data)), true); err != nil {
		return protocol.SealResponse{}, err
	}
	if err := durable.WriteFile(artifactPath(state.ledgerDir(), state.nextSeal), data, 0o640); err != nil {
		state.writeFailed = true
		return protocol.SealResponse{}, fmt.Errorf("persist sealer ledger entry: %w", err)
	}
	id := protocol.BlockID(body)
	state.heads[peerChainID] = chainHead{Sequence: block.ProducerSequence, BlockID: id, Bytes: head.Bytes + int64(len(data))}
	state.requests[request.RequestID] = rememberedRequest{Digest: digest, Response: response}
	state.nextSeal++
	state.used += int64(len(data))
	return response, nil
}

func (state *SealerStore) PublicKey() ed25519.PublicKey {
	state.mu.Lock()
	defer state.mu.Unlock()
	return append(ed25519.PublicKey(nil), state.publicKey...)
}

func (state *SealerStore) LedgerDirectory() string { return state.ledgerDir() }
func (state *SealerStore) EntryCount() uint64 {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.nextSeal - 1
}
func (state *SealerStore) ledgerDir() string { return filepath.Join(state.root, "ledger") }
func (state *SealerStore) keyPath() string   { return filepath.Join(state.root, "sealer.key") }
