// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

const SoftBackend = "soft-ed25519"

var requestIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type SealRequest struct {
	Version   int    `json:"version"`
	RequestID string `json:"request_id"`
	BlockID   string `json:"block_id"`
	Body      string `json:"body"`
}

type SealResponse struct {
	Version          int    `json:"version"`
	RequestID        string `json:"request_id"`
	BlockID          string `json:"block_id"`
	ChainID          string `json:"chain_id"`
	ProducerSequence uint64 `json:"producer_sequence"`
	Epoch            uint64 `json:"epoch"`
	SealSequence     uint64 `json:"seal_sequence"`
	Backend          string `json:"backend"`
	KeyID            string `json:"key_id"`
	PublicKey        string `json:"public_key"`
	Signature        string `json:"signature"`
}

type LedgerEntry struct {
	Request  SealRequest  `json:"request"`
	Response SealResponse `json:"response"`
}

func NewSealRequest(requestID string, encodedBody []byte) (SealRequest, Block, error) {
	if !requestIDPattern.MatchString(requestID) {
		return SealRequest{}, Block{}, fmt.Errorf("invalid request ID")
	}
	block, err := DecodeBlock(encodedBody)
	if err != nil {
		return SealRequest{}, Block{}, err
	}
	id := BlockID(encodedBody)
	return SealRequest{
		Version:   ProtocolVersion,
		RequestID: requestID,
		BlockID:   hex.EncodeToString(id[:]),
		Body:      base64.StdEncoding.EncodeToString(encodedBody),
	}, block, nil
}

func DecodeSealRequest(request SealRequest) (Block, []byte, error) {
	if len(request.Body) > base64.StdEncoding.EncodedLen(MaxBlockBodyBytes) {
		return Block{}, nil, fmt.Errorf("encoded block body is too large")
	}
	if request.Version != ProtocolVersion {
		return Block{}, nil, fmt.Errorf("unsupported request version %d", request.Version)
	}
	if !requestIDPattern.MatchString(request.RequestID) {
		return Block{}, nil, fmt.Errorf("invalid request ID")
	}
	body, err := base64.StdEncoding.DecodeString(request.Body)
	if err != nil {
		return Block{}, nil, fmt.Errorf("decode block body: %w", err)
	}
	if request.Body != base64.StdEncoding.EncodeToString(body) {
		return Block{}, nil, fmt.Errorf("block body base64 is not canonical")
	}
	block, err := DecodeBlock(body)
	if err != nil {
		return Block{}, nil, err
	}
	id := BlockID(body)
	if request.BlockID != hex.EncodeToString(id[:]) {
		return Block{}, nil, fmt.Errorf("request block ID mismatch")
	}
	return block, body, nil
}

func RequestDigest(request SealRequest) ([32]byte, error) {
	_, body, err := DecodeSealRequest(request)
	if err != nil {
		return [32]byte{}, err
	}
	hasher := sha256.New()
	hasher.Write([]byte("logseald-request-v1\x00"))
	hasher.Write([]byte(request.RequestID))
	hasher.Write(body)
	var result [32]byte
	copy(result[:], hasher.Sum(nil))
	return result, nil
}

func NewSealResponse(request SealRequest, block Block, sealSequence uint64, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) (SealResponse, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return SealResponse{}, fmt.Errorf("invalid Ed25519 key")
	}
	keyHash := sha256.Sum256(publicKey)
	response := SealResponse{
		Version:          ProtocolVersion,
		RequestID:        request.RequestID,
		BlockID:          request.BlockID,
		ChainID:          block.ChainID,
		ProducerSequence: block.ProducerSequence,
		Epoch:            0,
		SealSequence:     sealSequence,
		Backend:          SoftBackend,
		KeyID:            hex.EncodeToString(keyHash[:]),
		PublicKey:        base64.StdEncoding.EncodeToString(publicKey),
	}
	payload, err := SealPayload(response)
	if err != nil {
		return SealResponse{}, err
	}
	response.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return response, nil
}

func VerifySealResponse(request SealRequest, response SealResponse, pinned ed25519.PublicKey) (ed25519.PublicKey, error) {
	block, _, err := DecodeSealRequest(request)
	if err != nil {
		return nil, err
	}
	if response.Version != ProtocolVersion || response.RequestID != request.RequestID || response.BlockID != request.BlockID || response.ChainID != block.ChainID || response.ProducerSequence != block.ProducerSequence {
		return nil, fmt.Errorf("seal response does not match request")
	}
	if response.Epoch != 0 || response.SealSequence == 0 || response.Backend != SoftBackend {
		return nil, fmt.Errorf("unsupported seal response backend or sequence")
	}
	publicKey, err := base64.StdEncoding.DecodeString(response.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid response public key")
	}
	if response.PublicKey != base64.StdEncoding.EncodeToString(publicKey) {
		return nil, fmt.Errorf("response public key base64 is not canonical")
	}
	keyHash := sha256.Sum256(publicKey)
	if response.KeyID != hex.EncodeToString(keyHash[:]) {
		return nil, fmt.Errorf("response key ID mismatch")
	}
	if len(pinned) != 0 && !bytes.Equal(pinned, publicKey) {
		return nil, fmt.Errorf("sealer public key changed")
	}
	signature, err := base64.StdEncoding.DecodeString(response.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid response signature")
	}
	if response.Signature != base64.StdEncoding.EncodeToString(signature) {
		return nil, fmt.Errorf("response signature base64 is not canonical")
	}
	payload, err := SealPayload(response)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return nil, fmt.Errorf("seal signature verification failed")
	}
	return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func SealPayload(response SealResponse) ([]byte, error) {
	blockID, err := ParseBlockID(response.BlockID)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString("logseald-seal-v1\x00")
	out.Write(blockID[:])
	for _, value := range []string{response.RequestID, response.ChainID, response.Backend, response.KeyID} {
		if err := writeBytes32(&out, []byte(value)); err != nil {
			return nil, err
		}
	}
	for _, value := range []uint64{response.ProducerSequence, response.Epoch, response.SealSequence} {
		if err := binary.Write(&out, binary.BigEndian, value); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}

func MarshalJSONLine(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
