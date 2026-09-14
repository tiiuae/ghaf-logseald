// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const (
	KeyBindingHeader = "Logseald-Key-Binding"

	bindingRSA            = "rsa-pkcs1v15-sha256"
	bindingECDSA          = "ecdsa-asn1-sha256"
	bindingEd25519        = "ed25519"
	maxBindingHeaderBytes = 16 << 10
)

// The GIVC identity binds an independent signing key so transport certificate
// rotation does not require replacing historical log-signing trust.
type KeyBinding struct {
	Version            int    `json:"version"`
	Backend            string `json:"backend"`
	SigningKeyID       string `json:"signing_key_id"`
	SigningPublicKey   string `json:"signing_public_key"`
	TransportKeyID     string `json:"transport_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

func NewKeyBinding(certificate *x509.Certificate, transportSigner crypto.Signer, signingKey ed25519.PublicKey) (KeyBinding, error) {
	if certificate == nil || transportSigner == nil {
		return KeyBinding{}, fmt.Errorf("GIVC certificate and signer are required")
	}
	if len(signingKey) != ed25519.PublicKeySize {
		return KeyBinding{}, fmt.Errorf("invalid Ed25519 signing public key")
	}
	transportPublicKey, err := x509.MarshalPKIXPublicKey(transportSigner.Public())
	if err != nil {
		return KeyBinding{}, fmt.Errorf("marshal GIVC signer public key: %w", err)
	}
	if !bytes.Equal(transportPublicKey, certificate.RawSubjectPublicKeyInfo) {
		return KeyBinding{}, fmt.Errorf("GIVC signer does not match certificate")
	}
	algorithm, err := bindingAlgorithm(certificate.PublicKey)
	if err != nil {
		return KeyBinding{}, err
	}
	signingKeyHash := sha256.Sum256(signingKey)
	binding := KeyBinding{
		Version:            ProtocolVersion,
		Backend:            SoftBackend,
		SigningKeyID:       hex.EncodeToString(signingKeyHash[:]),
		SigningPublicKey:   base64.StdEncoding.EncodeToString(signingKey),
		TransportKeyID:     CertificateKeyID(certificate),
		SignatureAlgorithm: algorithm,
	}
	payload, err := keyBindingPayload(binding)
	if err != nil {
		return KeyBinding{}, err
	}
	signature, err := signKeyBinding(transportSigner, algorithm, payload)
	if err != nil {
		return KeyBinding{}, err
	}
	binding.Signature = base64.StdEncoding.EncodeToString(signature)
	return binding, nil
}

func VerifyKeyBinding(binding KeyBinding, certificate *x509.Certificate) (ed25519.PublicKey, error) {
	if certificate == nil {
		return nil, fmt.Errorf("authenticated GIVC certificate is required")
	}
	if binding.Version != ProtocolVersion || binding.Backend != SoftBackend {
		return nil, fmt.Errorf("unsupported key binding version or backend")
	}
	publicKey, err := base64.StdEncoding.DecodeString(binding.SigningPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid bound signing public key")
	}
	if binding.SigningPublicKey != base64.StdEncoding.EncodeToString(publicKey) {
		return nil, fmt.Errorf("bound signing public key base64 is not canonical")
	}
	keyHash := sha256.Sum256(publicKey)
	if binding.SigningKeyID != hex.EncodeToString(keyHash[:]) {
		return nil, fmt.Errorf("bound signing key ID mismatch")
	}
	if binding.TransportKeyID != CertificateKeyID(certificate) {
		return nil, fmt.Errorf("key binding does not match authenticated GIVC identity")
	}
	algorithm, err := bindingAlgorithm(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	if binding.SignatureAlgorithm != algorithm {
		return nil, fmt.Errorf("key binding signature algorithm mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(binding.Signature)
	if err != nil || len(signature) == 0 {
		return nil, fmt.Errorf("invalid key binding signature")
	}
	if binding.Signature != base64.StdEncoding.EncodeToString(signature) {
		return nil, fmt.Errorf("key binding signature base64 is not canonical")
	}
	payload, err := keyBindingPayload(binding)
	if err != nil {
		return nil, err
	}
	if err := verifyKeyBindingSignature(certificate.PublicKey, algorithm, payload, signature); err != nil {
		return nil, err
	}
	return ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func EncodeKeyBindingHeader(binding KeyBinding) (string, error) {
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("encode key binding: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func DecodeKeyBindingHeader(value string) (KeyBinding, error) {
	if value == "" || len(value) > maxBindingHeaderBytes {
		return KeyBinding{}, fmt.Errorf("missing or oversized key binding header")
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || value != base64.RawURLEncoding.EncodeToString(data) {
		return KeyBinding{}, fmt.Errorf("invalid key binding header encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var binding KeyBinding
	if err := decoder.Decode(&binding); err != nil {
		return KeyBinding{}, fmt.Errorf("decode key binding: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return KeyBinding{}, fmt.Errorf("key binding contains trailing data")
	}
	return binding, nil
}

func CertificateKeyID(certificate *x509.Certificate) string {
	hash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return "spki-sha256:" + hex.EncodeToString(hash[:])
}

func bindingAlgorithm(publicKey any) (string, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return bindingRSA, nil
	case *ecdsa.PublicKey:
		return bindingECDSA, nil
	case ed25519.PublicKey:
		return bindingEd25519, nil
	default:
		return "", fmt.Errorf("unsupported GIVC public key type %T", publicKey)
	}
}

func signKeyBinding(signer crypto.Signer, algorithm string, payload []byte) ([]byte, error) {
	if algorithm == bindingEd25519 {
		signature, err := signer.Sign(rand.Reader, payload, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("sign key binding with GIVC key: %w", err)
		}
		return signature, nil
	}
	digest := sha256.Sum256(payload)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("sign key binding with GIVC key: %w", err)
	}
	return signature, nil
}

func verifyKeyBindingSignature(publicKey any, algorithm string, payload, signature []byte) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		digest := sha256.Sum256(payload)
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
			return fmt.Errorf("verify GIVC key binding signature: %w", err)
		}
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(payload)
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return fmt.Errorf("verify GIVC key binding signature: invalid ECDSA signature")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(key, payload, signature) {
			return fmt.Errorf("verify GIVC key binding signature: invalid Ed25519 signature")
		}
	default:
		return fmt.Errorf("unsupported GIVC public key type %T", publicKey)
	}
	if expected, err := bindingAlgorithm(publicKey); err != nil || expected != algorithm {
		return fmt.Errorf("GIVC key binding signature algorithm mismatch")
	}
	return nil
}

func keyBindingPayload(binding KeyBinding) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString("logseald-key-binding-v1\x00")
	if err := binary.Write(&out, binary.BigEndian, uint16(binding.Version)); err != nil {
		return nil, err
	}
	for _, value := range []string{
		binding.Backend,
		binding.SigningKeyID,
		binding.SigningPublicKey,
		binding.TransportKeyID,
		binding.SignatureAlgorithm,
	} {
		if err := writeBytes32(&out, []byte(value)); err != nil {
			return nil, err
		}
	}
	return out.Bytes(), nil
}
