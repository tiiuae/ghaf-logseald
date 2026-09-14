// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package sealer

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"

	"github.com/tiiuae/ghaf-logseald/internal/protocol"
	"github.com/tiiuae/ghaf-logseald/internal/store"
	"github.com/tiiuae/ghaf-logseald/internal/tlsutil"
)

const maxRequestBytes = 2 << 20

type Handler struct {
	store      *store.SealerStore
	slots      chan struct{}
	keyBinding string
}

func NewHandler(state *store.SealerStore, keyBinding string) http.Handler {
	return &Handler{store: state, slots: make(chan struct{}, 1), keyBinding: keyBinding}
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
		return
	}
	if request.URL.Path != "/v1/seal" || request.Method != http.MethodPost {
		http.NotFound(writer, request)
		return
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		http.Error(writer, "authenticated client certificate required", http.StatusUnauthorized)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(writer, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	select {
	case handler.slots <- struct{}{}:
		defer func() { <-handler.slots }()
	default:
		http.Error(writer, "sealer is busy", http.StatusServiceUnavailable)
		return
	}
	peerChainID := tlsutil.ChainID(request.TLS.PeerCertificates[0])
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var sealRequest protocol.SealRequest
	if err := decoder.Decode(&sealRequest); err != nil {
		http.Error(writer, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}
	if err := ensureJSONEOF(decoder); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	response, err := handler.store.Seal(peerChainID, sealRequest)
	if err != nil {
		log.Printf("reject seal request from %s: %v", peerChainID, err)
		http.Error(writer, err.Error(), http.StatusConflict)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set(protocol.KeyBindingHeader, handler.keyBinding)
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		log.Printf("write seal response: %v", err)
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("request contains more than one JSON value")
		}
		return fmt.Errorf("read request trailer: %w", err)
	}
	return nil
}
