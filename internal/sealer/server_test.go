// SPDX-FileCopyrightText: 2022-2026 TII (SSRC) and the Ghaf contributors
// SPDX-License-Identifier: Apache-2.0

package sealer

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/tiiuae/ghaf-logseald/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type countingBody struct {
	io.Reader
	bytes int
}

func (body *countingBody) Read(data []byte) (int, error) {
	n, err := body.Reader.Read(data)
	body.bytes += n
	return n, err
}
func (body *countingBody) Close() error { return nil }

func TestRequestAdmissionBeforeBodyRead(t *testing.T) {
	state, err := store.OpenSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(state, "").(*Handler)
	handler.slots <- struct{}{}
	body := &countingBody{Reader: strings.NewReader("{}")}
	request := httptest.NewRequest(http.MethodPost, "/v1/seal", body)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{RawSubjectPublicKeyInfo: []byte("test")}}}
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || body.bytes != 0 {
		t.Fatalf("concurrent body admitted: status %d read %d", response.Code, body.bytes)
	}
	<-handler.slots
	body = &countingBody{Reader: strings.NewReader("{\"body\":\"" + strings.Repeat("a", maxRequestBytes) + "\"}")}
	request.Body = body
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusOK || body.bytes > maxRequestBytes+1 || state.EntryCount() != 0 {
		t.Fatalf("oversized body admitted: status %d read %d", response.Code, body.bytes)
	}
	request = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("health check broken after oversized request")
	}
}
