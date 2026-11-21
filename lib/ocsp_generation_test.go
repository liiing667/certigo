// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func newOCSPTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	return cert, key
}

func newOCSPTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		DNSNames:     []string{"leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	return cert
}

func newOCSPTestResponder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, withEKU bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate responder key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test OCSP Responder"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if withEKU {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create responder certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse responder certificate: %v", err)
	}
	return cert, key
}

func createOCSPTestResponse(t *testing.T, issuer, responder *x509.Certificate, signer *ecdsa.PrivateKey, template ocsp.Response) []byte {
	t.Helper()

	der, err := ocsp.CreateResponse(issuer, responder, template, signer)
	if err != nil {
		t.Fatalf("failed to create OCSP response: %v", err)
	}
	return der
}

func TestOCSPPOSTRequestContainsDERRequest(t *testing.T) {
	encoded := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}

	req, err := buildOCSPwithPOST("https://example.com/ocsp", encoded)
	if err != nil {
		t.Fatalf("buildOCSPwithPOST failed: %v", err)
	}
	if req.Method != "POST" {
		t.Fatalf("expected POST request, got %q", req.Method)
	}
	if req.Body == nil {
		t.Fatal("POST request has no body")
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read POST body: %v", err)
	}
	if !bytes.Equal(body, encoded) {
		t.Fatalf("POST body does not contain the DER OCSP request: got %x, want %x", body, encoded)
	}

	if got := req.Header.Get("Content-Type"); got != "application/ocsp-request" {
		t.Fatalf("unexpected Content-Type: %q", got)
	}
}

func TestOCSPResponseSelectionPrefersRevocation(t *testing.T) {
	now := time.Now()
	good := &ocsp.Response{
		Status:     ocsp.Good,
		ThisUpdate: now,
		ProducedAt: now,
		Raw:        []byte("good"),
	}
	revoked := &ocsp.Response{
		Status:     ocsp.Revoked,
		ThisUpdate: now.Add(-time.Hour),
		ProducedAt: now.Add(-time.Hour),
		Raw:        []byte("revoked"),
	}

	if !preferOCSPResponse(good, revoked) {
		t.Fatal("revocation status must take precedence over a newer good response")
	}
	if preferOCSPResponse(revoked, good) {
		t.Fatal("good status must not replace a revoked response")
	}
}

func TestOCSPResponseSelectionUsesNewestGeneration(t *testing.T) {
	now := time.Now()
	older := &ocsp.Response{
		Status:     ocsp.Good,
		ThisUpdate: now.Add(-time.Hour),
		ProducedAt: now.Add(-time.Hour),
		Raw:        []byte("older"),
	}
	newer := &ocsp.Response{
		Status:     ocsp.Good,
		ThisUpdate: now,
		ProducedAt: now,
		Raw:        []byte("newer"),
	}

	if !preferOCSPResponse(older, newer) {
		t.Fatal("newer OCSP response generation should be preferred")
	}
	if preferOCSPResponse(newer, older) {
		t.Fatal("older OCSP response generation must not replace a newer one")
	}
}

func TestOCSPResponderValidityUsesResponseTime(t *testing.T) {
	now := time.Now()
	responder := &x509.Certificate{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
	}

	if !certWasValidAt(responder, now) {
		t.Fatal("responder should be valid when the response is produced")
	}
	if certWasValidAt(responder, now.Add(24*time.Hour)) {
		t.Fatal("responder should not be valid for a response produced after expiry")
	}
}

func TestCheckOCSPRejectsStaleGoodResponseAfterBadSignature(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	staleLeaf := newOCSPTestLeaf(t, ca, caKey, 101)
	now := time.Now()

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong signing key: %v", err)
	}
	badSignature := createOCSPTestResponse(t, ca, ca, wrongKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})
	staleGood := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: staleLeaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		if atomic.AddInt32(&requests, 1) <= 2 {
			_, _ = w.Write(badSignature)
			return
		}
		// After the bad-signature response, the responder serves a validly
		// signed response for an old certificate serial. It must never be
		// reported as good for the current certificate.
		_, _ = w.Write(staleGood)
	}))
	defer server.Close()
	leaf.OCSPServer = []string{server.URL}

	status, err := checkOCSP([]*x509.Certificate{leaf, ca}, nil)
	if err == nil {
		t.Fatalf("expected the stale OCSP response to be rejected, got status %v", status)
	}
	if status != nil {
		t.Fatalf("expected no OCSP status on failure, got %v", status)
	}
	if stage := ocspValidationStage(err); stage != "serial" {
		t.Fatalf("expected serial-number rejection, got stage %q: %v", stage, err)
	} else {
		t.Logf("stale serial rejected at stage %s: %v", stage, err)
	}
}

func TestOCSPBadSignatureRejected(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong signing key: %v", err)
	}
	response := createOCSPTestResponse(t, ca, ca, wrongKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	if _, err := parseAndVerifyOCSPResponse(response, leaf, ca); err == nil {
		t.Fatal("expected a bad OCSP signature to be rejected")
	} else if stage := ocspValidationStage(err); stage != "signature" {
		t.Fatalf("expected signature-stage rejection, got %q: %v", stage, err)
	} else {
		t.Logf("bad responder signature rejected at stage %s: %v", stage, err)
	}
}

func TestOCSPUnknownStatusPreserved(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	response := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Unknown,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	status, err := checkOCSP([]*x509.Certificate{leaf, ca}, response)
	if err != nil {
		t.Fatalf("checkOCSP rejected a valid unknown response: %v", err)
	}
	if status.Status != ocsp.Unknown {
		t.Fatalf("expected unknown status, got %d", status.Status)
	}
	t.Logf("legal unknown OCSP conclusion preserved for serial %v", leaf.SerialNumber)
}

func TestFetchOCSPReturnsVerifiedResponse(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	response := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	leaf.OCSPServer = []string{server.URL}

	got, err := fetchOCSP(leaf, ca)
	if err != nil {
		t.Fatalf("fetchOCSP failed: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatal("fetchOCSP returned a different OCSP response generation")
	}
}

func TestCheckOCSPUsesStapledResponseWithoutOCSPServer(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()

	staple := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       now,
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	})

	status, err := checkOCSP([]*x509.Certificate{leaf, ca}, staple)
	if err != nil {
		t.Fatalf("checkOCSP rejected a valid stapled response: %v", err)
	}
	if status.Status != ocsp.Revoked {
		t.Fatalf("expected revoked status, got %d", status.Status)
	}
	if status.RevocationReason != ocsp.KeyCompromise {
		t.Fatalf("expected key-compromise reason, got %d", status.RevocationReason)
	}
}

func TestOCSPDelegatedResponderRequiresOCSPSigningEKU(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()

	responderWithoutEKU, keyWithoutEKU := newOCSPTestResponder(t, ca, caKey, false)
	responseWithoutEKU := createOCSPTestResponse(t, ca, responderWithoutEKU, keyWithoutEKU, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Certificate:  responderWithoutEKU,
	})
	if _, err := parseAndVerifyOCSPResponse(responseWithoutEKU, leaf, ca); err == nil {
		t.Fatal("expected a responder certificate without OCSPSigning EKU to be rejected")
	} else if stage := ocspValidationStage(err); stage != "responder" {
		t.Fatalf("expected responder-stage rejection, got %q: %v", stage, err)
	}

	responderWithEKU, keyWithEKU := newOCSPTestResponder(t, ca, caKey, true)
	responseWithEKU := createOCSPTestResponse(t, ca, responderWithEKU, keyWithEKU, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Certificate:  responderWithEKU,
	})
	status, err := parseAndVerifyOCSPResponse(responseWithEKU, leaf, ca)
	if err != nil {
		t.Fatalf("valid delegated responder was rejected: %v", err)
	}
	if status.Status != ocsp.Good {
		t.Fatalf("expected good status, got %d", status.Status)
	}
}

func TestVerifyChainReportsOCSPEvidencePerChain(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	staple := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       now,
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	})

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}

	result := VerifyChain([]*x509.Certificate{leaf}, staple, "leaf.example.com", caPath)
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if !result.Revoked() {
		t.Fatal("expected the revoked OCSP status to be reported")
	}
	if result.OCSPError != "" {
		t.Fatalf("unexpected OCSP error: %s", result.OCSPError)
	}
	if len(result.OCSPStatuses) != 1 {
		t.Fatalf("expected one per-chain OCSP status, got %d", len(result.OCSPStatuses))
	}

	evidence := result.OCSPStatuses[0]
	t.Logf("chain=%d serial=%s responder=%q source=%s stage=%s status=%s reason=%q",
		evidence.Chain, evidence.SerialNumber, evidence.Responder, evidence.Source,
		evidence.Stage, evidence.Status, evidence.RevocationReason)
	if evidence.SerialNumber != leaf.SerialNumber.String() {
		t.Fatalf("unexpected serial number in evidence: %q", evidence.SerialNumber)
	}
	if evidence.Status != "revoked" {
		t.Fatalf("unexpected status in evidence: %q", evidence.Status)
	}
	if evidence.RevocationReason != "KeyCompromise" {
		t.Fatalf("unexpected revocation reason in evidence: %q", evidence.RevocationReason)
	}
	if evidence.Source != "stapled" {
		t.Fatalf("unexpected source in evidence: %q", evidence.Source)
	}
	if evidence.Responder != "CN=Test CA" {
		t.Fatalf("unexpected responder in evidence: %q", evidence.Responder)
	}
}

func TestVerifyChainReportsOCSPFailureStage(t *testing.T) {
	ca, caKey := newOCSPTestCA(t)
	leaf := newOCSPTestLeaf(t, ca, caKey, 100)
	staleLeaf := newOCSPTestLeaf(t, ca, caKey, 101)
	now := time.Now()
	staleStaple := createOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: staleLeaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}

	result := VerifyChain([]*x509.Certificate{leaf}, staleStaple, "leaf.example.com", caPath)
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if result.OCSPError == "" {
		t.Fatal("expected the stale OCSP response to be reported")
	}
	if !result.VerificationFailed() {
		t.Fatal("a failed revocation check must fail verification")
	}
	if len(result.OCSPStatuses) != 1 || result.OCSPStatuses[0] == nil {
		t.Fatalf("expected one per-chain OCSP failure, got %#v", result.OCSPStatuses)
	}
	evidence := result.OCSPStatuses[0]
	if evidence.Stage != "serial" {
		t.Fatalf("expected serial failure stage, got %q", evidence.Stage)
	}
	if evidence.Error == "" {
		t.Fatal("expected the per-chain failure evidence to include the error")
	}
	t.Logf("stale response reported for chain=%d serial=%s stage=%s error=%q",
		evidence.Chain, evidence.SerialNumber, evidence.Stage, evidence.Error)
}

func TestVerificationFailedUsesOCSPConclusion(t *testing.T) {
	if (SimpleVerification{OCSPStatus: &ocsp.Response{Status: ocsp.Good}}).VerificationFailed() {
		t.Fatal("a good OCSP conclusion must not fail verification")
	}
	if (SimpleVerification{OCSPStatus: &ocsp.Response{Status: ocsp.Unknown}}).VerificationFailed() {
		t.Fatal("an unknown OCSP conclusion preserves the existing non-failing behavior")
	}
	if !(SimpleVerification{OCSPStatus: &ocsp.Response{Status: ocsp.Revoked}}).VerificationFailed() {
		t.Fatal("a revoked OCSP conclusion must fail verification")
	}
	if !(SimpleVerification{OCSPStatuses: []*OCSPStatus{&OCSPStatus{Status: "revoked"}}}).VerificationFailed() {
		t.Fatal("revocation evidence must also fail verification")
	}
	if !(SimpleVerification{OCSPError: "ocsp unavailable"}).VerificationFailed() {
		t.Fatal("an indeterminate revocation check must fail closed")
	}
	if !(SimpleVerification{OCSPStatuses: []*OCSPStatus{&OCSPStatus{Error: "bad signature"}}}).VerificationFailed() {
		t.Fatal("per-chain OCSP failure evidence must fail closed")
	}
	if !(SimpleVerification{Error: "chain verification failed"}).VerificationFailed() {
		t.Fatal("a chain verification error must fail verification")
	}
}
