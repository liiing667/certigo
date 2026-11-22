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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type mixedOCSPRoundTripper func(*http.Request) (*http.Response, error)

func (f mixedOCSPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func useMixedOCSPHTTPClient(t *testing.T, transport http.RoundTripper) {
	t.Helper()

	original := ocspHttpClient
	ocspHttpClient = &http.Client{Transport: transport}
	t.Cleanup(func() {
		ocspHttpClient = original
	})
}

func mixedOCSPHTTPResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func newMixedOCSPTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func newMixedOCSPTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64) *x509.Certificate {
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

func newMixedOCSPTestResponder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, withEKU bool) (*x509.Certificate, *ecdsa.PrivateKey) {
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

func createMixedOCSPTestResponse(t *testing.T, issuer, responder *x509.Certificate, signer *ecdsa.PrivateKey, template ocsp.Response) []byte {
	t.Helper()

	der, err := ocsp.CreateResponse(issuer, responder, template, signer)
	if err != nil {
		t.Fatalf("failed to create OCSP response: %v", err)
	}
	return der
}

func writeMixedOCSPTestCA(t *testing.T, ca *x509.Certificate) string {
	t.Helper()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}
	return caPath
}

func newMixedOCSPTestRoot(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create root certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse root certificate: %v", err)
	}
	return cert, key
}

func newMixedOCSPTestIntermediate(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey, serial int64) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("failed to create intermediate certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse intermediate certificate: %v", err)
	}
	return cert
}

func newMixedOCSPTestCrossSignedLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, serial int64) *x509.Certificate {
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
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("failed to create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate: %v", err)
	}
	return cert
}

func writeMixedOCSPTestRoots(t *testing.T, roots ...*x509.Certificate) string {
	t.Helper()

	caPath := filepath.Join(t.TempDir(), "roots.pem")
	var bundle []byte
	for _, root := range roots {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw})...)
	}
	if err := os.WriteFile(caPath, bundle, 0o600); err != nil {
		t.Fatalf("failed to write CA bundle: %v", err)
	}
	return caPath
}

func TestMixedEvidenceOCSPPOSTRequestContainsDERRequest(t *testing.T) {
	encoded := []byte{0x30, 0x03, 0x0a, 0x01, 0x00}

	req, err := buildOCSPwithPOST("https://example.com/ocsp", encoded)
	if err != nil {
		t.Fatalf("buildOCSPwithPOST failed: %v", err)
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
}

func TestMixedEvidenceOCSPResponseSelectionPrefersRevocation(t *testing.T) {
	now := time.Now()
	good := &ocsp.Response{Status: ocsp.Good, ThisUpdate: now, ProducedAt: now, Raw: []byte("good")}
	revoked := &ocsp.Response{Status: ocsp.Revoked, ThisUpdate: now.Add(-time.Hour), ProducedAt: now.Add(-time.Hour), Raw: []byte("revoked")}

	if !preferOCSPResponse(good, revoked) {
		t.Fatal("revoked status must take precedence over a newer good response")
	}
	if preferOCSPResponse(revoked, good) {
		t.Fatal("good status must not replace a revoked response")
	}
}

func TestMixedEvidenceOCSPResponderValidityUsesResponseTime(t *testing.T) {
	now := time.Now()
	responder := &x509.Certificate{
		NotBefore: now.Add(-2 * time.Hour),
		NotAfter:  now.Add(-time.Hour),
	}

	if !certWasValidAt(responder, now.Add(-90*time.Minute)) {
		t.Fatal("an old cached response should remain valid when produced during the responder certificate's lifetime")
	}
	if certWasValidAt(responder, now) {
		t.Fatal("a response produced after the responder certificate expired must be rejected")
	}
}

func TestMixedEvidenceOCSPBadSignatureRejected(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong signing key: %v", err)
	}
	response := createMixedOCSPTestResponse(t, ca, ca, wrongKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	if _, err := parseAndVerifyOCSPResponse(response, leaf, ca); err == nil {
		t.Fatal("expected a bad OCSP signature to be rejected")
	} else if stage := ocspValidationStage(err); stage != "signature" {
		t.Fatalf("expected signature-stage rejection, got %q: %v", stage, err)
	}
}

func TestMixedEvidenceOCSPDelegatedResponderRequiresOCSPSigningEKU(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()

	responderWithoutEKU, keyWithoutEKU := newMixedOCSPTestResponder(t, ca, caKey, false)
	responseWithoutEKU := createMixedOCSPTestResponse(t, ca, responderWithoutEKU, keyWithoutEKU, ocsp.Response{
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

	responderWithEKU, keyWithEKU := newMixedOCSPTestResponder(t, ca, caKey, true)
	responseWithEKU := createMixedOCSPTestResponse(t, ca, responderWithEKU, keyWithEKU, ocsp.Response{
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

func TestMixedEvidenceOCSPEmbeddedIssuerCertificate(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	response := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
		Certificate:  ca,
	})

	status, err := parseAndVerifyOCSPResponse(response, leaf, ca)
	if err != nil {
		t.Fatalf("embedded issuer certificate was rejected: %v", err)
	}
	if status.Status != ocsp.Good {
		t.Fatalf("expected good status, got %d", status.Status)
	}
}

func TestMixedEvidenceOCSPUnknownStatusPreserved(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	response := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
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
}

func TestMixedEvidenceOCSPOldCacheStillAccepted(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	old := time.Now().Add(-30 * 24 * time.Hour)
	response := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   old,
		NextUpdate:   old.Add(time.Hour),
	})

	status, err := checkOCSP([]*x509.Certificate{leaf, ca}, response)
	if err != nil {
		t.Fatalf("checkOCSP rejected an old cached response: %v", err)
	}
	if !status.ThisUpdate.Truncate(time.Second).Equal(old.Truncate(time.Second)) {
		t.Fatalf("old cache timestamps changed: got %v, want %v", status.ThisUpdate, old)
	}
}

func TestMixedEvidenceOCSPRecordsSourceAndSigner(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	staple := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       now,
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	})

	status, evidence, err := checkOCSPWithEvidence([]*x509.Certificate{leaf, ca}, staple)
	if err != nil {
		t.Fatalf("checkOCSPWithEvidence failed: %v", err)
	}
	if status.Status != ocsp.Revoked {
		t.Fatalf("expected revoked status, got %d", status.Status)
	}
	if evidence.Source != "stapled" {
		t.Fatalf("expected stapled source, got %q", evidence.Source)
	}
	if evidence.Stage != "verified" || !evidence.SignatureVerified {
		t.Fatalf("expected verified signature evidence, got %#v", evidence)
	}
	if evidence.SerialNumber != leaf.SerialNumber.String() {
		t.Fatalf("unexpected serial number in evidence: %q", evidence.SerialNumber)
	}
	if evidence.Issuer != PrintCommonName(ca.Subject) || evidence.Responder != PrintCommonName(ca.Subject) {
		t.Fatalf("unexpected issuer/responder evidence: %#v", evidence)
	}
}

func TestMixedEvidenceOCSPFetchedEvidenceIsIndependent(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	response := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	useMixedOCSPHTTPClient(t, mixedOCSPRoundTripper(func(req *http.Request) (*http.Response, error) {
		return mixedOCSPHTTPResponse(response), nil
	}))
	leaf.OCSPServer = []string{"https://ocsp.example.test/"}

	_, evidence, err := checkOCSPWithEvidence([]*x509.Certificate{leaf, ca}, nil)
	if err != nil {
		t.Fatalf("checkOCSPWithEvidence failed: %v", err)
	}
	if evidence.Source != "fetched" {
		t.Fatalf("expected fetched source, got %q", evidence.Source)
	}
	if evidence.Status != ocspStatusGood || !evidence.SignatureVerified {
		t.Fatalf("unexpected fetched evidence: %#v", evidence)
	}
}

func TestMixedEvidenceCheckOCSPRejectsStaleResponseAfterBadSignature(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	staleLeaf := newMixedOCSPTestLeaf(t, ca, caKey, 101)
	now := time.Now()

	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate wrong signing key: %v", err)
	}
	badSignature := createMixedOCSPTestResponse(t, ca, ca, wrongKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})
	staleGood := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber: staleLeaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	var requests int32
	useMixedOCSPHTTPClient(t, mixedOCSPRoundTripper(func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&requests, 1) <= 2 {
			return mixedOCSPHTTPResponse(badSignature), nil
		}
		return mixedOCSPHTTPResponse(staleGood), nil
	}))
	leaf.OCSPServer = []string{"https://ocsp.example.test/"}

	status, err := checkOCSP([]*x509.Certificate{leaf, ca}, nil)
	if err == nil {
		t.Fatalf("expected the stale OCSP response to be rejected, got status %v", status)
	}
	if status != nil {
		t.Fatalf("expected no OCSP status on failure, got %v", status)
	}
	if stage := ocspValidationStage(err); stage != "serial" {
		t.Fatalf("expected serial-number rejection, got stage %q: %v", stage, err)
	}
}

func TestMixedEvidenceVerifyChainReportsOCSPEvidencePerChain(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)
	now := time.Now()
	staple := createMixedOCSPTestResponse(t, ca, ca, caKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       now,
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	})

	result := VerifyChain([]*x509.Certificate{leaf}, staple, "leaf.example.com", writeMixedOCSPTestCA(t, ca))
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if !result.Revoked() || result.OCSPStatus == nil || result.OCSPStatus.Status != ocsp.Revoked {
		t.Fatal("expected the revoked OCSP status to be reported")
	}
	if len(result.OCSPStatuses) != 1 {
		t.Fatalf("expected one per-chain OCSP status, got %d", len(result.OCSPStatuses))
	}
	evidence := result.OCSPStatuses[0]
	if evidence == nil || evidence.Status != ocspStatusRevoked || evidence.Source != "stapled" {
		t.Fatalf("unexpected per-chain evidence: %#v", evidence)
	}
	if evidence.RevocationReason != "KeyCompromise" {
		t.Fatalf("unexpected revocation reason in evidence: %q", evidence.RevocationReason)
	}
}

func TestMixedEvidenceVerifyChainSeparatesAlternateChains(t *testing.T) {
	rootA, rootAKey := newMixedOCSPTestRoot(t, "Root A")
	rootB, rootBKey := newMixedOCSPTestRoot(t, "Root B")
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	intermediateA := newMixedOCSPTestIntermediate(t, rootA, rootAKey, intermediateKey, 10)
	intermediateB := newMixedOCSPTestIntermediate(t, rootB, rootBKey, intermediateKey, 11)
	leaf := newMixedOCSPTestCrossSignedLeaf(t, intermediateA, intermediateKey, 100)
	leaf.OCSPServer = []string{"https://ocsp.example.test/"}

	now := time.Now()
	good := createMixedOCSPTestResponse(t, intermediateA, intermediateA, intermediateKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})
	revoked := createMixedOCSPTestResponse(t, intermediateA, intermediateA, intermediateKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       now.Add(time.Minute),
		NextUpdate:       now.Add(time.Hour),
		RevokedAt:        now.Add(-time.Hour),
		RevocationReason: ocsp.KeyCompromise,
	})

	var requests int32
	useMixedOCSPHTTPClient(t, mixedOCSPRoundTripper(func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&requests, 1) <= 2 {
			return mixedOCSPHTTPResponse(good), nil
		}
		return mixedOCSPHTTPResponse(revoked), nil
	}))

	result := VerifyChain(
		[]*x509.Certificate{leaf, intermediateA, intermediateB},
		nil,
		"leaf.example.com",
		writeMixedOCSPTestRoots(t, rootA, rootB),
	)
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if len(result.Chains) != 2 {
		t.Fatalf("expected two valid chains, got %d", len(result.Chains))
	}
	if len(result.OCSPStatuses) != len(result.Chains) {
		t.Fatalf("expected one OCSP result per chain, got %d for %d chains", len(result.OCSPStatuses), len(result.Chains))
	}
	if !result.Revoked() || result.OCSPStatus == nil || result.OCSPStatus.Status != ocsp.Revoked {
		t.Fatalf("revocation from the later chain was hidden: %#v", result.OCSPStatus)
	}
	if result.OCSPStatuses[0] == nil || result.OCSPStatuses[1] == nil {
		t.Fatalf("expected independent evidence for both chains: %#v", result.OCSPStatuses)
	}
	if result.OCSPStatuses[0].Status == result.OCSPStatuses[1].Status {
		t.Fatalf("alternate chains collapsed to the same OCSP status: %#v", result.OCSPStatuses)
	}
	var report bytes.Buffer
	PrintVerifyResult(&report, result)
	for _, want := range []string{"for chain [0]", "for chain [1]", "Response Signature:", "Source: fetched"} {
		if !strings.Contains(report.String(), want) {
			t.Fatalf("text report is missing %q:\n%s", want, report.String())
		}
	}
	t.Logf("chain[0]=%s source=%s stage=%s; chain[1]=%s source=%s stage=%s",
		result.OCSPStatuses[0].Status, result.OCSPStatuses[0].Source, result.OCSPStatuses[0].Stage,
		result.OCSPStatuses[1].Status, result.OCSPStatuses[1].Source, result.OCSPStatuses[1].Stage)
}

func TestMixedEvidenceVerifyChainKeepsLaterFetchFailure(t *testing.T) {
	rootA, rootAKey := newMixedOCSPTestRoot(t, "Root A")
	rootB, rootBKey := newMixedOCSPTestRoot(t, "Root B")
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate intermediate key: %v", err)
	}
	intermediateA := newMixedOCSPTestIntermediate(t, rootA, rootAKey, intermediateKey, 10)
	intermediateB := newMixedOCSPTestIntermediate(t, rootB, rootBKey, intermediateKey, 11)
	leaf := newMixedOCSPTestCrossSignedLeaf(t, intermediateA, intermediateKey, 100)
	leaf.OCSPServer = []string{"https://ocsp.example.test/"}

	now := time.Now()
	good := createMixedOCSPTestResponse(t, intermediateA, intermediateA, intermediateKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   now,
		NextUpdate:   now.Add(time.Hour),
	})

	var requests int32
	useMixedOCSPHTTPClient(t, mixedOCSPRoundTripper(func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&requests, 1) <= 2 {
			return mixedOCSPHTTPResponse(good), nil
		}
		return nil, errors.New("OCSP server timeout")
	}))

	result := VerifyChain(
		[]*x509.Certificate{leaf, intermediateA, intermediateB},
		nil,
		"leaf.example.com",
		writeMixedOCSPTestRoots(t, rootA, rootB),
	)
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if len(result.OCSPStatuses) != 2 {
		t.Fatalf("expected two per-chain OCSP results, got %#v", result.OCSPStatuses)
	}
	if result.OCSPStatuses[0] == nil || result.OCSPStatuses[0].Status != ocspStatusGood {
		t.Fatalf("first chain's good status was lost: %#v", result.OCSPStatuses[0])
	}
	if result.OCSPStatuses[1] == nil || result.OCSPStatuses[1].Error == "" {
		t.Fatalf("second chain's fetch failure was hidden: %#v", result.OCSPStatuses[1])
	}
	if result.OCSPStatuses[1].Stage != "fetch" || result.OCSPStatuses[1].Source != "fetched" {
		t.Fatalf("unexpected fetch failure evidence: %#v", result.OCSPStatuses[1])
	}
	if result.OCSPError == "" || !result.VerificationFailed() {
		t.Fatalf("fetch failure was not fail-closed: %#v", result)
	}
	t.Logf("chain[0]=%s; chain[1]=error stage=%s source=%s error=%q",
		result.OCSPStatuses[0].Status, result.OCSPStatuses[1].Stage,
		result.OCSPStatuses[1].Source, result.OCSPStatuses[1].Error)
}

func TestMixedEvidenceVerifyChainWithoutOCSPKeepsExistingResult(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)

	result := VerifyChain([]*x509.Certificate{leaf}, nil, "leaf.example.com", writeMixedOCSPTestCA(t, ca))
	if result.Error != "" {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	if result.OCSPStatus != nil || result.OCSPError != "" || result.OCSPWasStapled {
		t.Fatalf("unexpected OCSP result without OCSP evidence: %#v", result)
	}
	if result.OCSPStatuses != nil {
		t.Fatalf("expected no per-chain OCSP statuses, got %#v", result.OCSPStatuses)
	}
	if result.VerificationFailed() {
		t.Fatal("a certificate without OCSP must not fail verification")
	}
}

func TestMixedEvidenceOCSPEvidenceSurvivesJSONRoundTrip(t *testing.T) {
	result := SimpleVerification{
		OCSPStatus:     &ocsp.Response{Status: ocsp.Good},
		OCSPWasStapled: true,
		OCSPStatuses: []*OCSPStatus{{
			Chain:              0,
			SerialNumber:       "100",
			Issuer:             "CN=Test CA",
			Responder:          "CN=Test CA",
			Source:             "stapled",
			Stage:              "verified",
			Status:             ocspStatusGood,
			SignatureAlgorithm: "ECDSA-SHA256",
			SignatureVerified:  true,
			WasStapled:         true,
		}},
		Chains: [][]simpleVerifyCert{{{Name: "CN=leaf.example.com"}}},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal verification result: %v", err)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("failed to unmarshal verification result: %v", err)
	}
	for _, key := range []string{"ocsp_response", "ocsp_was_stapled", "ocsp_statuses", "chains"} {
		if _, ok := object[key]; !ok {
			t.Fatalf("existing or new JSON field %q is missing: %s", key, encoded)
		}
	}

	var roundTripped SimpleVerification
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatalf("failed to unmarshal verification result: %v", err)
	}
	if len(roundTripped.OCSPStatuses) != 1 {
		t.Fatalf("per-chain OCSP evidence was lost: %#v", roundTripped.OCSPStatuses)
	}
	evidence := roundTripped.OCSPStatuses[0]
	if evidence.Source != "stapled" || evidence.Stage != "verified" || !evidence.SignatureVerified {
		t.Fatalf("per-chain OCSP evidence changed after round trip: %#v", evidence)
	}
}

func TestMixedEvidenceEncodeTLSToObjectIncludesOCSPEvidence(t *testing.T) {
	state := &tls.ConnectionState{
		Version:      tls.VersionTLS13,
		CipherSuite:  tls.TLS_AES_128_GCM_SHA256,
		OCSPResponse: []byte("staple"),
	}
	statuses := []*OCSPStatus{{Chain: 0, Source: "stapled", Stage: "verified", Status: ocspStatusGood, WasStapled: true}}

	encoded, err := json.Marshal(EncodeTLSToObjectWithOCSP(state, statuses))
	if err != nil {
		t.Fatalf("failed to marshal TLS description: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("failed to unmarshal TLS description: %v", err)
	}
	for _, key := range []string{"version", "cipher", "ocsp_stapled", "ocsp_statuses"} {
		if _, ok := object[key]; !ok {
			t.Fatalf("TLS JSON field %q is missing: %s", key, encoded)
		}
	}
}

func TestMixedEvidenceSimpleResultJSONBindsTLSAndVerificationEvidence(t *testing.T) {
	statuses := []*OCSPStatus{{
		Chain:              0,
		SerialNumber:       "100",
		Source:             "stapled",
		Stage:              "verified",
		Status:             ocspStatusGood,
		SignatureAlgorithm: "ECDSA-SHA256",
		SignatureVerified:  true,
		WasStapled:         true,
	}}
	result := SimpleResult{
		VerifyResult: &SimpleVerification{OCSPStatuses: statuses},
		TLSConnectionState: &tls.ConnectionState{
			Version:      tls.VersionTLS13,
			CipherSuite:  tls.TLS_AES_128_GCM_SHA256,
			OCSPResponse: []byte("staple"),
		},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}
	var object struct {
		TLSConnection struct {
			OCSPStatuses []*OCSPStatus `json:"ocsp_statuses"`
		} `json:"tls_connection"`
		VerifyResult struct {
			OCSPStatuses []*OCSPStatus `json:"ocsp_statuses"`
		} `json:"verify_result"`
	}
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if len(object.TLSConnection.OCSPStatuses) != 1 || len(object.VerifyResult.OCSPStatuses) != 1 {
		t.Fatalf("OCSP evidence is missing from a JSON consumer: %s", encoded)
	}
	if object.TLSConnection.OCSPStatuses[0].Source != "stapled" ||
		object.VerifyResult.OCSPStatuses[0].SignatureAlgorithm != "ECDSA-SHA256" {
		t.Fatalf("OCSP evidence changed across JSON consumers: %s", encoded)
	}
}

func TestMixedEvidenceVerificationFailedUsesPerChainOCSPConclusion(t *testing.T) {
	if (SimpleVerification{OCSPStatuses: []*OCSPStatus{{Status: ocspStatusUnknown}}}).VerificationFailed() {
		t.Fatal("an unknown OCSP conclusion preserves the existing non-failing behavior")
	}
	if !(SimpleVerification{OCSPStatuses: []*OCSPStatus{{Status: ocspStatusRevoked}}}).VerificationFailed() {
		t.Fatal("revocation evidence must fail verification")
	}
	if !(SimpleVerification{OCSPStatuses: []*OCSPStatus{{Error: "timeout"}}}).VerificationFailed() {
		t.Fatal("per-chain OCSP failure evidence must fail closed")
	}
	if !(SimpleVerification{OCSPError: "ocsp unavailable"}).VerificationFailed() {
		t.Fatal("an indeterminate legacy OCSP result must fail closed")
	}
}

func TestMixedEvidenceOCSPSkippedWithoutServer(t *testing.T) {
	ca, caKey := newMixedOCSPTestCA(t)
	leaf := newMixedOCSPTestLeaf(t, ca, caKey, 100)

	status, evidence, err := checkOCSPWithEvidence([]*x509.Certificate{leaf, ca}, nil)
	if !errors.Is(err, errSkippedRevocationCheck) {
		t.Fatalf("expected skipped revocation check, got %v", err)
	}
	if status != nil {
		t.Fatalf("expected no OCSP status, got %v", status)
	}
	if evidence.Stage != "skipped" {
		t.Fatalf("expected skipped stage, got %#v", evidence)
	}
}
