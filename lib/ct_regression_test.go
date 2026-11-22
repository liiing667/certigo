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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadCTRegressionCertificates(t *testing.T, paths ...string) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("parse certificate from %s: %v", path, err)
			}
			certs = append(certs, cert)
		}
	}
	return certs
}

func regressionSCTLogIDs(scts []*simpleSCT) [][]byte {
	ids := make([][]byte, len(scts))
	for i, sct := range scts {
		ids[i] = append([]byte(nil), sct.LogID...)
	}
	return ids
}

// certificateWithUnknownFirstLogRegression returns a copy of cert with the first SCT's
// log ID changed. The certificate signature is intentionally not updated:
// SCT parsing only inspects the embedded extension, so this is a convenient
// way to exercise unknown log IDs without adding another large fixture.
func certificateWithUnknownFirstLogRegression(t *testing.T, cert *x509.Certificate) *x509.Certificate {
	t.Helper()

	scts := parseSCTList(cert)
	if len(scts) == 0 {
		t.Fatal("test certificate has no SCTs")
	}

	raw := append([]byte(nil), cert.Raw...)
	idx := bytes.Index(raw, scts[0].LogID)
	if idx < 0 {
		t.Fatal("first SCT log ID not found in certificate")
	}
	if bytes.Contains(raw[idx+len(scts[0].LogID):], scts[0].LogID) {
		t.Fatal("first SCT log ID is not unique in certificate")
	}
	raw[idx] ^= 0xff

	mutated, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse certificate with unknown log ID: %v", err)
	}
	return mutated
}

func TestSCTEvidenceIsBoundPerCertificateRegression(t *testing.T) {
	certs := loadCTRegressionCertificates(t,
		"testdata/ct-sct-cert.pem",
		"../test-certs/example-leaf.crt",
	)
	if len(certs) != 2 {
		t.Fatalf("loaded %d certificates, want 2", len(certs))
	}
	sctCert, plainCert := certs[0], certs[1]

	original := createSimpleCertificate("", sctCert)
	if got := len(original.SCTList); got != 3 {
		t.Fatalf("original certificate has %d SCTs, want 3", got)
	}

	// Parse a certificate without SCTs between two parses of the certificate
	// with SCTs. A leaked "last certificate" state must not change either
	// result.
	plain := createSimpleCertificate("", plainCert)
	if len(plain.SCTList) != 0 {
		t.Fatalf("certificate without SCT extension has %d SCTs", len(plain.SCTList))
	}

	reparsed := createSimpleCertificate("", sctCert)
	if !reflect.DeepEqual(regressionSCTLogIDs(original.SCTList), regressionSCTLogIDs(reparsed.SCTList)) {
		t.Fatalf("SCT list changed after parsing a different certificate:\nfirst: %v\nagain: %v",
			regressionSCTLogIDs(original.SCTList), regressionSCTLogIDs(reparsed.SCTList))
	}

	// Two SCT-bearing certificates must keep their own lists.
	mutated := certificateWithUnknownFirstLogRegression(t, sctCert)
	mutatedSummary := createSimpleCertificate("", mutated)
	if reflect.DeepEqual(regressionSCTLogIDs(original.SCTList), regressionSCTLogIDs(mutatedSummary.SCTList)) {
		t.Fatal("different certificates produced the same SCT list")
	}
	if again := createSimpleCertificate("", sctCert); !reflect.DeepEqual(
		regressionSCTLogIDs(original.SCTList), regressionSCTLogIDs(again.SCTList)) {
		t.Fatal("SCT list was replaced by a subsequently parsed certificate")
	}
}

func TestUnknownLogIDAuditEvidenceRegression(t *testing.T) {
	certs := loadCTRegressionCertificates(t, "testdata/ct-sct-cert.pem")
	original := certs[0]
	mutated := certificateWithUnknownFirstLogRegression(t, original)

	scts := parseSCTList(mutated)
	if len(scts) != 3 {
		t.Fatalf("certificate has %d SCTs, want 3 (an unknown log must not drop its SCT)", len(scts))
	}
	unknown := scts[0]
	if !unknown.LogUnknown {
		t.Fatal("unknown log ID was not marked as unknown")
	}
	if unknown.LogOperator != "" || unknown.LogURL != "" {
		t.Fatalf("unknown log was assigned metadata: operator=%q url=%q", unknown.LogOperator, unknown.LogURL)
	}
	if len(unknown.LogID) != 32 {
		t.Fatalf("unknown log ID has length %d, want 32", len(unknown.LogID))
	}
	for i := 1; i < len(scts); i++ {
		if scts[i].LogUnknown || scts[i].LogOperator == "" || scts[i].LogURL == "" {
			t.Fatalf("known SCT %d lost its log identity after SCT 0 became unknown", i)
		}
	}

	blob, err := json.Marshal(unknown)
	if err != nil {
		t.Fatalf("marshal unknown SCT: %v", err)
	}
	var evidence struct {
		LogID       []byte `json:"log_id"`
		LogUnknown  bool   `json:"log_unknown"`
		LogOperator string `json:"log_operator"`
		LogURL      string `json:"log_url"`
	}
	if err := json.Unmarshal(blob, &evidence); err != nil {
		t.Fatalf("unmarshal unknown SCT: %v", err)
	}
	if !evidence.LogUnknown {
		t.Fatalf("JSON lost the unknown-log marker: %s", blob)
	}
	if !bytes.Equal(evidence.LogID, unknown.LogID) {
		t.Fatalf("JSON log ID = %x, want %x", evidence.LogID, unknown.LogID)
	}
	if evidence.LogOperator != "" || evidence.LogURL != "" {
		t.Fatalf("JSON invented log metadata: operator=%q url=%q", evidence.LogOperator, evidence.LogURL)
	}

	text := string(EncodeX509ToText(mutated, 100, true))
	if !strings.Contains(text, "Log Identity: unknown") {
		t.Fatalf("text output lost the unknown-log marker:\n%s", text)
	}
	if !strings.Contains(text, hexify(unknown.LogID)[:23]) {
		t.Fatalf("text output lost the unknown log ID:\n%s", text)
	}
	if strings.Contains(text, "SCT Parse Error:") {
		t.Fatalf("unknown log was reported as a parse error:\n%s", text)
	}
}

func TestKnownLogAndNoSCTCompatibilityRegression(t *testing.T) {
	certs := loadCTRegressionCertificates(t,
		"testdata/ct-sct-cert.pem",
		"../test-certs/example-leaf.crt",
	)
	sctCert, plainCert := certs[0], certs[1]

	scts := parseSCTList(sctCert)
	if len(scts) != 3 {
		t.Fatalf("certificate has %d SCTs, want 3", len(scts))
	}
	if scts[0].LogUnknown {
		t.Fatal("known log was marked as unknown")
	}
	if scts[0].LogOperator != "Google" {
		t.Fatalf("known log operator = %q, want Google", scts[0].LogOperator)
	}
	if scts[0].LogURL != "https://ct.googleapis.com/aviator/" {
		t.Fatalf("known log URL = %q, want aviator URL", scts[0].LogURL)
	}
	// Logs from earlier CT log list versions are kept in the generated map.
	// Their identity must remain available even though they may no longer be
	// in the current log list.
	const oldLogID = "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA="
	oldLog := knownLogs[oldLogID]
	if oldLog == nil {
		t.Fatal("known log from an earlier list version is missing")
	}
	if oldLog.operator != "Certly" || oldLog.url != "https://log.certly.io/" {
		t.Fatalf("known old log identity changed: operator=%q url=%q", oldLog.operator, oldLog.url)
	}

	knownJSON := EncodeX509ToJSON(sctCert)
	if bytes.Contains(knownJSON, []byte("log_unknown")) {
		t.Fatalf("known log JSON gained an unknown marker: %s", knownJSON)
	}
	if bytes.Contains(knownJSON, []byte("sct_error")) {
		t.Fatalf("known log JSON gained an SCT error field: %s", knownJSON)
	}

	plain := createSimpleCertificate("", plainCert)
	if len(plain.SCTList) != 0 || plain.SCTError != "" {
		t.Fatalf("certificate without SCTs has CT output: scts=%d error=%q", len(plain.SCTList), plain.SCTError)
	}
	plainJSON := EncodeX509ToJSON(plainCert)
	if bytes.Contains(plainJSON, []byte("sct_list")) || bytes.Contains(plainJSON, []byte("sct_error")) {
		t.Fatalf("certificate without SCTs gained CT JSON fields: %s", plainJSON)
	}
}

func TestSCTOrderCompatibilityRegression(t *testing.T) {
	certs := loadCTRegressionCertificates(t, "testdata/ct-sct-cert.pem")
	cert := certs[0]
	scts := parseSCTList(cert)
	if len(scts) != 3 {
		t.Fatalf("certificate has %d SCTs, want 3", len(scts))
	}

	var decoded struct {
		SCTList []struct {
			LogID []byte `json:"log_id"`
		} `json:"sct_list"`
	}
	if err := json.Unmarshal(EncodeX509ToJSON(cert), &decoded); err != nil {
		t.Fatalf("unmarshal certificate JSON: %v", err)
	}
	if len(decoded.SCTList) != len(scts) {
		t.Fatalf("JSON has %d SCTs, want %d", len(decoded.SCTList), len(scts))
	}
	for i := range scts {
		if !bytes.Equal(decoded.SCTList[i].LogID, scts[i].LogID) {
			t.Fatalf("JSON SCT %d log ID = %x, want %x", i, decoded.SCTList[i].LogID, scts[i].LogID)
		}
	}

	text := string(EncodeX509ToText(cert, 100, true))
	lastPos := -1
	for i, sct := range scts {
		if sct.LogURL == "" {
			continue
		}
		pos := strings.Index(text, "Log URL: "+sct.LogURL)
		if pos < 0 {
			t.Fatalf("text output is missing SCT %d (%s)", i, sct.LogURL)
		}
		if pos <= lastPos {
			t.Fatalf("text output has SCT %d out of order", i)
		}
		lastPos = pos
	}
}

func TestSCTRetryIsolationRegression(t *testing.T) {
	bad := &x509.Certificate{
		Raw: []byte{0x30, 0x00},
		Extensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
			Value: []byte{0x04, 0x02, 0x00, 0x00},
		}},
	}
	scts, err := parseCertificateSCTs(bad)
	if err == nil {
		t.Fatal("malformed certificate with SCT extension parsed without error")
	}
	if len(scts) != 0 {
		t.Fatalf("malformed certificate returned %d SCTs", len(scts))
	}

	certs := loadCTRegressionCertificates(t,
		"../test-certs/example-leaf.crt",
		"testdata/ct-sct-cert.pem",
	)
	if scts, err := parseCertificateSCTs(certs[0]); err != nil || len(scts) != 0 {
		t.Fatalf("certificate without SCTs after a failure: scts=%d err=%v", len(scts), err)
	}
	if scts, err := parseCertificateSCTs(certs[1]); err != nil || len(scts) != 3 {
		t.Fatalf("SCT certificate after a failure: scts=%d err=%v", len(scts), err)
	}
}
