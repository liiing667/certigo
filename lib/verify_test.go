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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

type chainTestCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newChainTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return key
}

func newChainTestRoot(t *testing.T, commonName string, serial int64) chainTestCA {
	t.Helper()
	key := newChainTestKey(t)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create root certificate %q: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse root certificate %q: %v", commonName, err)
	}
	return chainTestCA{cert: cert, key: key}
}

func newChainTestIntermediate(t *testing.T, issuer chainTestCA, commonName string, serial int64, key *ecdsa.PrivateKey) chainTestCA {
	t.Helper()
	if key == nil {
		key = newChainTestKey(t)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatalf("failed to create intermediate certificate %q: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse intermediate certificate %q: %v", commonName, err)
	}
	return chainTestCA{cert: cert, key: key}
}

func newChainTestLeaf(t *testing.T, issuer chainTestCA, commonName string, serial int64) *x509.Certificate {
	t.Helper()
	key := newChainTestKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatalf("failed to create leaf certificate %q: %v", commonName, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse leaf certificate %q: %v", commonName, err)
	}
	return cert
}

func chainTestRootsPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "roots.pem")
}

func writeChainTestRoots(t *testing.T, path string, roots ...*x509.Certificate) {
	t.Helper()
	var data []byte
	for _, root := range roots {
		data = append(data, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: root.Raw,
		})...)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write roots file: %v", err)
	}
}

func newChainTestFixture(t *testing.T) ([]*x509.Certificate, chainTestCA, chainTestCA) {
	t.Helper()
	rootA := newChainTestRoot(t, "Root A", 1)
	rootB := newChainTestRoot(t, "Root B", 2)
	intermediateKey := newChainTestKey(t)
	intermediateA := newChainTestIntermediate(t, rootA, "Shared Intermediate", 10, intermediateKey)
	intermediateB := newChainTestIntermediate(t, rootB, "Shared Intermediate", 11, intermediateKey)
	leaf := newChainTestLeaf(t, intermediateA, "leaf.example.com", 100)
	return []*x509.Certificate{leaf, intermediateA.cert, intermediateB.cert}, rootA, rootB
}

func TestChainPolicyCABundleCompatibility(t *testing.T) {
	root := newChainTestRoot(t, "Compatibility Root", 1)
	rootsPath := chainTestRootsPath(t)
	writeChainTestRoots(t, rootsPath, root.cert)

	pool, err := caBundle(rootsPath)
	if err != nil {
		t.Fatalf("caBundle failed: %v", err)
	}
	if pool == nil {
		t.Fatal("caBundle returned a nil pool")
	}
}

func TestChainPolicyReportRetainsAnchorPerChain(t *testing.T) {
	certs, rootA, rootB := newChainTestFixture(t)
	rootsPath := chainTestRootsPath(t)
	writeChainTestRoots(t, rootsPath, rootA.cert, rootB.cert)

	var wantAnchors []string
	var wantVersion string
	for attempt := 0; attempt < 5; attempt++ {
		result := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
		if result.Error != "" {
			t.Fatalf("attempt %d: unexpected verification error: %s", attempt, result.Error)
		}
		if !result.Verified() {
			t.Fatalf("attempt %d: result is not verified even though every chain has an anchor", attempt)
		}
		if result.ExitCode() != 0 {
			t.Fatalf("attempt %d: successful report returned exit code %d", attempt, result.ExitCode())
		}
		if result.PolicyVersion != VerificationPolicyVersion {
			t.Fatalf("attempt %d: policy version = %q, want %q", attempt, result.PolicyVersion, VerificationPolicyVersion)
		}
		if result.RootSetVersion == "" {
			t.Fatalf("attempt %d: root set version is empty", attempt)
		}
		if result.RootCount != 2 {
			t.Fatalf("attempt %d: root count = %d, want 2", attempt, result.RootCount)
		}
		if len(result.Roots) != 2 {
			t.Fatalf("attempt %d: got %d roots in report, want 2", attempt, len(result.Roots))
		}
		if result.RootSource == "" {
			t.Fatalf("attempt %d: root source is empty", attempt)
		}
		if len(result.Chains) != 2 {
			t.Fatalf("attempt %d: got %d chains, want 2", attempt, len(result.Chains))
		}
		if len(result.Anchors) != len(result.Chains) {
			t.Fatalf("attempt %d: got %d anchors for %d chains", attempt, len(result.Anchors), len(result.Chains))
		}
		if len(result.ChainReports) != len(result.Chains) {
			t.Fatalf("attempt %d: got %d chain reports for %d chains", attempt, len(result.ChainReports), len(result.Chains))
		}

		anchors := make([]string, 0, len(result.Chains))
		for i := range result.Chains {
			report := result.ChainReports[i]
			if report.Index != i {
				t.Fatalf("attempt %d: chain report %d has index %d", attempt, i, report.Index)
			}
			if report.PolicyVersion != result.PolicyVersion {
				t.Fatalf("attempt %d: chain report %d policy version = %q, want %q", attempt, i, report.PolicyVersion, result.PolicyVersion)
			}
			if report.RootSetVersion != result.RootSetVersion {
				t.Fatalf("attempt %d: chain report %d root set version = %q, want %q", attempt, i, report.RootSetVersion, result.RootSetVersion)
			}
			if report.Anchor == nil {
				t.Fatalf("attempt %d: chain report %d has no anchor", attempt, i)
			}
			if !report.Anchor.Trusted {
				t.Fatalf("attempt %d: chain report %d anchor %q is not trusted", attempt, i, report.Anchor.Name)
			}

			chain := result.Chains[i]
			last := chain[len(chain)-1]
			if report.Anchor.Name != last.Name {
				t.Fatalf("attempt %d: chain report %d anchor = %q, chain ends at %q", attempt, i, report.Anchor.Name, last.Name)
			}
			if result.Anchors[i].Name != report.Anchor.Name {
				t.Fatalf("attempt %d: anchors[%d] = %q, chain report anchor = %q", attempt, i, result.Anchors[i].Name, report.Anchor.Name)
			}
			anchors = append(anchors, report.Anchor.Name)
		}

		sortedAnchors := append([]string(nil), anchors...)
		sort.Strings(sortedAnchors)
		if !slices.Equal(sortedAnchors, []string{"CN=Root A", "CN=Root B"}) {
			t.Fatalf("attempt %d: anchors = %v, want Root A and Root B", attempt, sortedAnchors)
		}

		if attempt == 0 {
			wantAnchors = anchors
			wantVersion = result.RootSetVersion
			continue
		}
		if !slices.Equal(anchors, wantAnchors) {
			t.Fatalf("attempt %d: anchor order changed from %v to %v", attempt, wantAnchors, anchors)
		}
		if result.RootSetVersion != wantVersion {
			t.Fatalf("attempt %d: root set version changed from %q to %q", attempt, wantVersion, result.RootSetVersion)
		}
	}
}

func TestChainPolicySnapshotAcrossRootUpdates(t *testing.T) {
	certs, rootA, rootB := newChainTestFixture(t)
	rootsPath := chainTestRootsPath(t)
	writeChainTestRoots(t, rootsPath, rootA.cert, rootB.cert)

	snapshot, err := LoadVerificationPolicy(rootsPath)
	if err != nil {
		t.Fatalf("failed to load verification policy: %v", err)
	}
	if snapshot.Version() != VerificationPolicyVersion {
		t.Fatalf("policy version = %q, want %q", snapshot.Version(), VerificationPolicyVersion)
	}
	if snapshot.RootCount() != 2 {
		t.Fatalf("policy root count = %d, want 2", snapshot.RootCount())
	}
	before := VerifyChainWithPolicy(snapshot, certs, nil, "leaf.example.com")
	if len(before.Chains) != 2 {
		t.Fatalf("initial snapshot produced %d chains, want 2", len(before.Chains))
	}

	// Simulate an update that removes Root B. The already-loaded policy must
	// keep using the root set it snapshotted, so both chains remain valid.
	writeChainTestRoots(t, rootsPath, rootA.cert)
	stillSnapshotted := VerifyChainWithPolicy(snapshot, certs, nil, "leaf.example.com")
	if len(stillSnapshotted.Chains) != 2 {
		t.Fatalf("snapshotted policy produced %d chains after file update, want 2", len(stillSnapshotted.Chains))
	}

	// A fresh verification must use only the updated root set. Root B can no
	// longer vouch for the chain, and the report must say so.
	after := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
	if after.Error != "" {
		t.Fatalf("updated verification failed unexpectedly: %s", after.Error)
	}
	if len(after.Chains) != 1 {
		t.Fatalf("updated verification produced %d chains, want 1", len(after.Chains))
	}
	if len(after.ChainReports) != 1 {
		t.Fatalf("updated verification produced %d chain reports, want 1", len(after.ChainReports))
	}
	if after.ChainReports[0].Anchor == nil || after.ChainReports[0].Anchor.Name != "CN=Root A" {
		t.Fatalf("updated verification anchor = %+v, want CN=Root A", after.ChainReports[0].Anchor)
	}
	if after.RootSetVersion == before.RootSetVersion {
		t.Fatalf("root set version did not change after removing Root B")
	}
	if !after.Verified() {
		t.Fatalf("updated verification should still have one trusted anchor")
	}

	// Reordering the same roots must not change the policy version.
	writeChainTestRoots(t, rootsPath, rootB.cert, rootA.cert)
	reordered, err := LoadVerificationPolicy(rootsPath)
	if err != nil {
		t.Fatalf("failed to load reordered policy: %v", err)
	}
	writeChainTestRoots(t, rootsPath, rootA.cert, rootB.cert)
	original, err := LoadVerificationPolicy(rootsPath)
	if err != nil {
		t.Fatalf("failed to reload original policy: %v", err)
	}
	if reordered.RootSetVersion() != original.RootSetVersion() {
		t.Fatalf("root set version depends on file order: %q != %q", reordered.RootSetVersion(), original.RootSetVersion())
	}

	// Removing the remaining root must fail closed and identify the failed
	// path rather than returning the previous successful report.
	otherRoot := newChainTestRoot(t, "Unrelated Root", 99)
	writeChainTestRoots(t, rootsPath, otherRoot.cert)
	failed := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
	if failed.Error == "" {
		t.Fatal("verification unexpectedly succeeded without a trusted root")
	}
	if failed.Verified() {
		t.Fatal("failed verification must not be reported as verified")
	}
	if failed.ExitCode() != 1 {
		t.Fatalf("failed verification exit code = %d, want 1", failed.ExitCode())
	}
	if failed.FailurePath == nil {
		t.Fatal("failed verification has no failure path")
	}

	// A root that is still present in the input but has been removed from the
	// trust bundle must not be reported as a trusted anchor.
	writeChainTestRoots(t, rootsPath, rootA.cert)
	inputWithRemovedRoot := []*x509.Certificate{certs[0], certs[2], rootB.cert}
	rejected := VerifyChain(inputWithRemovedRoot, nil, "leaf.example.com", rootsPath)
	if rejected.Error == "" {
		t.Fatal("removed root in the input was accepted as a trust anchor")
	}
	if rejected.FailurePath == nil {
		t.Fatal("removed root rejection has no failure path")
	}
	if rejected.FailurePath.Anchor != nil && rejected.FailurePath.Anchor.Trusted {
		t.Fatalf("removed root %q was reported as trusted", rejected.FailurePath.Anchor.Name)
	}
}

func TestChainPolicyFailurePathLocatesCertificate(t *testing.T) {
	root := newChainTestRoot(t, "Root", 1)
	intermediate := newChainTestIntermediate(t, root, "Intermediate", 2, nil)
	leaf := newChainTestLeaf(t, intermediate, "leaf.example.com", 3)
	certs := []*x509.Certificate{leaf, intermediate.cert}
	rootsPath := chainTestRootsPath(t)

	otherRoot := newChainTestRoot(t, "Removed Root", 4)
	writeChainTestRoots(t, rootsPath, otherRoot.cert)
	result := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
	if result.Error == "" {
		t.Fatal("verification unexpectedly succeeded with a removed root")
	}
	if result.Verified() || result.ExitCode() != 1 {
		t.Fatalf("failed verification returned verified=%v exit=%d", result.Verified(), result.ExitCode())
	}
	failure := result.FailurePath
	if failure == nil {
		t.Fatal("failed verification has no failure path")
	}
	if len(result.ChainReports) != 1 || result.ChainReports[0].FailurePath == nil {
		t.Fatalf("failed verification does not retain a per-chain failure path: %+v", result.ChainReports)
	}
	if result.ChainReports[0].PolicyVersion != result.PolicyVersion {
		t.Fatalf("failed chain report policy version = %q, want %q", result.ChainReports[0].PolicyVersion, result.PolicyVersion)
	}
	if result.ChainReports[0].Valid {
		t.Fatal("failed chain report is marked valid")
	}
	if failure.Stage != "chain" {
		t.Fatalf("failure stage = %q, want chain", failure.Stage)
	}
	if failure.Certificate == nil {
		t.Fatal("failure path does not identify a failing certificate")
	}
	if failure.Index < 0 || failure.Index >= len(failure.Path) {
		t.Fatalf("failure index %d is outside path of length %d", failure.Index, len(failure.Path))
	}
	if failure.Path[failure.Index].Name != failure.Certificate.Name {
		t.Fatalf("failure index points at %q, certificate is %q", failure.Path[failure.Index].Name, failure.Certificate.Name)
	}
	if failure.Position == "" || failure.Position == "unknown" {
		t.Fatalf("failure position is not specific: %q", failure.Position)
	}
	if !strings.Contains(failure.Reason, "unknown authority") {
		t.Fatalf("failure reason = %q, want unknown authority", failure.Reason)
	}
	if len(failure.Path) < 2 {
		t.Fatalf("attempted path has %d entries, want at least leaf and intermediate", len(failure.Path))
	}
	var rendered bytes.Buffer
	PrintVerifyResult(&rendered, result)
	for _, want := range []string{"Failure stage: chain", "Failure position:", "Attempted path:", "<-- failed"} {
		if !strings.Contains(rendered.String(), want) {
			t.Fatalf("text report does not contain %q:\n%s", want, rendered.String())
		}
	}

	// A hostname mismatch happens after path building, so the failure must
	// point at the leaf instead of the anchor.
	writeChainTestRoots(t, rootsPath, root.cert)
	result = VerifyChain(certs, nil, "wrong.example.com", rootsPath)
	failure = result.FailurePath
	if failure == nil {
		t.Fatal("hostname mismatch has no failure path")
	}
	if failure.Stage != "hostname" {
		t.Fatalf("hostname failure stage = %q, want hostname", failure.Stage)
	}
	if failure.Index != 0 || failure.Position != "leaf" {
		t.Fatalf("hostname failure position = %q index %d, want leaf index 0", failure.Position, failure.Index)
	}
	if failure.Certificate == nil || failure.Certificate.Name != "CN=leaf.example.com" {
		t.Fatalf("hostname failure certificate = %+v, want leaf", failure.Certificate)
	}
}

func TestChainPolicyReportJSONEvidence(t *testing.T) {
	certs, rootA, rootB := newChainTestFixture(t)
	rootsPath := chainTestRootsPath(t)
	writeChainTestRoots(t, rootsPath, rootA.cert, rootB.cert)

	success := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
	blob, err := json.Marshal(success)
	if err != nil {
		t.Fatalf("failed to marshal successful report: %v", err)
	}
	for _, field := range []string{
		`"policy_version"`,
		`"root_set_version"`,
		`"root_count"`,
		`"roots"`,
		`"chain_reports"`,
		`"anchors"`,
		`"anchor"`,
	} {
		if !strings.Contains(string(blob), field) {
			t.Fatalf("successful report does not contain %s: %s", field, blob)
		}
	}

	otherRoot := newChainTestRoot(t, "Removed Root", 99)
	writeChainTestRoots(t, rootsPath, otherRoot.cert)
	failed := VerifyChain(certs, nil, "leaf.example.com", rootsPath)
	blob, err = json.Marshal(failed)
	if err != nil {
		t.Fatalf("failed to marshal failed report: %v", err)
	}
	for _, field := range []string{
		`"failure_path"`,
		`"position"`,
		`"certificate"`,
		`"policy_version"`,
	} {
		if !strings.Contains(string(blob), field) {
			t.Fatalf("failed report does not contain %s: %s", field, blob)
		}
	}
}
