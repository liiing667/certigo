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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// VerificationPolicyVersion identifies the path validation rules applied by
// this build. A report is only comparable to another report with the same
// policy version and root set version.
const VerificationPolicyVersion = "certigo-x509-chain-policy-v1"

type simpleVerifyCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	PEM                string `json:"pem"`
	signatureAlgorithm x509.SignatureAlgorithm
}

// PathNode is one certificate in a reported verification path. Source says
// whether the certificate came from the caller's input ("input"), from the
// snapshotted trust-anchor set ("anchor"), or from an error hint ("reported").
// Trusted is true only when the node actually terminated a valid path.
type PathNode struct {
	Name         string `json:"name"`
	IsSelfSigned bool   `json:"is_self_signed"`
	PEM          string `json:"pem"`
	Source       string `json:"source,omitempty"`
	InputIndex   int    `json:"input_index,omitempty"`
	Trusted      bool   `json:"trusted"`
}

func newPathNode(cert *x509.Certificate, source string, inputIndex int, trusted bool) PathNode {
	simple := newSimpleVerifyCert(cert)
	return PathNode{
		Name:         simple.Name,
		IsSelfSigned: simple.IsSelfSigned,
		PEM:          simple.PEM,
		Source:       source,
		InputIndex:   inputIndex,
		Trusted:      trusted,
	}
}

// ChainReport ties one path to the anchor that terminated it. Chain order is
// deterministic, so on a successful result ChainReports[i] describes
// Chains[i]. On a failed result ChainReports may contain one invalid entry
// describing the attempted path. Valid reports whether the path itself
// reached a trusted anchor; FailurePath may also be set for a failed
// revocation check on an otherwise valid path.
type ChainReport struct {
	Index          int          `json:"index"`
	PolicyVersion  string       `json:"policy_version"`
	RootSetVersion string       `json:"root_set_version"`
	Anchor         *PathNode    `json:"anchor,omitempty"`
	Valid          bool         `json:"valid"`
	FailurePath    *FailurePath `json:"failure_path,omitempty"`
}

// FailurePath describes where path construction or policy checking stopped.
// Index is a zero-based position in Path; it is -1 when the failing
// certificate could not be located in the attempted path.
type FailurePath struct {
	Stage       string     `json:"stage"`
	Reason      string     `json:"reason"`
	Chain       int        `json:"chain,omitempty"`
	Index       int        `json:"index"`
	Position    string     `json:"position"`
	Certificate *PathNode  `json:"certificate,omitempty"`
	Hint        *PathNode  `json:"hint_certificate,omitempty"`
	Anchor      *PathNode  `json:"anchor,omitempty"`
	Path        []PathNode `json:"path,omitempty"`
}

type SimpleVerification struct {
	Error          string               `json:"error,omitempty"`
	OCSPStatus     *ocsp.Response       `json:"ocsp_response,omitempty"`
	OCSPWasStapled bool                 `json:"ocsp_was_stapled,omitempty"`
	OCSPError      string               `json:"ocsp_error,omitempty"`
	PolicyVersion  string               `json:"policy_version,omitempty"`
	RootSetVersion string               `json:"root_set_version,omitempty"`
	RootSource     string               `json:"root_source,omitempty"`
	RootCount      int                  `json:"root_count"`
	Roots          []PathNode           `json:"roots,omitempty"`
	Chains         [][]simpleVerifyCert `json:"chains"`

	// Anchors is parallel to Chains. ChainReports contains the same anchors
	// plus the policy version that produced each path.
	Anchors      []PathNode    `json:"anchors,omitempty"`
	ChainReports []ChainReport `json:"chain_reports,omitempty"`
	FailurePath  *FailurePath  `json:"failure_path,omitempty"`
}

// Verified reports whether this result contains at least one valid chain and
// every reported chain has a trusted anchor. Exit code and report therefore
// come from the same evidence.
func (s SimpleVerification) Verified() bool {
	if s.Error != "" || s.FailurePath != nil || len(s.Chains) == 0 {
		return false
	}
	if len(s.Anchors) != len(s.Chains) || len(s.ChainReports) != len(s.Chains) {
		return false
	}
	for i, report := range s.ChainReports {
		if !report.Valid || report.Anchor == nil || !report.Anchor.Trusted {
			return false
		}
		if report.Anchor.PEM != s.Anchors[i].PEM {
			return false
		}
	}
	return true
}

// ExitCode returns the process exit code implied by this report.
func (s SimpleVerification) ExitCode() int {
	if s.Verified() {
		return 0
	}
	return 1
}

// VerificationPolicy is an immutable snapshot of the trust roots and path
// validation rules for one verification. Loading the policy reads the CA
// bundle (or the system trust store) exactly once, so a bundle update cannot
// change which anchors are used halfway through a verification, and the
// report describes the same roots that produced the decision.
type VerificationPolicy struct {
	version        string
	rootSource     string
	roots          []*x509.Certificate
	rootsKnown     bool
	system         bool
	rootSetVersion string
	rootPool       *x509.CertPool
}

// Version returns the path-validation policy version.
func (p *VerificationPolicy) Version() string {
	if p == nil {
		return ""
	}
	return p.version
}

// RootSetVersion returns a stable digest of the snapshotted roots. Reordering
// a CA bundle does not change it; adding or removing a root does.
func (p *VerificationPolicy) RootSetVersion() string {
	if p == nil {
		return ""
	}
	return p.rootSetVersion
}

// RootSource returns the CA bundle path, or "system" for the system store.
func (p *VerificationPolicy) RootSource() string {
	if p == nil {
		return ""
	}
	return p.rootSource
}

// RootCount returns the number of snapshotted roots, or -1 when the platform
// supplied an opaque system pool that cannot be enumerated.
func (p *VerificationPolicy) RootCount() int {
	if p == nil || !p.rootsKnown {
		return -1
	}
	return len(p.roots)
}

// Roots returns a copy of the snapshotted root certificates.
func (p *VerificationPolicy) Roots() []*x509.Certificate {
	if p == nil {
		return nil
	}
	return append([]*x509.Certificate(nil), p.roots...)
}

func (p *VerificationPolicy) isRoot(cert *x509.Certificate) bool {
	if p == nil || cert == nil {
		return false
	}
	for _, root := range p.roots {
		if bytes.Equal(root.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// NewVerificationPolicy snapshots the given roots. The caller must not mutate
// the certificates afterwards. Use LoadVerificationPolicy when a CA path or
// the system trust store should be read.
func NewVerificationPolicy(roots []*x509.Certificate, source string) *VerificationPolicy {
	if source == "" {
		source = "provided"
	}
	return makeVerificationPolicy(roots, source, true, false, nil)
}

func makeVerificationPolicy(roots []*x509.Certificate, source string, rootsKnown, system bool, pool *x509.CertPool) *VerificationPolicy {
	normalized := normalizeRoots(roots)
	if pool == nil {
		pool = x509.NewCertPool()
		for _, root := range normalized {
			pool.AddCert(root)
		}
	}
	return &VerificationPolicy{
		version:        VerificationPolicyVersion,
		rootSource:     source,
		roots:          normalized,
		rootsKnown:     rootsKnown,
		system:         system,
		rootSetVersion: computeRootSetVersion(normalized, rootsKnown),
		rootPool:       pool,
	}
}

// LoadVerificationPolicy reads the trust roots once. A non-empty caPath is
// read on every call, so a root removed from the bundle cannot anchor a later
// verification. With no caPath, Linux CA bundle files are read fresh (rather
// than using Go's process-wide cached SystemCertPool); other platforms fall
// back to SystemCertPool.
func LoadVerificationPolicy(caPath string) (*VerificationPolicy, error) {
	if caPath != "" {
		certs, err := readCACertificates(caPath)
		if err != nil {
			return nil, err
		}
		return makeVerificationPolicy(certs, caPath, true, false, nil), nil
	}

	// Windows, macOS, and iOS use platform verifiers backed by the OS trust
	// store. Keep using SystemCertPool there instead of a possibly stale
	// Unix-style PEM bundle.
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("error loading system roots: %w", err)
		}
		if pool == nil {
			return nil, errors.New("system roots are not available")
		}
		return makeVerificationPolicy(nil, "system", false, true, pool), nil
	}

	certs, err := loadSystemRootCertificates()
	if err == nil && len(certs) > 0 {
		return makeVerificationPolicy(certs, "system", true, true, nil), nil
	}
	if err != nil && (os.Getenv("SSL_CERT_FILE") != "" || os.Getenv("SSL_CERT_DIR") != "" || !errors.Is(err, os.ErrNotExist)) {
		return nil, err
	}

	pool, poolErr := x509.SystemCertPool()
	if poolErr != nil {
		if err != nil {
			return nil, fmt.Errorf("error loading system roots: %w", errors.Join(err, poolErr))
		}
		return nil, fmt.Errorf("error loading system roots: %w", poolErr)
	}
	if pool == nil {
		return nil, errors.New("system roots are not available")
	}
	return makeVerificationPolicy(nil, "system", false, true, pool), nil
}

func readCACertificates(caPath string) ([]*x509.Certificate, error) {
	caFile, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("error opening CA bundle %s: %w", caPath, err)
	}
	defer func() { _ = caFile.Close() }()

	var certs []*x509.Certificate
	err = ReadAsX509FromFiles(
		[]*os.File{caFile},
		"",
		func(string) string {
			// TODO: The JDK trust store ships with this password.
			return "changeit"
		},
		func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return fmt.Errorf("error parsing CA bundle: %w", err)
			}
			if cert != nil {
				certs = append(certs, cert)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("error parsing CA bundle: %w", err)
	}
	return certs, nil
}

// caBundle is retained for callers that only need the trust pool. New
// verification code should use LoadVerificationPolicy so the certificate list
// and pool are snapshotted together with the report.
func caBundle(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}
	certs, err := readCACertificates(caPath)
	if err != nil {
		return nil, err
	}
	bundle := x509.NewCertPool()
	for _, cert := range certs {
		bundle.AddCert(cert)
	}
	return bundle, nil
}

// Keep the compatibility helper referenced for in-package callers;
// verification itself goes through the policy loader.
var _ = caBundle

var systemRootBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
	"/usr/local/etc/ssl/cert.pem",
	"/usr/local/share/certs/ca-root-nss.crt",
	"/etc/openssl/certs/ca-certificates.crt",
	"/etc/certs/ca-certificates.crt",
	"/etc/ssl/cacert.pem",
	"/var/ssl/certs/ca-bundle.crt",
}

var systemRootCertDirectories = []string{
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
	"/usr/local/share/certs",
	"/etc/openssl/certs",
	"/etc/certs/CA",
	"/var/ssl/certs",
	"/system/etc/security/cacerts",
	"/data/misc/keychain/certs-added",
}

func loadSystemRootCertificates() ([]*x509.Certificate, error) {
	fileFromEnv := os.Getenv("SSL_CERT_FILE")
	dirFromEnv := os.Getenv("SSL_CERT_DIR")
	files := systemRootBundlePaths
	if fileFromEnv != "" {
		files = []string{fileFromEnv}
	}

	var certs []*x509.Certificate
	var firstErr error
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			if firstErr == nil && !errors.Is(err, os.ErrNotExist) {
				firstErr = err
			}
			continue
		}
		certs = append(certs, parseRootCertificates(data)...)
		break
	}

	dirs := systemRootCertDirectories
	if dirFromEnv != "" {
		dirs = filepath.SplitList(dirFromEnv)
	}
	for _, dir := range dirs {
		certs = append(certs, loadCertificatesFromDirectory(dir)...)
	}

	if len(certs) > 0 {
		return certs, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, os.ErrNotExist
}

func loadCertificatesFromDirectory(dir string) []*x509.Certificate {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var certs []*x509.Certificate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		certs = append(certs, parseRootCertificates(data)...)
	}
	return certs
}

func parseRootCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		if parsed, err := x509.ParseCertificates(data); err == nil {
			certs = append(certs, parsed...)
		}
	}
	return certs
}

func normalizeRoots(certs []*x509.Certificate) []*x509.Certificate {
	seen := make(map[string]struct{}, len(certs))
	roots := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		key := string(cert.Raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		roots = append(roots, cert)
	}
	sort.Slice(roots, func(i, j int) bool {
		return bytes.Compare(roots[i].Raw, roots[j].Raw) < 0
	})
	return roots
}

func computeRootSetVersion(roots []*x509.Certificate, known bool) string {
	h := sha256.New()
	_, _ = h.Write([]byte(VerificationPolicyVersion))
	_, _ = h.Write([]byte{0})
	if !known {
		_, _ = h.Write([]byte("system-pool"))
	} else {
		_, _ = h.Write([]byte("root-set"))
		for _, root := range roots {
			sum := sha256.Sum256(root.Raw)
			_, _ = h.Write(sum[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

type SimpleResult struct {
	Certificates           []*x509.Certificate `json:"certificates"`
	Formats                []string
	VerifyResult           *SimpleVerification `json:"verify_result,omitempty"`
	TLSConnectionState     *tls.ConnectionState
	CertificateRequestInfo *tls.CertificateRequestInfo
}

func (s SimpleResult) MarshalJSON() ([]byte, error) {
	certs := make([]interface{}, len(s.Certificates))
	for i, c := range s.Certificates {
		certs[i] = EncodeX509ToObject(c)
	}

	out := map[string]interface{}{}
	out["certificates"] = certs
	if s.VerifyResult != nil {
		out["verify_result"] = s.VerifyResult
	}
	if s.TLSConnectionState != nil {
		out["tls_connection"] = EncodeTLSToObject(s.TLSConnectionState)
	}
	if s.CertificateRequestInfo != nil {
		encoded, err := EncodeCRIToObject(s.CertificateRequestInfo)
		if err != nil {
			return nil, err
		}
		out["certificate_request_info"] = encoded
	}
	return json.Marshal(out)
}

// VerifyChain snapshots the trust roots and validates the chain against that
// one snapshot. It is the compatibility entry point used by the CLI.
func VerifyChain(certs []*x509.Certificate, ocspStaple []byte, expectedName, caPath string) SimpleVerification {
	policy, err := LoadVerificationPolicy(caPath)
	if err != nil {
		result := newSimpleVerification(nil, ocspStaple)
		result.Error = err.Error() + "\n"
		if caPath == "" {
			result.RootSource = "system"
		} else {
			result.RootSource = caPath
		}
		result.FailurePath = &FailurePath{
			Stage:    "policy",
			Reason:   err.Error(),
			Index:    -1,
			Position: "root_set",
		}
		return result
	}
	return VerifyChainWithPolicy(policy, certs, ocspStaple, expectedName)
}

// VerifyChainWithPolicy validates the chain against an already snapshotted
// policy. Reusing a policy guarantees that validation and every reported
// anchor come from the same root set even if the underlying CA file changes.
func VerifyChainWithPolicy(policy *VerificationPolicy, certs []*x509.Certificate, ocspStaple []byte, expectedName string) SimpleVerification {
	result := newSimpleVerification(policy, ocspStaple)
	if policy == nil {
		result.Error = "verification policy is nil"
		result.FailurePath = &FailurePath{
			Stage:    "policy",
			Reason:   result.Error,
			Index:    -1,
			Position: "policy",
		}
		return result
	}
	if policy.rootPool == nil {
		result.Error = "verification policy has no root pool"
		result.FailurePath = &FailurePath{
			Stage:    "policy",
			Reason:   result.Error,
			Index:    -1,
			Position: "root_set",
		}
		return result
	}
	if len(certs) == 0 || certs[0] == nil {
		result.Error = "no certificates found"
		result.FailurePath = &FailurePath{
			Stage:    "input",
			Reason:   result.Error,
			Index:    -1,
			Position: "input",
		}
		return result
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		if certs[i] != nil {
			intermediates.AddCert(certs[i])
		}
	}

	// expectedName could be a hostname or could be a SPIFFE ID (spiffe://...)
	// x509 package doesn't support verifying SPIFFE IDs. When we're expecting
	// a SPIFFE ID, we tell Certificate.Verify below to skip name matching,
	// and then we perform our own matching later on.
	spiffeIDExpected := strings.HasPrefix(strings.ToLower(expectedName), "spiffe://")
	var expectedDNSName string
	if !spiffeIDExpected {
		expectedDNSName = expectedName
	}
	opts := x509.VerifyOptions{
		DNSName:       expectedDNSName,
		Roots:         policy.rootPool,
		Intermediates: intermediates,
		// Freeze one verification time for every chain in this result.
		CurrentTime: time.Now(),
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Error = err.Error()
		recordFailure(&result, policy, describeVerificationFailure(err, certs, policy))
		return result
	}

	if spiffeIDExpected {
		// The Verify method above didn't actually verify that the certificate
		// matches the expected SPIFFE ID. We thus perform this check
		// explicitly here.
		if err := verifyCertificateSPIFFEIDMatch(certs[0], expectedName); err != nil {
			result.Error = err.Error()
			recordFailure(&result, policy, newLeafFailure("spiffe", err, certs[0], policy))
			return result
		}
	}

	chains = normalizeChains(chains)
	if len(chains) == 0 {
		result.Error = "no valid certificate chains found"
		recordFailure(&result, policy, &FailurePath{
			Stage:    "chain",
			Reason:   result.Error,
			Index:    -1,
			Position: "chain",
		})
		return result
	}

	for chainIndex, chain := range chains {
		status, ocspErr := checkOCSP(chain, ocspStaple)
		if ocspErr == nil {
			result.OCSPStatus = status
		}
		if ocspErr != nil && !errors.Is(ocspErr, errSkippedRevocationCheck) {
			result.OCSPError = ocspErr.Error()
		}

		aChain := make([]simpleVerifyCert, 0, len(chain))
		for _, cert := range chain {
			aChain = append(aChain, newSimpleVerifyCert(cert))
		}

		anchorCert := chain[len(chain)-1]
		anchorTrusted := true
		if policy.rootsKnown {
			anchorTrusted = policy.isRoot(anchorCert)
		}
		anchor := newPathNode(anchorCert, "anchor", -1, anchorTrusted)
		report := ChainReport{
			Index:          chainIndex,
			PolicyVersion:  policy.Version(),
			RootSetVersion: policy.RootSetVersion(),
			Anchor:         &anchor,
			Valid:          anchorTrusted,
		}
		if !anchorTrusted {
			report.FailurePath = &FailurePath{
				Stage:       "anchor",
				Reason:      fmt.Sprintf("certificate chain terminated at %s, which is not in the snapshotted root set", anchor.Name),
				Chain:       chainIndex,
				Index:       len(chain) - 1,
				Position:    "anchor",
				Certificate: &anchor,
				Anchor:      &anchor,
				Path:        pathNodesForChain(chain, certs, policy),
			}
		}
		if ocspErr != nil && !errors.Is(ocspErr, errSkippedRevocationCheck) {
			pathNodes := pathNodesForChain(chain, certs, policy)
			ocspFailure := &FailurePath{
				Stage:    "ocsp",
				Reason:   ocspErr.Error(),
				Chain:    chainIndex,
				Index:    0,
				Position: "leaf",
				Anchor:   &anchor,
				Path:     pathNodes,
			}
			if len(pathNodes) > 0 {
				ocspFailure.Certificate = &pathNodes[0]
			}
			report.FailurePath = ocspFailure
		}
		result.Chains = append(result.Chains, aChain)
		result.Anchors = append(result.Anchors, anchor)
		result.ChainReports = append(result.ChainReports, report)
	}
	for _, report := range result.ChainReports {
		if !report.Valid && report.FailurePath != nil {
			result.Error = report.FailurePath.Reason
			result.FailurePath = report.FailurePath
			break
		}
	}
	return result
}

func recordFailure(result *SimpleVerification, policy *VerificationPolicy, failure *FailurePath) {
	if result == nil {
		return
	}
	result.FailurePath = failure
	if policy == nil || failure == nil || (failure.Certificate == nil && len(failure.Path) == 0) {
		return
	}
	result.ChainReports = append(result.ChainReports, ChainReport{
		Index:          0,
		PolicyVersion:  policy.Version(),
		RootSetVersion: policy.RootSetVersion(),
		Anchor:         failure.Anchor,
		Valid:          false,
		FailurePath:    failure,
	})
}

func pathNodesForChain(chain []*x509.Certificate, certs []*x509.Certificate, policy *VerificationPolicy) []PathNode {
	nodes := make([]PathNode, 0, len(chain))
	for i, cert := range chain {
		if i == len(chain)-1 {
			trusted := true
			if policy != nil && policy.rootsKnown {
				trusted = policy.isRoot(cert)
			}
			nodes = append(nodes, newPathNode(cert, "anchor", -1, trusted))
			continue
		}
		nodes = append(nodes, pathNodeForCertificate(cert, certs, policy))
	}
	return nodes
}

func newSimpleVerification(policy *VerificationPolicy, ocspStaple []byte) SimpleVerification {
	result := SimpleVerification{
		Chains:         [][]simpleVerifyCert{},
		Anchors:        []PathNode{},
		ChainReports:   []ChainReport{},
		OCSPWasStapled: ocspStaple != nil,
		PolicyVersion:  VerificationPolicyVersion,
	}
	if policy == nil {
		return result
	}
	result.PolicyVersion = policy.Version()
	result.RootSetVersion = policy.RootSetVersion()
	result.RootSource = policy.RootSource()
	if count := policy.RootCount(); count >= 0 {
		result.RootCount = count
	}
	// The system trust store can contain hundreds of roots; the digest and
	// count are sufficient there. Explicit CA bundles are small enough to
	// include in the report so callers can audit the exact root set.
	if !policy.system {
		roots := policy.Roots()
		result.Roots = make([]PathNode, 0, len(roots))
		for _, root := range roots {
			result.Roots = append(result.Roots, newPathNode(root, "anchor", -1, true))
		}
		if len(result.Roots) == 0 {
			result.Roots = nil
		}
	}
	return result
}

func newSimpleVerifyCert(cert *x509.Certificate) simpleVerifyCert {
	return simpleVerifyCert{
		Name:               PrintCommonName(cert.Subject),
		IsSelfSigned:       IsSelfSigned(cert),
		PEM:                string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil))),
		signatureAlgorithm: cert.SignatureAlgorithm,
	}
}

func normalizeChains(chains [][]*x509.Certificate) [][]*x509.Certificate {
	out := make([][]*x509.Certificate, 0, len(chains))
	seen := make(map[string]struct{}, len(chains))
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		valid := true
		for _, cert := range chain {
			if cert == nil {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		key := chainFingerprint(chain)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, chain)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai := out[i][len(out[i])-1]
		aj := out[j][len(out[j])-1]
		if cmp := bytes.Compare(ai.Raw, aj.Raw); cmp != 0 {
			return cmp < 0
		}
		return chainFingerprint(out[i]) < chainFingerprint(out[j])
	})
	return out
}

func chainFingerprint(chain []*x509.Certificate) string {
	h := sha256.New()
	for _, cert := range chain {
		sum := sha256.Sum256(cert.Raw)
		_, _ = h.Write(sum[:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func newLeafFailure(stage string, err error, leaf *x509.Certificate, policy *VerificationPolicy) *FailurePath {
	trusted := policy != nil && policy.isRoot(leaf)
	source := "input"
	if trusted {
		source = "anchor"
	}
	node := newPathNode(leaf, source, 0, trusted)
	failure := &FailurePath{
		Stage:       stage,
		Reason:      err.Error(),
		Index:       0,
		Position:    "leaf",
		Certificate: &node,
		Path:        []PathNode{node},
	}
	if trusted {
		failure.Anchor = &node
	}
	return failure
}

func describeVerificationFailure(err error, certs []*x509.Certificate, policy *VerificationPolicy) *FailurePath {
	failure := &FailurePath{
		Stage:    "chain",
		Reason:   err.Error(),
		Index:    -1,
		Position: "unknown",
	}
	if len(certs) > 0 && certs[0] != nil {
		failure.Path = buildAttemptedPath(certs[0], certs[1:], policy)
		failure.Anchor = pathAnchor(failure.Path)
	}

	var (
		hostnameErr      x509.HostnameError
		unknownAuthority x509.UnknownAuthorityError
		invalidCert      x509.CertificateInvalidError
		constraintErr    x509.ConstraintViolationError
		insecureAlg      x509.InsecureAlgorithmError
		systemRoots      x509.SystemRootsError
	)
	switch {
	case errors.As(err, &hostnameErr):
		failure.Stage = "hostname"
		failure.setCertificate(hostnameErr.Certificate, certs, policy)
	case errors.As(err, &unknownAuthority):
		failure.Stage = "chain"
		failure.setCertificate(unknownAuthority.Cert, certs, policy)
	case errors.As(err, &invalidCert):
		failure.Stage = "chain"
		failure.setCertificate(invalidCert.Cert, certs, policy)
	case errors.As(err, &constraintErr):
		failure.Stage = "constraints"
	case errors.As(err, &insecureAlg):
		failure.Stage = "algorithm"
	case errors.As(err, &systemRoots):
		failure.Stage = "policy"
	}

	if failure.Certificate == nil && len(failure.Path) > 0 {
		last := failure.Path[len(failure.Path)-1]
		failure.Certificate = &last
	}
	if failure.Hint == nil && failure.Anchor != nil && !failure.Anchor.Trusted {
		hint := *failure.Anchor
		failure.Hint = &hint
	}
	failure.finalizeIndex()
	return failure
}

func (f *FailurePath) setCertificate(cert *x509.Certificate, certs []*x509.Certificate, policy *VerificationPolicy) {
	if f == nil || cert == nil {
		return
	}
	node := pathNodeForCertificate(cert, certs, policy)
	f.Certificate = &node
	if !pathContainsCertificate(f.Path, cert) {
		f.Path = append(f.Path, node)
	}
}

func (f *FailurePath) finalizeIndex() {
	if f == nil {
		return
	}
	if f.Certificate == nil {
		f.Index = -1
		if f.Position == "" {
			f.Position = "unknown"
		}
		return
	}
	for i := range f.Path {
		if f.Path[i].PEM == f.Certificate.PEM {
			f.Index = i
			f.Position = pathPosition(f.Path, i)
			return
		}
	}
	f.Index = -1
	f.Position = "reported"
}

func pathPosition(path []PathNode, index int) string {
	if index < 0 || index >= len(path) {
		return "unknown"
	}
	if index == 0 {
		return "leaf"
	}
	node := path[index]
	if node.Source == "anchor" {
		return "anchor"
	}
	if node.Source == "input" && node.InputIndex > 0 {
		return fmt.Sprintf("intermediate[%d] (input[%d])", index-1, node.InputIndex)
	}
	return fmt.Sprintf("path[%d]", index)
}

func buildAttemptedPath(leaf *x509.Certificate, intermediates []*x509.Certificate, policy *VerificationPolicy) []PathNode {
	if leaf == nil {
		return nil
	}
	trusted := policy != nil && policy.isRoot(leaf)
	source := "input"
	if trusted {
		source = "anchor"
	}
	nodes := []PathNode{newPathNode(leaf, source, 0, trusted)}
	used := map[string]struct{}{string(leaf.Raw): {}}
	current := leaf

	for {
		if policy != nil && policy.isRoot(current) {
			nodes[len(nodes)-1].Source = "anchor"
			nodes[len(nodes)-1].Trusted = true
			break
		}
		issuer, issuerSource, inputIndex, ok := findIssuer(current, intermediates, policy, used)
		if !ok {
			if IsSelfSigned(current) {
				nodes[len(nodes)-1].Source = "anchor"
			}
			break
		}
		used[string(issuer.Raw)] = struct{}{}
		nodes = append(nodes, newPathNode(issuer, issuerSource, inputIndex, policy != nil && policy.isRoot(issuer)))
		current = issuer
		if len(nodes) > len(intermediates)+len(policyRoots(policy))+2 {
			// Defensive cycle guard. A well-formed path cannot be longer than
			// the supplied intermediates plus the root set plus the leaf.
			break
		}
	}
	return nodes
}

func policyRoots(policy *VerificationPolicy) []*x509.Certificate {
	if policy == nil {
		return nil
	}
	return policy.roots
}

func findIssuer(current *x509.Certificate, intermediates []*x509.Certificate, policy *VerificationPolicy, used map[string]struct{}) (*x509.Certificate, string, int, bool) {
	type candidate struct {
		cert       *x509.Certificate
		source     string
		inputIndex int
	}
	candidates := make([]candidate, 0, len(intermediates)+len(policyRoots(policy)))
	for i, cert := range intermediates {
		if cert == nil {
			continue
		}
		if _, ok := used[string(cert.Raw)]; ok {
			continue
		}
		candidates = append(candidates, candidate{cert: cert, source: "input", inputIndex: i + 1})
	}
	if policy != nil {
		for _, cert := range policy.roots {
			if cert == nil {
				continue
			}
			if _, ok := used[string(cert.Raw)]; ok {
				continue
			}
			candidates = append(candidates, candidate{cert: cert, source: "anchor", inputIndex: -1})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return issuerScore(current, candidates[i].cert) > issuerScore(current, candidates[j].cert)
	})
	for _, candidate := range candidates {
		if !bytes.Equal(current.RawIssuer, candidate.cert.RawSubject) {
			continue
		}
		if current.CheckSignatureFrom(candidate.cert) != nil {
			continue
		}
		return candidate.cert, candidate.source, candidate.inputIndex, true
	}
	// Some valid chains use equivalent but differently encoded names. Fall
	// back to the signature check, which is authoritative.
	for _, candidate := range candidates {
		if current.CheckSignatureFrom(candidate.cert) == nil {
			return candidate.cert, candidate.source, candidate.inputIndex, true
		}
	}
	return nil, "", 0, false
}

func issuerScore(child, parent *x509.Certificate) int {
	score := 0
	if bytes.Equal(child.RawIssuer, parent.RawSubject) {
		score += 4
	}
	if len(child.AuthorityKeyId) > 0 && bytes.Equal(child.AuthorityKeyId, parent.SubjectKeyId) {
		score += 8
	}
	if IsSelfSigned(parent) {
		score++
	}
	return score
}

func pathNodeForCertificate(cert *x509.Certificate, certs []*x509.Certificate, policy *VerificationPolicy) PathNode {
	for i, input := range certs {
		if input == nil || !bytes.Equal(input.Raw, cert.Raw) {
			continue
		}
		trusted := policy != nil && policy.isRoot(input)
		source := "input"
		if trusted || IsSelfSigned(input) {
			source = "anchor"
		}
		return newPathNode(cert, source, i, trusted)
	}
	if policy != nil && policy.isRoot(cert) {
		return newPathNode(cert, "anchor", -1, true)
	}
	source := "reported"
	if IsSelfSigned(cert) {
		source = "anchor"
	}
	return newPathNode(cert, source, -1, false)
}

func pathContainsCertificate(path []PathNode, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	certPEM := string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil)))
	for _, node := range path {
		if node.PEM == certPEM {
			return true
		}
	}
	return false
}

func pathAnchor(path []PathNode) *PathNode {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i].Trusted || path[i].IsSelfSigned {
			node := path[i]
			return &node
		}
	}
	return nil
}

func fmtCert(cert simpleVerifyCert) string {
	name := cert.Name
	if cert.IsSelfSigned {
		name += green.SprintfFunc()(" [self-signed]")
	}
	for _, alg := range badSignatureAlgorithms {
		if cert.signatureAlgorithm == alg {
			name += red.SprintfFunc()(" [%s]", algString(alg))
			break
		}
	}
	return name
}

func PrintVerifyResult(out io.Writer, result SimpleVerification) {
	if result.Error != "" || result.FailurePath != nil {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Failed to verify certificate chain:"))
		switch {
		case result.Error != "":
			_, _ = fmt.Fprintf(out, "\t%s\n", result.Error)
		case result.FailurePath.Reason != "":
			_, _ = fmt.Fprintf(out, "\t%s\n", result.FailurePath.Reason)
		}
		printFailurePath(out, result.FailurePath)
		return
	}

	printOCSPStatus(out, result)
	printCertificateChains(out, result)
}

func printFailurePath(out io.Writer, failure *FailurePath) {
	if failure == nil {
		return
	}
	if failure.Stage != "" {
		_, _ = fmt.Fprintf(out, "\tFailure stage: %s\n", failure.Stage)
	}
	if failure.Certificate != nil {
		if failure.Index >= 0 {
			_, _ = fmt.Fprintf(out, "\tFailure position: %s (index %d)\n", failure.Position, failure.Index)
		} else {
			_, _ = fmt.Fprintf(out, "\tFailure position: %s\n", failure.Position)
		}
		_, _ = fmt.Fprintf(out, "\tFailure certificate: %s\n", failure.Certificate.Name)
	}
	if failure.Hint != nil && (failure.Certificate == nil || failure.Hint.PEM != failure.Certificate.PEM) {
		_, _ = fmt.Fprintf(out, "\tCandidate issuer: %s\n", failure.Hint.Name)
	}
	if len(failure.Path) > 0 {
		_, _ = fmt.Fprint(out, "\tAttempted path:\n")
		for i, node := range failure.Path {
			suffix := ""
			if i == failure.Index {
				suffix += " <-- failed"
			}
			if !node.Trusted && node.Source == "anchor" {
				suffix += " [untrusted]"
			}
			_, _ = fmt.Fprintf(out, "\t\t[%d] %s%s\n", i, node.Name, suffix)
		}
	}
	_, _ = fmt.Fprint(out, "\n")
}

func printCertificateChains(out io.Writer, result SimpleVerification) {
	_, _ = fmt.Fprint(out, green.SprintfFunc()("Found %d valid certificate chain(s):\n", len(result.Chains)))
	for i, chain := range result.Chains {
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i, fmtCert(chain[0]))
		for j, cert := range chain {
			if j == 0 {
				continue
			}
			_, _ = fmt.Fprintf(out, "\t=> %s\n", fmtCert(cert))
		}
	}
}

func printOCSPStatus(out io.Writer, result SimpleVerification) {
	if result.OCSPError != "" {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Certificate has OCSP extension, but was unable to check status:"))
		_, _ = fmt.Fprintf(out, "\t%s\n\n", result.OCSPError)
		return
	}

	if result.OCSPStatus != nil {
		status, ok := revocationStatusDescription[result.OCSPStatus.Status]
		if !ok {
			status = "Unknown"
		}

		color, ok := revocationStatusColor[result.OCSPStatus.Status]
		if !ok {
			color = yellow
		}

		wasStapled := ""
		if result.OCSPWasStapled {
			wasStapled = " (was stapled)"
		}

		_, _ = fmt.Fprint(out, color.SprintfFunc()("Checked OCSP status for certificate%s, got:", wasStapled))
		_, _ = fmt.Fprintf(out, "\n\t%s (last update: %s)", status, result.OCSPStatus.ProducedAt.Format(time.RFC822))

		if result.OCSPStatus.Status == ocsp.Revoked {
			reason, ok := revocationReasonDescription[result.OCSPStatus.RevocationReason]
			if !ok {
				reason = "Unknown"
			}

			_, _ = fmt.Fprintf(out, "\n\tWas revoked at %s due to: %s", result.OCSPStatus.RevokedAt.Format(time.RFC822), reason)
		}

		_, _ = fmt.Fprint(out, "\n\n")
	}
}

func verifyCertificateSPIFFEIDMatch(cert *x509.Certificate, expectedSPIFFEID string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
	uris := cert.URIs
	if len(uris) == 0 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains no URI SANs", expectedSPIFFEID)
	} else if len(uris) > 1 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains %d URIs SANs instead of exactly 1", expectedSPIFFEID, len(uris))
	}

	uri := uris[0]
	actualSPIFFEID := uri.String()
	err := verifySPIFFEIDMatch(expectedSPIFFEID, actualSPIFFEID)
	if err != nil {
		return fmt.Errorf("x509: certificate is valid for %s, not %s: %s", actualSPIFFEID, expectedSPIFFEID, err)
	}

	// Matched
	return nil
}

func verifySPIFFEIDMatch(expected string, actual string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
	// SPIFFE ID format: spiffe://trust-domain-name/path
	// * scheme and authority of the URI are case-insensitive
	// * path of the URI is case-sensitive
	//
	// However, as per Trust Domain and Path sections, authority is not supposed to include userinfo
	// and authority's host is supposed to be lower-case and no %-escaped characters. Similarly, no
	// %-escaped stuff in the path.
	//
	// Thus, all we need to do is verify that:
	// 1. both IDs start with "spiffe://" (case-insensitive)
	// 2. both IDs equal (case-sensitive) after the "spiffe://"

	// Verify both have "spiffe" as the scheme (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(expected), "spiffe://") {
		return fmt.Errorf("expected scheme is not \"spiffe\"")
	}
	if !strings.HasPrefix(strings.ToLower(actual), "spiffe://") {
		return fmt.Errorf("actual scheme is not \"spiffe\"")
	}

	// Verify that everything after the scheme equals in a case-sensitive way
	expectedRemainder := expected[len("spiffe://"):]
	actualRemainder := actual[len("spiffe://"):]
	if expectedRemainder != actualRemainder {
		return fmt.Errorf("trust domain and/or path do not match")
	}

	// They match
	return nil
}
