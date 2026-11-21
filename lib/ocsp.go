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
	"crypto/sha1" //nolint:gosec // SHA-1 is required by RFC 6960 for OCSP responder key hashes.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ocsp"
)

var (
	errSkippedRevocationCheck = errors.New("skipped revocation check")

	revocationStatusColor = map[int]*color.Color{
		ocsp.Good:    green,
		ocsp.Revoked: red,
		ocsp.Unknown: yellow,
	}

	revocationStatusDescription = map[int]string{
		ocsp.Good:    "Good",
		ocsp.Revoked: "Revoked",
		ocsp.Unknown: "Unknown",
	}

	revocationReasonDescription = map[int]string{
		ocsp.Unspecified:          "Unspecified",
		ocsp.KeyCompromise:        "KeyCompromise",
		ocsp.CACompromise:         "CACompromise",
		ocsp.AffiliationChanged:   "AffiliationChanged",
		ocsp.Superseded:           "Superseded",
		ocsp.CessationOfOperation: "CessationOfOperation",
		ocsp.CertificateHold:      "CertificateHold",
		ocsp.RemoveFromCRL:        "RemoveFromCRL",
		ocsp.PrivilegeWithdrawn:   "PrivilegeWithdrawn",
		ocsp.AACompromise:         "AACompromise",
	}

	ocspHttpClient = &http.Client{
		// Set a timeout so we don't block forever on broken servers.
		Timeout: 5 * time.Second,
	}
)

const (
	// We retry multiple times, because OCSP servers are often a bit unreliable.
	maxOCSPValidationRetries = 3

	// OCSP produced-at times are commonly truncated to the minute, and
	// responders may have a slightly different clock than the CA. Allow a
	// small grace period when checking the responder certificate's validity.
	ocspResponderClockSkew = 5 * time.Minute
)

type ocspValidationError struct {
	stage string
	err   error
}

func (e *ocspValidationError) Error() string {
	return e.err.Error()
}

func (e *ocspValidationError) Unwrap() error {
	return e.err
}

func newOCSPValidationError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return &ocspValidationError{stage: stage, err: err}
}

func ocspValidationStage(err error) string {
	var validationError *ocspValidationError
	if errors.As(err, &validationError) {
		return validationError.stage
	}
	return "fetch"
}

func ocspStatusName(status int) string {
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func ocspParseErrorStage(err error) string {
	message := err.Error()
	switch {
	case strings.Contains(message, "no response matching"):
		return "serial"
	case strings.Contains(message, "signature"):
		return "signature"
	default:
		return "parse"
	}
}

func checkOCSP(chain []*x509.Certificate, ocspStaple []byte) (status *ocsp.Response, err error) {
	if len(chain) < 2 {
		// Nothing to check here
		return nil, errSkippedRevocationCheck
	}
	if chain[0] == nil || chain[1] == nil {
		return nil, errors.New("invalid certificate chain")
	}

	leaf, issuer := chain[0], chain[1]
	stapled := len(ocspStaple) > 0
	if len(leaf.OCSPServer) == 0 && !stapled {
		return nil, errSkippedRevocationCheck
	}

	if stapled {
		// A stapled response is the server's authoritative answer for this
		// connection. Don't replace it with a freshly fetched response: that
		// could mix certificates, responders, and statuses from different
		// generations of the certificate.
		status, err = parseAndVerifyOCSPResponse(ocspStaple, leaf, issuer)
		if err != nil {
			return nil, err
		}
		return status, nil
	}

	var lastError error
	for i := 0; i < maxOCSPValidationRetries; i++ {
		// Gather every candidate generation for this attempt, then commit
		// exactly one complete response. Fields from different responses are
		// never combined, and an invalid or old candidate cannot replace a
		// valid one.
		responses, err := fetchOCSPResponses(leaf, issuer)
		if err != nil {
			lastError = err
			continue
		}

		status, err = selectOCSPResponse(responses, leaf, issuer)
		if err == nil {
			return status, nil
		}
		lastError = err
	}

	if lastError == nil {
		lastError = errors.New("unable to obtain a valid OCSP response")
	}
	return nil, lastError
}

func checkOCSPWithEvidence(chain []*x509.Certificate, ocspStaple []byte) (*ocsp.Response, *OCSPStatus, error) {
	evidence := &OCSPStatus{
		Source:     "fetched",
		WasStapled: len(ocspStaple) > 0,
	}
	if len(chain) > 0 && chain[0] != nil && chain[0].SerialNumber != nil {
		evidence.SerialNumber = chain[0].SerialNumber.String()
	}
	if evidence.WasStapled {
		evidence.Source = "stapled"
	}

	status, err := checkOCSP(chain, ocspStaple)
	if errors.Is(err, errSkippedRevocationCheck) {
		evidence.Stage = "skipped"
		return nil, evidence, err
	}
	if err != nil {
		evidence.Error = err.Error()
		evidence.Stage = ocspValidationStage(err)
		return nil, evidence, err
	}
	if status == nil {
		err = errors.New("no OCSP response received")
		evidence.Error = err.Error()
		evidence.Stage = "parse"
		return nil, evidence, err
	}

	evidence.Stage = "verified"
	evidence.Status = ocspStatusName(status.Status)
	evidence.ProducedAt = status.ProducedAt
	evidence.ThisUpdate = status.ThisUpdate
	evidence.NextUpdate = status.NextUpdate

	if status.Certificate != nil {
		evidence.Responder = PrintCommonName(status.Certificate.Subject)
	} else if len(chain) > 1 {
		evidence.Responder = PrintCommonName(chain[1].Subject)
	}

	if status.Status == ocsp.Revoked {
		reason, ok := revocationReasonDescription[status.RevocationReason]
		if !ok {
			reason = "Unknown"
		}
		evidence.RevokedAt = status.RevokedAt
		evidence.RevocationReason = reason
	}

	return status, evidence, nil
}

func fetchOCSP(cert, issuer *x509.Certificate) ([]byte, error) {
	responses, err := fetchOCSPResponses(cert, issuer)
	if err != nil {
		return nil, err
	}
	if len(responses) == 0 {
		return nil, errors.New("no OCSP response received")
	}
	if status, err := selectOCSPResponse(responses, cert, issuer); err == nil {
		return status.Raw, nil
	}
	return responses[0], nil
}

// fetchOCSPResponses asks every OCSP server listed in the certificate for a
// response. Returning all candidate responses lets the caller select one
// complete response generation instead of letting server order decide which
// certificate/responder/status tuple is reported.
func fetchOCSPResponses(cert, issuer *x509.Certificate) ([][]byte, error) {
	encoded, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failure building request: %s", err)
	}

	// Try all the OCSP servers listed in the certificate
	var responses [][]byte
	var errs []error
	for _, server := range cert.OCSPServer {
		bodies, err := fetchOCSPFromServer(server, encoded)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		responses = append(responses, bodies...)
	}

	if len(responses) > 0 {
		return responses, nil
	}
	if len(errs) == 0 {
		errs = append(errs, errors.New("no OCSP servers to query"))
	}
	return nil, errors.Join(errs...)
}

func fetchOCSPFromServer(server string, encoded []byte) ([][]byte, error) {
	// We try both GET and POST requests, because some servers are janky.
	var reqs []*http.Request
	var errs []error
	if len(encoded) < 255 {
		// GET only supported for requests with small payloads, so we can stash
		// them in the path. RFC says 255 bytes encoded, but doesn't mention if that
		// refers to the DER-encoded payload before or after base64 is applied. We
		// just assume it's the former and try both GET and POST in case one fails.
		req, err := buildOCSPwithGET(server, encoded)
		if err != nil {
			errs = append(errs, err)
		} else {
			reqs = append(reqs, req)
		}
	}

	// POST should always be supported, but some servers don't like it.
	req, err := buildOCSPwithPOST(server, encoded)
	if err != nil {
		errs = append(errs, err)
	} else {
		reqs = append(reqs, req)
	}

	var responses [][]byte
	for _, req := range reqs {
		body, err := doOCSPRequest(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("error querying OCSP server %s: %w", server, err))
			continue
		}
		responses = append(responses, body)
	}

	if len(responses) > 0 {
		// Return every response from this server, including ones that fail
		// validation. The caller selects one complete response generation and
		// can report the precise rejection stage. This also prevents a valid
		// older generation on one method from hiding a newer/revoked response
		// on the other.
		return responses, nil
	}
	if len(errs) == 0 {
		errs = append(errs, fmt.Errorf("no OCSP request could be sent to %s", server))
	}
	return nil, errors.Join(errs...)
}

func doOCSPRequest(req *http.Request) ([]byte, error) {
	resp, err := ocspHttpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code, got: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func selectOCSPResponse(responses [][]byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	var (
		best *ocsp.Response
		errs []error
	)
	for _, encoded := range responses {
		status, err := parseAndVerifyOCSPResponse(encoded, leaf, issuer)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if best == nil || preferOCSPResponse(best, status) {
			best = status
		}
	}

	if best != nil {
		return best, nil
	}
	if len(errs) == 0 {
		return nil, errors.New("no OCSP response received")
	}
	return nil, errors.Join(errs...)
}

// parseAndVerifyOCSPResponse binds the response to the certificate being
// checked and verifies the responder that signed it. In particular, it rejects
// responses that are validly signed by the issuer but describe another
// certificate (for example, a cached response from a previous certificate
// generation).
func parseAndVerifyOCSPResponse(encoded []byte, leaf, issuer *x509.Certificate) (*ocsp.Response, error) {
	if leaf == nil || issuer == nil {
		return nil, newOCSPValidationError("parse", errors.New("missing certificate or issuer"))
	}

	status, err := ocsp.ParseResponseForCert(encoded, leaf, issuer)
	if err != nil {
		return nil, newOCSPValidationError(ocspParseErrorStage(err), err)
	}
	if status == nil {
		return nil, newOCSPValidationError("parse", errors.New("empty OCSP response"))
	}

	if status.SerialNumber == nil || leaf.SerialNumber == nil || status.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		return nil, newOCSPValidationError("serial", fmt.Errorf("OCSP response does not match certificate serial %v", leaf.SerialNumber))
	}

	responder := status.Certificate
	if responder == nil {
		// The response was signed directly by the issuing CA.
		if err := status.CheckSignatureFrom(issuer); err != nil {
			return nil, newOCSPValidationError("signature", fmt.Errorf("bad signature on OCSP response: %w", err))
		}
		if err := verifyOCSPResponderID(status, issuer); err != nil {
			return nil, newOCSPValidationError("responder", err)
		}
		return status, nil
	}

	// The embedded responder certificate must have been issued by the same CA
	// that issued the certificate being checked.
	if err := issuer.CheckSignature(responder.SignatureAlgorithm, responder.RawTBSCertificate, responder.Signature); err != nil {
		return nil, newOCSPValidationError("responder", fmt.Errorf("OCSP responder certificate is not signed by the issuer: %w", err))
	}

	// Some responders embed the issuing CA certificate itself instead of
	// leaving the certificate out. That is equivalent to a directly signed
	// response, and the CA does not need an OCSPSigning EKU in that case.
	if bytes.Equal(responder.Raw, issuer.Raw) {
		if err := status.CheckSignatureFrom(issuer); err != nil {
			return nil, newOCSPValidationError("signature", fmt.Errorf("bad signature on OCSP response: %w", err))
		}
		if err := verifyOCSPResponderID(status, issuer); err != nil {
			return nil, newOCSPValidationError("responder", err)
		}
		return status, nil
	}

	// ... and it must be explicitly authorized to sign OCSP responses.
	if !hasOCSPSigningEKU(responder) {
		return nil, newOCSPValidationError("responder", errors.New("OCSP responder certificate is missing the OCSPSigning extended key usage"))
	}

	// Check the responder certificate against the time at which the response
	// was produced, not the current wall clock. The same response must produce
	// the same result across retries and process restarts.
	if !certWasValidAt(responder, status.ProducedAt) {
		return nil, newOCSPValidationError("responder", errors.New("OCSP responder certificate was not valid when the response was produced"))
	}

	if err := status.CheckSignatureFrom(responder); err != nil {
		return nil, newOCSPValidationError("signature", fmt.Errorf("bad signature on OCSP response from delegated responder: %w", err))
	}
	if err := verifyOCSPResponderID(status, responder); err != nil {
		return nil, newOCSPValidationError("responder", err)
	}

	return status, nil
}

func hasOCSPSigningEKU(cert *x509.Certificate) bool {
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

func certWasValidAt(cert *x509.Certificate, at time.Time) bool {
	if at.IsZero() {
		// There is no production time to compare against. Don't introduce a
		// wall-clock dependency for such responses.
		return true
	}
	return !at.Before(cert.NotBefore.Add(-ocspResponderClockSkew)) &&
		!at.After(cert.NotAfter.Add(ocspResponderClockSkew))
}

func verifyOCSPResponderID(status *ocsp.Response, responder *x509.Certificate) error {
	if len(status.RawResponderName) > 0 {
		if !bytes.Equal(status.RawResponderName, responder.RawSubject) {
			return errors.New("OCSP responder name does not match the responder certificate")
		}
		return nil
	}
	if len(status.ResponderKeyHash) > 0 {
		var publicKeyInfo struct {
			Algorithm pkix.AlgorithmIdentifier
			PublicKey asn1.BitString
		}
		if _, err := asn1.Unmarshal(responder.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
			return fmt.Errorf("failed to parse OCSP responder public key: %w", err)
		}
		hash := sha1.Sum(publicKeyInfo.PublicKey.RightAlign()) //nolint:gosec // Required by RFC 6960.
		if !bytes.Equal(status.ResponderKeyHash, hash[:]) {
			return errors.New("OCSP responder key hash does not match the responder certificate")
		}
		return nil
	}
	return errors.New("OCSP response has no responder identifier")
}

func preferOCSPResponse(current, candidate *ocsp.Response) bool {
	// A revocation must never be hidden by a good or unknown response from a
	// different server or retry.
	if candidate.Status == ocsp.Revoked && current.Status != ocsp.Revoked {
		return true
	}
	if current.Status == ocsp.Revoked && candidate.Status != ocsp.Revoked {
		return false
	}

	// Prefer the newest response generation, and use stable tie-breakers so
	// that the choice doesn't depend on server or map iteration order.
	if !candidate.ThisUpdate.Equal(current.ThisUpdate) {
		return candidate.ThisUpdate.After(current.ThisUpdate)
	}
	if !candidate.ProducedAt.Equal(current.ProducedAt) {
		return candidate.ProducedAt.After(current.ProducedAt)
	}
	if candidate.Status != current.Status {
		// Two responses from the same generation disagree. Prefer the
		// conservative "unknown" status over "good".
		return candidate.Status == ocsp.Unknown
	}
	if candidate.SerialNumber != nil && current.SerialNumber != nil {
		if cmp := candidate.SerialNumber.Cmp(current.SerialNumber); cmp != 0 {
			return cmp > 0
		}
	}
	return bytes.Compare(candidate.Raw, current.Raw) > 0
}

func buildOCSPwithPOST(server string, encoded []byte) (*http.Request, error) {
	// The OCSP request must be sent as the HTTP request body. Calling
	// Request.Write writes a complete HTTP request to a separate buffer; it
	// does not populate req.Body, so that approach sent an empty POST.
	req, err := http.NewRequest("POST", server, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}

func buildOCSPwithGET(server string, encoded []byte) (*http.Request, error) {
	// https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1
	// GET {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
	url := fmt.Sprintf("%s/%s", server, base64.StdEncoding.EncodeToString(encoded))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}
