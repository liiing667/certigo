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
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctutil "github.com/google/certificate-transparency-go/x509util"
)

//go:generate go run github.com/square/certigo/internal/gen-known-logs --out ctlogs.go
//go:generate go fmt ctlogs.go

// parseSCTList returns the SCTs embedded in cert. The result is derived
// exclusively from cert, so parsing another certificate (or retrying the same
// certificate after a failure) cannot reuse SCT state from an earlier one.
func parseSCTList(cert *x509.Certificate) []*simpleSCT {
	sctList, _ := parseCertificateSCTs(cert)
	return sctList
}

// parseCertificateSCTs parses the SCT list from a single certificate. It
// returns any SCTs that could be decoded even if other entries in the same
// list are malformed, so one bad entry cannot hide the rest of the
// certificate's CT evidence.
func parseCertificateSCTs(cert *x509.Certificate) ([]*simpleSCT, error) {
	if cert == nil {
		return nil, errors.New("cannot parse SCTs from a nil certificate")
	}

	// certificate-transparency-go contains a fork of crypto/x509 with support
	// for SCTs. We must re-parse the whole certificate to get at them, so do a
	// quick check to see if the SCT extension is present before re-parsing the
	// certificate unnecessarily.
	if !hasSCTs(cert) {
		return nil, nil
	}

	parsedCert, parseErr := ctx509.ParseCertificate(cert.Raw)
	if parsedCert == nil {
		if parseErr == nil {
			parseErr = errors.New("certificate parser returned no certificate")
		}
		return nil, fmt.Errorf("unable to parse certificate SCT extension: %w", parseErr)
	}

	var sctList []*simpleSCT
	var parseErrors []string
	if parseErr != nil {
		// The CT x509 fork can return a usable certificate together with
		// non-fatal extension errors. Keep any SCTs it did decode and report
		// the error alongside them.
		parseErrors = append(parseErrors, parseErr.Error())
	}
	for i := range parsedCert.SCTList.SCTList {
		sct, err := ctutil.ExtractSCT(&parsedCert.SCTList.SCTList[i])
		if err != nil {
			parseErrors = append(parseErrors, fmt.Sprintf("SCT %d: %v", i, err))
			continue
		}
		sctList = append(sctList, simpleSCTFromCT(sct))
	}
	if len(parseErrors) > 0 {
		return sctList, fmt.Errorf("unable to parse SCTs: %s", strings.Join(parseErrors, "; "))
	}
	return sctList, nil
}

func simpleSCTFromCT(sct *ct.SignedCertificateTimestamp) *simpleSCT {
	// Copy the log ID so the displayed identity is not coupled to the
	// certificate-transparency parser's buffer.
	id := append([]byte(nil), sct.LogID.KeyID[:]...)
	out := &simpleSCT{
		Version:            uint64(sct.SCTVersion),
		LogID:              id,
		Timestamp:          time.UnixMilli(int64(sct.Timestamp)),
		SignatureAlgorithm: sctSignatureAlg(sct.Signature.Algorithm),
	}
	if log := getLogByID(id); log != nil {
		out.LogOperator = log.operator
		out.LogURL = log.url
	} else {
		// Keep the raw LogID in the SCT and mark it as unknown. Dropping
		// unknown logs would make the remaining CT evidence unauditable.
		out.LogUnknown = true
	}
	return out
}

func hasSCTs(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT)) {
			return true
		}
	}
	return false
}

func getLogByID(id []byte) *ctLog {
	b64 := base64.StdEncoding.EncodeToString(id)
	return knownLogs[b64]
}

func sctSignatureAlg(alg cttls.SignatureAndHashAlgorithm) simpleSigAlg {
	x509Alg := x509.UnknownSignatureAlgorithm
	switch alg.Signature {
	case cttls.RSA:
		switch alg.Hash {
		case cttls.MD5:
			x509Alg = x509.MD5WithRSA
		case cttls.SHA1:
			x509Alg = x509.SHA1WithRSA
		case cttls.SHA256:
			x509Alg = x509.SHA256WithRSA
		case cttls.SHA384:
			x509Alg = x509.SHA384WithRSA
		case cttls.SHA512:
			x509Alg = x509.SHA512WithRSA
		}
	case cttls.DSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.DSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.DSAWithSHA256
		}
	case cttls.ECDSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.ECDSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.ECDSAWithSHA256
		case cttls.SHA384:
			x509Alg = x509.ECDSAWithSHA384
		case cttls.SHA512:
			x509Alg = x509.ECDSAWithSHA512
		}
	}
	return simpleSigAlg(x509Alg)
}
