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
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/square/certigo/jceks"
	"github.com/square/certigo/pkcs7"
)

const (
	// nameHeader is the PEM header field for the friendly name/alias of the key in the key store.
	nameHeader = "friendlyName"

	// localKeyIDHeader is the PKCS#12 PEM header field that ties a certificate
	// bag to the private key bag it belongs to.
	localKeyIDHeader = "localKeyId"

	// fileHeader is the origin file where the key came from (as in file on disk).
	fileHeader = "originFile"
)

// KeystoreFormat identifies the key store formats that support precise alias
// selection.
type KeystoreFormat string

const (
	KeystoreFormatPKCS12 KeystoreFormat = "PKCS12"
	KeystoreFormatJCEKS  KeystoreFormat = "JCEKS"
)

// ExportStage identifies where a keystore export stopped. Keeping the stage
// in the error lets callers distinguish an unsupported input, a wrong store
// password, a wrong key password, and an output failure.
type ExportStage string

const (
	ExportStageSelect  ExportStage = "select"
	ExportStageUnlock  ExportStage = "unlock"
	ExportStageKey     ExportStage = "key"
	ExportStageCommit  ExportStage = "commit"
	ExportStageOutput  ExportStage = "output"
)

var (
	// ErrKeystoreAliasNotFound is returned when the requested alias is not
	// present in the selected key store.
	ErrKeystoreAliasNotFound = errors.New("keystore alias not found")

	// ErrKeystoreEmpty is returned when a key store contains no exportable
	// material at all.
	ErrKeystoreEmpty = errors.New("keystore contains no exportable material")

	// ErrUnsupportedKeystoreFormat is returned for formats that do not support
	// alias selection or keystore export.
	ErrUnsupportedKeystoreFormat = errors.New("unsupported keystore format")
)

// ExportBlockIdentity is the stable identity of one PEM block written by an
// alias export. Digest covers the exact PEM block bytes (without the headers
// that the CLI strips from normal output), CertificateFingerprint is the
// SHA-256 of the certificate DER, and KeyDigest is the SHA-256 of the private
// key DER.
type ExportBlockIdentity struct {
	Type                   string `json:"type"`
	Alias                  string `json:"alias,omitempty"`
	Digest                 string `json:"digest"`
	CertificateFingerprint string `json:"certificate_fingerprint,omitempty"`
	KeyDigest              string `json:"key_digest,omitempty"`
}

// KeystoreExportReport is the audit representation of one keystore export.
// It never contains private key material, only stable identities and digests.
type KeystoreExportReport struct {
	Format KeystoreFormat         `json:"format"`
	Alias  string                 `json:"alias,omitempty"`
	Stage  ExportStage            `json:"stage"`
	Blocks []ExportBlockIdentity  `json:"blocks"`
}

// KeystoreExport is one committed keystore export transaction. Format and
// Alias are frozen when the export is accepted; Blocks is only populated after
// the whole selected entry (including its certificate chain) has been read and
// validated. A failed export leaves Stage set to the step that failed and does
// not publish partial Blocks.
type KeystoreExport struct {
	Format KeystoreFormat
	Alias  string
	Stage  ExportStage
	Blocks []*pem.Block
}

// KeystoreExportError describes a rejected keystore export together with the
// format, target alias, and failure stage that produced it.
type KeystoreExportError struct {
	Format KeystoreFormat
	Alias  string
	Stage  ExportStage
	Err    error
}

func (e *KeystoreExportError) Error() string {
	format := string(e.Format)
	if format == "" {
		format = "keystore"
	}
	target := ""
	if e.Alias != "" {
		target = fmt.Sprintf(" alias %q", e.Alias)
	}
	stage := ""
	if e.Stage != "" {
		stage = fmt.Sprintf(" during %s", e.Stage)
	}
	if e.Err == nil {
		return fmt.Sprintf("%s export%s%s failed", format, target, stage)
	}
	return fmt.Sprintf("%s export%s%s failed: %v", format, target, stage, e.Err)
}

func (e *KeystoreExportError) Unwrap() error {
	return e.Err
}

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p7b":   "PEM",
	".p7c":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
	".jks":   "JCEKS", // Only partially supported
	".der":   "DER",
}

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

// TODO: replace misuse of error type in future version (errors should not act as multi-line output templates)
func errorFromErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	if len(errs) == 1 {
		return errs[0]
	}
	buffer := new(bytes.Buffer)
	buffer.WriteString("encountered multiple errors:\n")
	for _, err := range errs {
		buffer.WriteString("* ")
		buffer.WriteString(strings.TrimSuffix(err.Error(), "\n"))
		buffer.WriteString("\n")
	}
	return errors.New(buffer.String())
}

// ReadAsPEMFromFiles will read PEM blocks from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to PEM
// blocks and passed to the callback.
func ReadAsPEMFromFiles(files []*os.File, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	return ReadAsPEMFromFilesWithAlias(files, format, "", password, callback)
}

// ReadAsPEMFromFilesWithAlias is ReadAsPEMFromFiles with precise alias
// selection for PKCS12 and JCEKS inputs. When alias is non-empty, exactly the
// selected entry is materialized: a trusted certificate, or a private key
// together with its complete certificate chain. Neighboring aliases are never
// passed to the callback. Alias selection on other input formats is rejected.
func ReadAsPEMFromFilesWithAlias(files []*os.File, format, alias string, password func(string) string, callback func(*pem.Block, string) error) error {
	type item struct {
		block  *pem.Block
		format string
	}

	var collected []item
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s", file.Name())
		}

		emit := callback
		if alias != "" {
			emit = func(block *pem.Block, format string) error {
				collected = append(collected, item{block: block, format: format})
				return nil
			}
		}
		err = readCertsFromStream(reader, file.Name(), format, alias, password, emit)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := errorFromErrors(errs); err != nil {
		return err
	}
	for _, item := range collected {
		if err := callback(item.block, item.format); err != nil {
			return err
		}
	}
	return errorFromErrors(errs)
}

// ReadAsPEM will read PEM blocks from the given set of inputs. Input data may
// be in plain-text PEM files, DER-encoded certificates or PKCS7 envelopes, or
// PKCS12/JCEKS keystores. All inputs will be converted to PEM blocks and
// passed to the callback.
func ReadAsPEM(readers []io.Reader, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	return ReadAsPEMWithAlias(readers, format, "", password, callback)
}

// ReadAsPEMWithAlias is ReadAsPEM with precise alias selection for PKCS12 and
// JCEKS inputs.
func ReadAsPEMWithAlias(readers []io.Reader, format, alias string, password func(string) string, callback func(*pem.Block, string) error) error {
	type item struct {
		block  *pem.Block
		format string
	}

	var collected []item
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		format, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		emit := callback
		if alias != "" {
			emit = func(block *pem.Block, format string) error {
				collected = append(collected, item{block: block, format: format})
				return nil
			}
		}
		err = readCertsFromStream(reader, "", format, alias, password, emit)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := errorFromErrors(errs); err != nil {
		return err
	}
	for _, item := range collected {
		if err := callback(item.block, item.format); err != nil {
			return err
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509FromFiles will read X.509 certificates from the given set of
// inputs. Input data may be in plain-text PEM files, DER-encoded certificates
// or PKCS7 envelopes, or PKCS12/JCEKS keystores. All inputs will be converted
// to X.509 certificates (private keys are skipped) and passed to the callback.
func ReadAsX509FromFiles(files []*os.File, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	return ReadAsX509FromFilesWithAlias(files, format, "", password, callback)
}

// ReadAsX509FromFilesWithAlias is ReadAsX509FromFiles with precise alias
// selection for PKCS12 and JCEKS inputs. For a private key alias, the
// certificate chain attached to that key is selected; neighboring aliases are
// skipped.
func ReadAsX509FromFilesWithAlias(files []*os.File, format, alias string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	type item struct {
		cert   *x509.Certificate
		format string
	}

	var collected []item
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		format, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s, try adding --format flag", file.Name())
		}

		emit := pemToX509(callback)
		if alias != "" {
			emit = pemToX509(func(cert *x509.Certificate, format string, err error) error {
				if err != nil {
					return err
				}
				collected = append(collected, item{cert: cert, format: format})
				return nil
			})
		}
		err = readCertsFromStream(reader, file.Name(), format, alias, password, emit)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := errorFromErrors(errs); err != nil {
		return err
	}
	for _, item := range collected {
		if err := callback(item.cert, item.format, nil); err != nil {
			return err
		}
	}
	return errorFromErrors(errs)
}

// ReadAsX509 will read X.509 certificates from the given set of inputs. Input
// data may be in plain-text PEM files, DER-encoded certificates or PKCS7
// envelopes, or PKCS12/JCEKS keystores. All inputs will be converted to X.509
// certificates (private keys are skipped) and passed to the callback.
func ReadAsX509(readers []io.Reader, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	return ReadAsX509WithAlias(readers, format, "", password, callback)
}

// ReadAsX509WithAlias is ReadAsX509 with precise alias selection for PKCS12
// and JCEKS inputs.
func ReadAsX509WithAlias(readers []io.Reader, format, alias string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	type item struct {
		cert   *x509.Certificate
		format string
	}

	var collected []item
	var errs []error
	for _, r := range readers {
		reader := bufio.NewReaderSize(r, 4)
		format, err := formatForFile(reader, "", format)
		if err != nil {
			return fmt.Errorf("unable to guess format for input stream")
		}

		emit := pemToX509(callback)
		if alias != "" {
			emit = pemToX509(func(cert *x509.Certificate, format string, err error) error {
				if err != nil {
					return err
				}
				collected = append(collected, item{cert: cert, format: format})
				return nil
			})
		}
		err = readCertsFromStream(reader, "", format, alias, password, emit)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := errorFromErrors(errs); err != nil {
		return err
	}
	for _, item := range collected {
		if err := callback(item.cert, item.format, nil); err != nil {
			return err
		}
	}
	return errorFromErrors(errs)
}

func pemToX509(callback func(*x509.Certificate, string, error) error) func(*pem.Block, string) error {
	return func(block *pem.Block, format string) error {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			return callback(cert, format, err)
		case "PKCS7":
			certs, err := pkcs7.ExtractCertificates(block.Bytes)
			if err == nil {
				for _, cert := range certs {
					return callback(cert, format, nil)
				}
			} else {
				return callback(nil, format, err)
			}
		case "CERTIFICATE REQUEST":
			fmt.Println(red.SprintfFunc()("warning: certificate requests are not supported"))
		}
		return nil
	}
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func readCertsFromStream(reader io.Reader, filename string, format string, alias string, password func(string) string, callback func(*pem.Block, string) error) error {
	if password == nil {
		password = func(string) string { return "" }
	}

	headers := map[string]string{}
	if filename != "" && filename != os.Stdin.Name() {
		headers[fileHeader] = filename
	}

	format = strings.TrimSpace(format)
	if alias != "" && format != string(KeystoreFormatPKCS12) && format != string(KeystoreFormatJCEKS) {
		return fmt.Errorf("alias selection requires a PKCS12 or JCEKS keystore, input format is %s\n", format) //nolint:staticcheck // See errorFromErrors
	}

	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			block.Headers = mergeHeaders(block.Headers, headers)
			err := callback(block, format)
			if err != nil {
				return err
			}
		}
		return nil
	case "DER":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		x509Certs, err0 := x509.ParseCertificates(data)
		if err0 == nil {
			for _, cert := range x509Certs {
				err := callback(EncodeX509ToPEM(cert, headers), format)
				if err != nil {
					return err
				}
			}
			return nil
		}
		p7bBlocks, err1 := pkcs7.ParseSignedData(data)
		if err1 == nil {
			for _, block := range p7bBlocks {
				err := callback(pkcs7ToPem(block, headers), format)
				if err != nil {
					return err
				}
			}
			return nil
		}
		//nolint:staticcheck // See errorFromErrors
		return fmt.Errorf("unable to parse certificates from DER data\n* X.509 parser gave: %s\n* PKCS7 parser gave: %s\n", err0, err1)
	case "PKCS12":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		blocks, stage, err := pkcs12BlocksForAlias(data, password(""), alias)
		if err != nil {
			if alias != "" {
				return &KeystoreExportError{
					Format: KeystoreFormatPKCS12,
					Alias:  alias,
					Stage:  stage,
					Err:    err,
				}
			}
			//nolint:staticcheck // See errorFromErrors
			return fmt.Errorf("unable to read keystore: %s\n", err)
		}
		if len(blocks) == 0 {
			if alias != "" {
				return &KeystoreExportError{
					Format: KeystoreFormatPKCS12,
					Alias:  alias,
					Stage:  ExportStageSelect,
					Err:    ErrKeystoreEmpty,
				}
			}
			//nolint:staticcheck // See errorFromErrors
			return fmt.Errorf("keystore appears to be empty or password was incorrect\n")
		}
		for _, block := range blocks {
			block.Headers = mergeHeaders(block.Headers, headers)
			err := callback(block, format)
			if err != nil {
				return err
			}
		}
		return nil
	case "JCEKS":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		keyStore, err := jceks.LoadFromReader(bytes.NewReader(data), []byte(password("")))
		if err != nil {
			if alias != "" {
				return &KeystoreExportError{
					Format: KeystoreFormatJCEKS,
					Alias:  alias,
					Stage:  ExportStageUnlock,
					Err:    err,
				}
			}
			return fmt.Errorf("unable to parse keystore: %s\n", err) //nolint:staticcheck // See errorFromErrors
		}
		blocks, stage, err := jceksBlocksForAlias(keyStore, alias, password)
		if err != nil {
			if alias != "" {
				return &KeystoreExportError{
					Format: KeystoreFormatJCEKS,
					Alias:  alias,
					Stage:  stage,
					Err:    err,
				}
			}
			if stage == ExportStageKey {
				return fmt.Errorf("problem reading key: %s\n", err) //nolint:staticcheck // See errorFromErrors
			}
			//nolint:staticcheck // See errorFromErrors
			return fmt.Errorf("unable to parse keystore: %s\n", err)
		}
		for _, block := range blocks {
			block.Headers = mergeHeaders(block.Headers, headers)
			if err := callback(block, format); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unknown file type '%s'\n", format) //nolint:staticcheck // See errorFromErrors
}

func mergeHeaders(baseHeaders, extraHeaders map[string]string) (headers map[string]string) {
	headers = map[string]string{}
	for k, v := range baseHeaders {
		headers[k] = v
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return
}

// EncodeX509ToPEM converts an X.509 certificate into a PEM block for output.
func EncodeX509ToPEM(cert *x509.Certificate, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert.Raw,
		Headers: headers,
	}
}

// Convert a PKCS7 envelope into a PEM block for output.
func pkcs7ToPem(block *pkcs7.SignedDataEnvelope, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "PKCS7",
		Bytes:   block.Raw,
		Headers: headers,
	}
}

// Convert a key into one or more PEM blocks for output.
func keyToPem(key crypto.PrivateKey, headers map[string]string) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   x509.MarshalPKCS1PrivateKey(k),
			Headers: headers,
		}, nil
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			//nolint:staticcheck // See errorFromErrors
			return nil, fmt.Errorf("error marshaling key: %s\n", reflect.TypeOf(key))
		}
		return &pem.Block{
			Type:    "EC PRIVATE KEY",
			Bytes:   raw,
			Headers: headers,
		}, nil
	}
	//nolint:staticcheck // See errorFromErrors
	return nil, fmt.Errorf("unknown key type: %s\n", reflect.TypeOf(key))
}

// ExportKeystore materializes a single keystore export transaction. Format
// and alias are captured before the password callback is used, so a retry
// cannot silently switch to another key store or alias. The returned export
// has no Blocks unless every selected block, including the complete
// certificate chain, was read successfully. On failure the returned export
// still identifies the frozen format, alias, and failure stage.
func ExportKeystore(data []byte, format, alias string, password func(string) string) (*KeystoreExport, error) {
	if password == nil {
		password = func(string) string { return "" }
	}

	export := &KeystoreExport{
		Format: KeystoreFormat(strings.ToUpper(strings.TrimSpace(format))),
		Alias:  alias,
		Stage:  ExportStageSelect,
	}

	var (
		blocks []*pem.Block
		stage  ExportStage
		err    error
	)

	switch export.Format {
	case KeystoreFormatPKCS12:
		blocks, stage, err = pkcs12BlocksForAlias(data, password(""), alias)
	case KeystoreFormatJCEKS:
		var keyStore *jceks.KeyStore
		keyStore, err = jceks.LoadFromReader(bytes.NewReader(data), []byte(password("")))
		if err != nil {
			stage = ExportStageUnlock
			break
		}
		blocks, stage, err = jceksBlocksForAlias(keyStore, alias, password)
	default:
		stage = ExportStageSelect
		err = fmt.Errorf("%w: %q", ErrUnsupportedKeystoreFormat, format)
	}

	if err != nil {
		export.Stage = stage
		return export, &KeystoreExportError{
			Format: export.Format,
			Alias:  export.Alias,
			Stage:  stage,
			Err:    err,
		}
	}
	if len(blocks) == 0 {
		export.Stage = ExportStageSelect
		return export, &KeystoreExportError{
			Format: export.Format,
			Alias:  export.Alias,
			Stage:  ExportStageSelect,
			Err:    ErrKeystoreEmpty,
		}
	}

	export.Blocks = blocks
	export.Stage = ExportStageCommit
	return export, nil
}

// Identities returns one stable identity for every committed PEM block. The
// digest is computed over the exact PEM encoding that the CLI emits, without
// any PEM headers.
func (e *KeystoreExport) Identities() []ExportBlockIdentity {
	if e == nil {
		return nil
	}

	identities := make([]ExportBlockIdentity, 0, len(e.Blocks))
	for _, block := range e.Blocks {
		if block == nil {
			continue
		}

		identity := ExportBlockIdentity{
			Type:   block.Type,
			Alias:  e.Alias,
			Digest: pemBlockOutputDigest(block),
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				identity.CertificateFingerprint = sha256Hex(cert.Raw)
			}
		}
		if isPrivateKeyPEMBlock(block) {
			identity.KeyDigest = sha256Hex(block.Bytes)
		}
		identities = append(identities, identity)
	}

	return identities
}

// Report returns the audit record for this export. It is available after a
// successful commit and after a rejection, where Stage identifies the last
// completed or failed step.
func (e *KeystoreExport) Report() KeystoreExportReport {
	if e == nil {
		return KeystoreExportReport{}
	}
	return KeystoreExportReport{
		Format: e.Format,
		Alias:  e.Alias,
		Stage:  e.Stage,
		Blocks: e.Identities(),
	}
}

// PEMBlockDigest returns the SHA-256 digest of the exact PEM encoding of block
// without headers. This is the identity used by alias exports.
func PEMBlockDigest(block *pem.Block) string {
	return pemBlockOutputDigest(block)
}

func pemBlockOutputDigest(block *pem.Block) string {
	if block == nil {
		return ""
	}
	canonical := &pem.Block{Type: block.Type, Bytes: block.Bytes}
	return sha256Hex(pem.EncodeToMemory(canonical))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func isPrivateKeyPEMBlock(block *pem.Block) bool {
	return block != nil && strings.HasSuffix(block.Type, "PRIVATE KEY")
}

// pkcs12BlocksForAlias returns only the selected alias and, for a private key,
// the certificate bags tied to that key by localKeyId. Private key bags for
// neighboring aliases are never returned.
func pkcs12BlocksForAlias(data []byte, password, alias string) ([]*pem.Block, ExportStage, error) {
	blocks, err := pkcs12ToRawPemBlocks(data, password)
	if err != nil {
		return nil, ExportStageUnlock, err
	}
	if alias == "" {
		if err := normalizePrivateKeyBlocks(blocks); err != nil {
			return nil, ExportStageKey, err
		}
		return blocks, ExportStageCommit, nil
	}

	selected, err := selectPKCS12Blocks(blocks, alias)
	if err != nil {
		return nil, ExportStageSelect, err
	}
	for _, block := range selected {
		if block.Headers == nil {
			block.Headers = make(map[string]string)
		}
		block.Headers[nameHeader] = alias
	}
	// Only the selected private key is converted into its concrete PEM
	// representation. A neighboring key of an unsupported type must not be
	// able to reject or alter an export that does not include it.
	if err := normalizePrivateKeyBlocks(selected); err != nil {
		return nil, ExportStageKey, err
	}
	return selected, ExportStageCommit, nil
}

func selectPKCS12Blocks(blocks []*pem.Block, alias string) ([]*pem.Block, error) {
	keyIDs := make(map[string]struct{})
	certIDs := make(map[string]struct{})
	found := false
	hasPrivateKey := false

	for _, block := range blocks {
		if block == nil || block.Headers == nil || block.Headers[nameHeader] != alias {
			continue
		}
		found = true
		if isPrivateKeyPEMBlock(block) {
			hasPrivateKey = true
		}
		keyID := block.Headers[localKeyIDHeader]
		if keyID == "" {
			continue
		}
		if isPrivateKeyPEMBlock(block) {
			keyIDs[keyID] = struct{}{}
		} else if block.Type == "CERTIFICATE" {
			certIDs[keyID] = struct{}{}
		}
	}

	if !found {
		return nil, fmt.Errorf("%w: %q", ErrKeystoreAliasNotFound, alias)
	}

	selected := make([]*pem.Block, 0, len(blocks))
	for _, block := range blocks {
		if block == nil {
			continue
		}
		if block.Headers != nil && block.Headers[nameHeader] == alias {
			selected = append(selected, block)
			continue
		}

		// Never let a private key bag from another alias into the export.
		if block.Type != "CERTIFICATE" || block.Headers == nil {
			continue
		}
		// A certificate that explicitly names another alias is not part of
		// this entry, even if a malformed key store repeats localKeyId.
		// Anonymous chain bags are handled below and by issuer walking.
		if block.Headers[nameHeader] != "" {
			continue
		}

		keyID := block.Headers[localKeyIDHeader]
		if keyID == "" {
			continue
		}
		if _, ok := keyIDs[keyID]; ok {
			selected = append(selected, block)
			continue
		}
		if len(keyIDs) == 0 {
			if _, ok := certIDs[keyID]; ok {
				selected = append(selected, block)
			}
		}
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrKeystoreAliasNotFound, alias)
	}
	if hasPrivateKey {
		// PKCS#12 producers do not always attach localKeyId or a friendly
		// name to CA certificate bags. Follow the issuer relationship from
		// the selected leaf through those otherwise anonymous bags so the
		// complete chain travels with the private key.
		selected = appendPKCS12CertificateChains(selected, blocks)
	}
	return selected, nil
}

func appendPKCS12CertificateChains(selected, all []*pem.Block) []*pem.Block {
	type candidate struct {
		block *pem.Block
		cert  *x509.Certificate
	}

	included := make(map[*pem.Block]struct{}, len(selected))
	for _, block := range selected {
		included[block] = struct{}{}
	}

	bySubject := make(map[string][]candidate)
	for _, block := range all {
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		bySubject[string(cert.RawSubject)] = append(bySubject[string(cert.RawSubject)], candidate{
			block: block,
			cert:  cert,
		})
		// A semantically equal issuer may be encoded with a different string
		// type or ordering. Keep the textual form as a fallback index.
		bySubject[cert.Subject.String()] = append(bySubject[cert.Subject.String()], candidate{
			block: block,
			cert:  cert,
		})
	}

	for _, selectedBlock := range selected {
		if selectedBlock == nil || selectedBlock.Type != "CERTIFICATE" {
			continue
		}
		start, err := x509.ParseCertificate(selectedBlock.Bytes)
		if err != nil {
			continue
		}

		current := start
		seen := map[*x509.Certificate]struct{}{current: struct{}{}}
		for depth := 0; depth < len(all)+1; depth++ {
			if current.CheckSignatureFrom(current) == nil ||
				current.CheckSignature(current.SignatureAlgorithm,
					current.RawTBSCertificate, current.Signature) == nil {
				break
			}

			var next *candidate
			parents := bySubject[string(current.RawIssuer)]
			if len(parents) == 0 {
				parents = bySubject[current.Issuer.String()]
			}
			for i := range parents {
				parent := &parents[i]
				if parent.block == selectedBlock {
					continue
				}
				if _, ok := seen[parent.cert]; ok {
					continue
				}
				if current.CheckSignatureFrom(parent.cert) != nil &&
					parent.cert.CheckSignature(current.SignatureAlgorithm,
						current.RawTBSCertificate, current.Signature) != nil {
					continue
				}
				next = parent
				break
			}
			if next == nil {
				break
			}

			included[next.block] = struct{}{}
			seen[next.cert] = struct{}{}
			current = next.cert
		}
	}

	ordered := make([]*pem.Block, 0, len(included))
	for _, block := range all {
		if block == nil {
			continue
		}
		if _, ok := included[block]; ok {
			ordered = append(ordered, block)
		}
	}
	return ordered
}

// jceksBlocksForAlias returns all entries, or exactly one selected entry when
// alias is set. Blocks are fully materialized before the caller can emit any
// of them, so a failed key password or missing chain cannot leave a partial
// export behind.
func jceksBlocksForAlias(keyStore *jceks.KeyStore, alias string, password func(string) string) ([]*pem.Block, ExportStage, error) {
	if keyStore == nil {
		return nil, ExportStageSelect, ErrKeystoreEmpty
	}
	if password == nil {
		password = func(string) string { return "" }
	}

	if alias != "" {
		if cert, _ := keyStore.GetCert(alias); cert != nil {
			return []*pem.Block{EncodeX509ToPEM(cert, map[string]string{nameHeader: alias})}, ExportStageCommit, nil
		}
		if !keyStore.HasAlias(alias) {
			return nil, ExportStageSelect, fmt.Errorf("%w: %q", ErrKeystoreAliasNotFound, alias)
		}

		key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password(alias)))
		if err != nil {
			stage := ExportStageKey
			if errors.Is(err, jceks.ErrDecryptionFailed) {
				stage = ExportStageUnlock
			}
			return nil, stage, err
		}
		if key == nil {
			return nil, ExportStageKey, fmt.Errorf("%w: %q", ErrKeystoreAliasNotFound, alias)
		}

		headers := map[string]string{nameHeader: alias}
		block, err := keyToPem(key, headers)
		if err != nil {
			return nil, ExportStageKey, err
		}
		blocks := make([]*pem.Block, 0, 1+len(certs))
		blocks = append(blocks, block)
		for _, cert := range certs {
			blocks = append(blocks, EncodeX509ToPEM(cert, headers))
		}
		return blocks, ExportStageCommit, nil
	}

	var blocks []*pem.Block
	for _, certAlias := range keyStore.ListCerts() {
		cert, _ := keyStore.GetCert(certAlias)
		if cert == nil {
			continue
		}
		blocks = append(blocks, EncodeX509ToPEM(cert, map[string]string{nameHeader: certAlias}))
	}
	for _, keyAlias := range keyStore.ListPrivateKeys() {
		key, certs, err := keyStore.GetPrivateKeyAndCerts(keyAlias, []byte(password(keyAlias)))
		if err != nil {
			return nil, ExportStageUnlock, err
		}
		if key == nil {
			return nil, ExportStageKey, fmt.Errorf("%w: %q", ErrKeystoreAliasNotFound, keyAlias)
		}

		headers := map[string]string{nameHeader: keyAlias}
		block, err := keyToPem(key, headers)
		if err != nil {
			return nil, ExportStageKey, err
		}
		blocks = append(blocks, block)
		for _, cert := range certs {
			blocks = append(blocks, EncodeX509ToPEM(cert, headers))
		}
	}
	return blocks, ExportStageCommit, nil
}

// pkcs12ToPemBlocks converts all PKCS#12 safe bags in data to PEM blocks.
func pkcs12ToPemBlocks(data []byte, password string) ([]*pem.Block, error) {
	blocks, err := pkcs12ToRawPemBlocks(data, password)
	if err != nil {
		return nil, err
	}
	if err := normalizePrivateKeyBlocks(blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// pkcs12ToRawPemBlocks converts all PKCS#12 safe bags to PEM blocks while
// preserving the bag headers and order. Private key blocks still have the
// package's generic "PRIVATE KEY" type until normalizePrivateKeyBlocks runs.
func pkcs12ToRawPemBlocks(data []byte, password string) ([]*pem.Block, error) {
	// pkcs12.ToPEM is deprecated because it returns "PRIVATE KEY" PEM blocks that are not in PKCS#8 format, but rather
	// in a format specific to the key type. However, the pkcs12 package does not provide an equivalent replacement:
	// there is no other way to preserve the order of the safe bag contents or to preserve "friendlyName", "localKeyId",
	// and "Microsoft CSP Name" attributes that may be present in the PKCS#12 data. Therefore, this function calls the
	// deprecated function and then attempts to fix the invalid PEM blocks by giving them appropriate block types.
	//nolint:staticcheck // See comment
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 data: %w", err)
	}
	return blocks, nil
}

func normalizePrivateKeyBlocks(blocks []*pem.Block) error {
	for _, block := range blocks {
		if block == nil {
			continue
		}
		if block.Type != "PRIVATE KEY" {
			continue
		}
		if _, parseErr := x509.ParseECPrivateKey(block.Bytes); parseErr == nil {
			block.Type = "EC PRIVATE KEY"
			continue
		}
		if _, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes); parseErr == nil {
			block.Type = "RSA PRIVATE KEY"
			continue
		}
		if key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
			switch k := key.(type) {
			case *rsa.PrivateKey:
				block.Type = "RSA PRIVATE KEY"
				block.Bytes = x509.MarshalPKCS1PrivateKey(k)
				continue
			case *ecdsa.PrivateKey:
				raw, err := x509.MarshalECPrivateKey(k)
				if err != nil {
					return fmt.Errorf("error marshaling key: %s\n", reflect.TypeOf(key))
				}
				block.Type = "EC PRIVATE KEY"
				block.Bytes = raw
				continue
			}
		}

		//nolint:staticcheck // See errorFromErrors
		return fmt.Errorf("PKCS#12 conversion produced unknown private key type\n")
	}

	return nil
}

// formatForFile returns the file format (either from flags or
// based on file extension).
func formatForFile(file *bufio.Reader, filename, format string) (string, error) {
	// First, honor --format flag we got from user
	if format != "" {
		return format, nil
	}

	// Second, attempt to guess based on extension
	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, nil
	}

	// Third, attempt to guess based on first 4 bytes of input
	data, err := file.Peek(4)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %s\n", err) //nolint:staticcheck // See errorFromErrors
	}

	// Heuristics for guessing -- best effort.
	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		// JCEKS/JKS files always start with this prefix
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		// Starts with '----' or 'CONN' (what s_client prints...)
		return "PEM", nil
	}
	if magic&0xFFFF0000 == 0x30820000 {
		// Looks like the input is DER-encoded, so it's either PKCS12 or X.509.
		if magic&0x0000FF00 == 0x0300 {
			// Probably X.509
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", fmt.Errorf("unable to guess file format")
}

// pemScanner will return a bufio.Scanner that splits the input
// from the given reader into PEM blocks.
func pemScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}

		return 0, nil, nil
	})

	return scanner
}
