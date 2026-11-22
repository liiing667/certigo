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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/square/certigo/jceks"
)

func loadAliasTestKey(t *testing.T, filename string) *rsa.PrivateKey {
	t.Helper()

	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		require.NoError(t, err)
		return key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err)
		rsaKey, ok := key.(*rsa.PrivateKey)
		require.True(t, ok)
		return rsaKey
	default:
		t.Fatalf("unexpected private key PEM type %q", block.Type)
		return nil
	}
}

func loadAliasTestCert(t *testing.T, filename string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	block, _ := pem.Decode(data)
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func buildAliasTestJCEKS(t *testing.T, storePassword string) []byte {
	t.Helper()

	targetKey := loadAliasTestKey(t, "../jceks/testdata/private-key.key")
	targetCert := loadAliasTestCert(t, "../jceks/testdata/private-key.crt")
	targetCA := loadAliasTestCert(t, "../jceks/testdata/private-key-ca.crt")
	neighborKey := loadAliasTestKey(t, "../test-certs/example-small-key.key")
	neighborCert := loadAliasTestCert(t, "../test-certs/example-small-key.crt")

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)
	var encoder jceks.Encoder

	targetCipher, err := jceks.PBEWithMD5AndDES3CBC([]byte(storePassword), sha3.NewShake128(), 20)
	require.NoError(t, err)
	require.NoError(t, encoder.AddPrivateKeyPKCS1(
		"target",
		now,
		x509.MarshalPKCS1PrivateKey(targetKey),
		[][]byte{targetCert.Raw, targetCA.Raw},
		targetCipher,
	))

	neighborCipher, err := jceks.PBEWithMD5AndDES3CBC([]byte(storePassword), sha3.NewShake128(), 20)
	require.NoError(t, err)
	require.NoError(t, encoder.AddPrivateKeyPKCS1(
		"neighbor",
		now,
		x509.MarshalPKCS1PrivateKey(neighborKey),
		[][]byte{neighborCert.Raw},
		neighborCipher,
	))

	require.NoError(t, encoder.SetIntegrityPassword(storePassword))

	var output bytes.Buffer
	_, err = encoder.WriteTo(&output)
	require.NoError(t, err)
	return output.Bytes()
}

func aliasTestHasBlockBytes(blocks []*pem.Block, want []byte) bool {
	for _, block := range blocks {
		if block != nil && bytes.Equal(block.Bytes, want) {
			return true
		}
	}
	return false
}

func TestSecretExportJCEKSSelectsOnlyTargetAlias(t *testing.T) {
	data := buildAliasTestJCEKS(t, "store-password")
	targetKey := loadAliasTestKey(t, "../jceks/testdata/private-key.key")
	targetCert := loadAliasTestCert(t, "../jceks/testdata/private-key.crt")
	targetCA := loadAliasTestCert(t, "../jceks/testdata/private-key-ca.crt")
	neighborCert := loadAliasTestCert(t, "../test-certs/example-small-key.crt")

	var prompts []string
	export, err := ExportKeystore(data, "JCEKS", "target", func(prompt string) string {
		prompts = append(prompts, prompt)
		return "store-password"
	})
	require.NoError(t, err)
	require.Equal(t, KeystoreFormatJCEKS, export.Format)
	require.Equal(t, "target", export.Alias)
	require.Equal(t, ExportStageCommit, export.Stage)
	require.Equal(t, []string{"", "target"}, prompts)

	require.Len(t, export.Blocks, 3)
	require.Equal(t, "RSA PRIVATE KEY", export.Blocks[0].Type)
	require.Equal(t, x509.MarshalPKCS1PrivateKey(targetKey), export.Blocks[0].Bytes)
	require.Equal(t, targetCert.Raw, export.Blocks[1].Bytes)
	require.Equal(t, targetCA.Raw, export.Blocks[2].Bytes)

	identities := export.Identities()
	require.Len(t, identities, 3)
	for i, identity := range identities {
		require.Equal(t, "target", identity.Alias)
		require.Equal(t, PEMBlockDigest(export.Blocks[i]), identity.Digest)
	}
	require.NotEmpty(t, identities[0].KeyDigest)
	require.NotEmpty(t, identities[1].CertificateFingerprint)
	require.NotEmpty(t, identities[2].CertificateFingerprint)

	report := export.Report()
	require.Equal(t, KeystoreFormatJCEKS, report.Format)
	require.Equal(t, "target", report.Alias)
	require.Equal(t, ExportStageCommit, report.Stage)
	require.Equal(t, identities, report.Blocks)

	for _, block := range export.Blocks {
		require.NotEqual(t, neighborCert.Raw, block.Bytes)
	}

	// The complete store still exports in the original order when no alias
	// is requested: public entries first, then private keys sorted by alias.
	all, err := ExportKeystore(data, "JCEKS", "", func(string) string { return "store-password" })
	require.NoError(t, err)
	require.Len(t, all.Blocks, 5)
	require.Equal(t, x509.MarshalPKCS1PrivateKey(loadAliasTestKey(t, "../test-certs/example-small-key.key")), all.Blocks[0].Bytes)
	require.Equal(t, neighborCert.Raw, all.Blocks[1].Bytes)
	require.Equal(t, x509.MarshalPKCS1PrivateKey(targetKey), all.Blocks[2].Bytes)
	require.Equal(t, targetCert.Raw, all.Blocks[3].Bytes)
	require.Equal(t, targetCA.Raw, all.Blocks[4].Bytes)
}

func TestSecretExportJCEKSAliasFailuresPublishNoBlocks(t *testing.T) {
	data := buildAliasTestJCEKS(t, "store-password")

	export, err := ExportKeystore(data, "JCEKS", "missing", func(string) string { return "store-password" })
	require.ErrorIs(t, err, ErrKeystoreAliasNotFound)
	require.Empty(t, export.Blocks)
	require.Equal(t, ExportStageSelect, export.Stage)
	var exportErr *KeystoreExportError
	require.ErrorAs(t, err, &exportErr)
	require.Equal(t, "missing", exportErr.Alias)
	require.Equal(t, ExportStageSelect, exportErr.Stage)

	// A wrong store password must not publish entries parsed before the
	// integrity check failed.
	export, err = ExportKeystore(data, "JCEKS", "target", func(string) string { return "wrong" })
	require.ErrorIs(t, err, jceks.ErrIntegrityProtectionViolation)
	require.Empty(t, export.Blocks)
	require.Equal(t, ExportStageUnlock, export.Stage)

	// A wrong key password must not publish the certificate chain without
	// the private key it belongs to.
	export, err = ExportKeystore(data, "JCEKS", "target", func(prompt string) string {
		if prompt == "" {
			return "store-password"
		}
		return "wrong-key-password"
	})
	require.ErrorIs(t, err, jceks.ErrDecryptionFailed)
	require.Empty(t, export.Blocks)
	require.Equal(t, ExportStageUnlock, export.Stage)
}

func TestSecretExportJCEKSTrustedCertificateAlias(t *testing.T) {
	cert := loadAliasTestCert(t, "../jceks/testdata/trusted-cert.crt")

	var encoder jceks.Encoder
	require.NoError(t, encoder.AddTrustedCertificate("public", time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC), cert.Raw))
	require.NoError(t, encoder.SetIntegrityPassword("store-password"))

	var output bytes.Buffer
	_, err := encoder.WriteTo(&output)
	require.NoError(t, err)

	export, err := ExportKeystore(output.Bytes(), "JCEKS", "public", func(string) string { return "store-password" })
	require.NoError(t, err)
	require.Len(t, export.Blocks, 1)
	require.Equal(t, "CERTIFICATE", export.Blocks[0].Type)
	require.Equal(t, cert.Raw, export.Blocks[0].Bytes)
	require.Equal(t, "public", export.Identities()[0].Alias)
}

func TestSecretExportPKCS12SelectsAliasAndChain(t *testing.T) {
	data, err := os.ReadFile("testdata/multi-alias.p12")
	require.NoError(t, err)

	targetKey := loadAliasTestKey(t, "../jceks/testdata/private-key.key")
	targetCert := loadAliasTestCert(t, "../jceks/testdata/private-key.crt")
	targetCA := loadAliasTestCert(t, "../jceks/testdata/private-key-ca.crt")
	neighborKey := loadAliasTestKey(t, "../test-certs/example-small-key.key")
	neighborCert := loadAliasTestCert(t, "../test-certs/example-small-key.crt")

	export, err := ExportKeystore(data, "PKCS12", "target", func(string) string { return "password" })
	require.NoError(t, err)
	require.Equal(t, ExportStageCommit, export.Stage)

	var keyBlocks, certBlocks []*pem.Block
	for _, block := range export.Blocks {
		if isPrivateKeyPEMBlock(block) {
			keyBlocks = append(keyBlocks, block)
		} else if block.Type == "CERTIFICATE" {
			certBlocks = append(certBlocks, block)
		}
	}
	require.Len(t, keyBlocks, 1)
	require.Equal(t, x509.MarshalPKCS1PrivateKey(targetKey), keyBlocks[0].Bytes)
	require.Len(t, certBlocks, 2)
	require.True(t, aliasTestHasBlockBytes(certBlocks, targetCert.Raw))
	require.True(t, aliasTestHasBlockBytes(certBlocks, targetCA.Raw))

	// The neighboring private key and certificate must not leak into the
	// selected export.
	for _, block := range export.Blocks {
		require.NotEqual(t, x509.MarshalPKCS1PrivateKey(neighborKey), block.Bytes)
		require.NotEqual(t, neighborCert.Raw, block.Bytes)
	}

	neighbor, err := ExportKeystore(data, "PKCS12", "neighbor", func(string) string { return "password" })
	require.NoError(t, err)
	require.Len(t, neighbor.Blocks, 2)
	require.True(t, aliasTestHasBlockBytes(neighbor.Blocks, x509.MarshalPKCS1PrivateKey(neighborKey)))
	require.True(t, aliasTestHasBlockBytes(neighbor.Blocks, neighborCert.Raw))

	missing, err := ExportKeystore(data, "PKCS12", "missing", func(string) string { return "password" })
	require.ErrorIs(t, err, ErrKeystoreAliasNotFound)
	require.Empty(t, missing.Blocks)
	require.Equal(t, ExportStageSelect, missing.Stage)

	wrongPassword, err := ExportKeystore(data, "PKCS12", "target", func(string) string { return "wrong" })
	require.ErrorIs(t, err, pkcs12.ErrIncorrectPassword)
	require.Empty(t, wrongPassword.Blocks)
	require.Equal(t, ExportStageUnlock, wrongPassword.Stage)
}

func TestSecretExportPKCS12AliasMatchesLegacyOutputWhenUnambiguous(t *testing.T) {
	data, err := os.ReadFile("../test-certs/example-leaf.p12")
	require.NoError(t, err)

	all, err := ExportKeystore(data, "PKCS12", "", func(string) string { return "password" })
	require.NoError(t, err)
	selected, err := ExportKeystore(data, "PKCS12", "example-leaf", func(string) string { return "password" })
	require.NoError(t, err)

	require.Equal(t, all.Blocks, selected.Blocks)

	explicit, err := ExportKeystore(data, "PKCS12", "example-leaf", func(string) string { return "wrong" })
	require.Error(t, err)
	require.Empty(t, explicit.Blocks)
	require.Equal(t, ExportStageUnlock, explicit.Stage)
}

func TestSecretExportAliasTransactionDoesNotPublishEarlierFilesOnFailure(t *testing.T) {
	multi, err := os.ReadFile("testdata/multi-alias.p12")
	require.NoError(t, err)
	other, err := os.ReadFile("../test-certs/example-leaf.p12")
	require.NoError(t, err)

	calls := 0
	err = ReadAsPEMWithAlias(
		[]io.Reader{bytes.NewReader(multi), bytes.NewReader(other)},
		"PKCS12",
		"target",
		func(string) string { return "password" },
		func(*pem.Block, string) error {
			calls++
			return nil
		},
	)
	require.ErrorIs(t, err, ErrKeystoreAliasNotFound)
	require.Zero(t, calls, "no block may be published when a later input fails")

	err = ReadAsPEMWithAlias(
		[]io.Reader{bytes.NewReader(multi)},
		"PKCS12",
		"target",
		func(string) string { return "password" },
		func(*pem.Block, string) error {
			calls++
			return nil
		},
	)
	require.NoError(t, err)
	require.Equal(t, 3, calls)
}
