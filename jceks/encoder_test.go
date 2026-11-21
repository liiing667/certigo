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

package jceks

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"errors"
	"flag"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var writeReencoded = flag.Bool("jceks.write-reencoded", false, "write expected re-encoded JCEKS files")

type discardErrWriter struct {
	err           error
	writeAfterErr int
}

func (dew *discardErrWriter) Write(p []byte) (int, error) {
	if dew.err != nil {
		dew.writeAfterErr++
		return 1, dew.err
	}

	return len(p), nil
}

func TestCounterWriter(t *testing.T) {
	t.Parallel()

	var dew discardErrWriter

	cw := &counterWriter{w: &dew}

	nn, err := cw.Write([]byte("Hello "))
	require.NoError(t, err)
	require.Equal(t, 6, nn)

	nn, err = cw.Write([]byte("World"))
	require.NoError(t, err)
	require.Equal(t, 5, nn)

	expectErr := errors.New("expected error")
	dew.err = expectErr

	nn, err = cw.Write([]byte("discarded"))
	require.NoError(t, err)
	require.Equal(t, 9, nn)

	nn, err = cw.Write([]byte("more"))
	require.NoError(t, err)
	require.Equal(t, 4, nn)

	n, err := cw.Results()
	require.Equal(t, expectErr, err)
	require.Equal(t, int64(6+5+1), n)
	require.Equal(t, 1, dew.writeAfterErr)
}

func TestJCEKSDigester(t *testing.T) {
	t.Parallel()

	jd := newJCEKSDigester([]byte("CHANGE"))
	_, err := jd.Write([]byte("Hello, "))
	require.NoError(t, err)
	_, err = jd.Write([]byte("World!"))
	require.NoError(t, err)

	var buf bytes.Buffer
	err = jd.WriteDigest(&buf)
	require.NoError(t, err)

	expected := sha1.Sum([]byte("CHANGEMighty AphroditeHello, World!"))

	require.Equal(t, expected[:], buf.Bytes())
}

func TestSetIntegrityPassword(t *testing.T) {
	t.Parallel()

	var enc Encoder
	require.False(t, enc.setIntegrityPassword)

	err := enc.SetIntegrityPassword("")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInvalidPassword)
	require.False(t, enc.setIntegrityPassword)

	err = enc.SetIntegrityPassword("123456")
	require.NoError(t, err)
	require.True(t, enc.setIntegrityPassword)
	require.Equal(t, []byte{0, '1', 0, '2', 0, '3', 0, '4', 0, '5', 0, '6'}, enc.integrityPassword)
}

func TestEncodePrivateKeyStore(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	leafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)
	caCert, err := LoadPEMCert("testdata/private-key-ca.crt")
	require.NoError(t, err)

	var enc Encoder

	cipher, err := PBEWithMD5AndDES3CBC([]byte("changeit"), rnd, 20)
	require.NoError(t, err)
	err = enc.AddPrivateKeyPKCS1("example.test", now, pkcs1, [][]byte{leafCert.Raw, caCert.Raw}, cipher)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-private-store.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-private-store.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeTrustedCertificateStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	err = enc.AddTrustedCertificate("ca1", now, cert.Raw)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-cert-store.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-cert-store.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeExistingPrivateKeyStore(t *testing.T) {
	t.Parallel()

	ks, err := LoadFromFile("testdata/private-key.jceks", []byte("store-password"))
	require.NoError(t, err)

	var enc Encoder
	err = enc.AddKeyStore(ks)
	require.NoError(t, err)
	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-re-encode-private-key.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-re-encode-private-key.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeExistingTrustedCertificateStore(t *testing.T) {
	t.Parallel()

	ks, err := LoadFromFile("testdata/trusted-cert.jceks", []byte("store-password"))
	require.NoError(t, err)

	var enc Encoder
	err = enc.AddKeyStore(ks)
	require.NoError(t, err)
	err = enc.SetIntegrityPassword("changeit")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	if *writeReencoded {
		err = os.WriteFile("testdata/encoder-re-encode-trusted-cert.jceks", buf.Bytes(), 0666)
		require.NoError(t, err)
	}

	expected, err := os.ReadFile("testdata/encoder-re-encode-trusted-cert.jceks")
	require.NoError(t, err)
	require.Equal(t, expected, buf.Bytes())
}

func TestEncodeDuplicateAliases(t *testing.T) {
	t.Parallel()

	rnd := sha3.NewShake128()
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	privCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)

	otherCert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	cipher, err := PBEWithMD5AndDES3CBC([]byte("confusion"), rnd, 20)
	require.NoError(t, err)

	// Write private key entry as "foo" and cert as "bar"
	err = enc.AddPrivateKeyPKCS1("foo", now, pkcs1, [][]byte{privCert.Raw}, cipher)
	require.NoError(t, err)
	err = enc.AddTrustedCertificate("bar", now, otherCert.Raw)
	require.NoError(t, err)

	// Now write them again with opposite aliases, which should overwrite the previous ones
	err = enc.AddPrivateKeyPKCS1("bar", now, pkcs1, [][]byte{privCert.Raw}, cipher)
	require.NoError(t, err)
	err = enc.AddTrustedCertificate("foo", now, otherCert.Raw)
	require.NoError(t, err)

	err = enc.SetIntegrityPassword("confusion")
	require.NoError(t, err)

	var buf bytes.Buffer
	n, err := enc.WriteTo(&buf)
	require.NoError(t, err)
	require.Equal(t, int64(buf.Len()), n)

	reloaded, err := LoadFromReader(&buf, []byte("confusion"))
	require.NoError(t, err)

	require.Equal(t, []string{"foo"}, reloaded.ListCerts())
	require.Equal(t, []string{"bar"}, reloaded.ListPrivateKeys())
}

func TestProhibitDuplicateAliases(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder

	enc.SetProhibitDuplicateAliases(true)

	err = enc.AddTrustedCertificate("alias", now, cert.Raw)
	require.NoError(t, err)

	err = enc.AddTrustedCertificate("alias", now, cert.Raw)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateAlias)
}

// failingCipher is a PrivateKeyCipher that always fails. It simulates a key protection failure while a batch of
// entries is being imported.
type failingCipher struct{}

func (failingCipher) encryptPrivateKey(privateKeyInfo) (encryptedPrivateKeyInfo, error) {
	return encryptedPrivateKeyInfo{}, errors.New("simulated key protection failure")
}

// TestFailedPrivateKeyImportLeavesEncoderUnchanged verifies that a failure while adding one entry never leaves partial
// key material in the Encoder. A retry after such a failure must start from the same state the Encoder was in before
// the failed attempt, otherwise the retried import could be mixed with incomplete material from the first attempt.
func TestFailedPrivateKeyImportLeavesEncoderUnchanged(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	leafCert, err := LoadPEMCert("testdata/private-key.crt")
	require.NoError(t, err)

	var enc Encoder

	// A trusted entry that must remain exactly as committed before the failed private-key import.
	require.NoError(t, enc.AddTrustedCertificate("ca", now, leafCert.Raw))

	rsaPriv, err := LoadPEMKey("testdata/private-key.key")
	require.NoError(t, err)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaPriv)

	err = enc.AddPrivateKeyPKCS1("leaf", now, pkcs1, [][]byte{leafCert.Raw}, failingCipher{})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrKeyProtectionFailed)

	// Nothing from the failed attempt may have been committed.
	require.Equal(t, uint(1), enc.entryCount)
	require.Len(t, enc.entries, 1)
	require.NotNil(t, enc.entries[0])
	require.Equal(t, map[string]int{"ca": 0}, enc.aliasIndices)

	// A retry with a working cipher must produce a clean store with both entries and the certificate chain still
	// attached to its own alias ("leaf"), rather than to an alias carried over from the failed attempt.
	rnd := sha3.NewShake128()
	cipher, err := PBEWithMD5AndDES3CBC([]byte("changeit"), rnd, 20)
	require.NoError(t, err)

	require.NoError(t, enc.AddPrivateKeyPKCS1("leaf", now, pkcs1, [][]byte{leafCert.Raw}, cipher))
	require.NoError(t, enc.SetIntegrityPassword("changeit"))

	var buf bytes.Buffer
	_, err = enc.WriteTo(&buf)
	require.NoError(t, err)

	reloaded, err := LoadFromReader(&buf, []byte("changeit"))
	require.NoError(t, err)
	require.Equal(t, []string{"ca"}, reloaded.ListCerts())
	require.Equal(t, []string{"leaf"}, reloaded.ListPrivateKeys())

	_, certs, err := reloaded.GetPrivateKeyAndCerts("leaf", []byte("changeit"))
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Equal(t, leafCert.Raw, certs[0].Raw)
}

// TestAddKeyStoreIsAtomic verifies that importing an existing keystore commits nothing when any entry in the batch
// cannot be encoded. The Encoder must stay byte-for-byte unchanged so that a retry cannot mix partial material in.
func TestAddKeyStoreIsAtomic(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder
	require.NoError(t, enc.AddTrustedCertificate("existing", now, cert.Raw))

	beforeEntries := enc.entryCount
	beforeAliases := maps.Clone(enc.aliasIndices)

	// A keystore containing an unencodable private-key entry (an alias longer than the JCEKS maximum).
	bad := &KeyStore{
		trustedCerts: map[string]*trustedCertEntry{
			"new-cert": {timestamp: now, cert: cert},
		},
		privateKeys: map[string]*privateKeyEntry{
			strings.Repeat("a", maxAliasLen+1): {
				timestamp:    now,
				protectedKey: []byte{1, 2, 3},
				certs:        []*x509.Certificate{cert},
			},
		},
	}

	err = enc.AddKeyStore(bad)
	require.Error(t, err)

	// The failed import changed nothing.
	require.Equal(t, beforeEntries, enc.entryCount)
	require.Equal(t, beforeAliases, enc.aliasIndices)
	require.Len(t, enc.entries, 1)

	// A retry with a valid keystore commits the complete batch in one shot.
	good := &KeyStore{
		trustedCerts: map[string]*trustedCertEntry{
			"new-cert": {timestamp: now, cert: cert},
		},
	}
	require.NoError(t, enc.AddKeyStore(good))
	require.Equal(t, []string{"existing", "new-cert"}, enc.aliasIndicesSortedForTest())
}

// aliasIndicesSortedForTest returns the committed aliases in sorted order for stable assertions.
func (e *Encoder) aliasIndicesSortedForTest() []string {
	aliases := make([]string, 0, len(e.aliasIndices))
	for alias := range e.aliasIndices {
		aliases = append(aliases, alias)
	}
	slices.Sort(aliases)

	return aliases
}

// TestWriteToNeverEmitsPartialStore verifies that when the destination writer fails, it never receives a fragment of
// the keystore. The complete, checksummed keystore is assembled first, so a failed write (or a process restart before
// retrying it) cannot leave callers trusting a truncated or otherwise incomplete store.
func TestWriteToNeverEmitsPartialStore(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder
	require.NoError(t, enc.AddTrustedCertificate("ca1", now, cert.Raw))
	require.NoError(t, enc.SetIntegrityPassword("changeit"))

	// Build the expected complete keystore using a healthy writer.
	var expected bytes.Buffer
	n, err := enc.WriteTo(&expected)
	require.NoError(t, err)
	require.Equal(t, int64(expected.Len()), n)

	failing := &failingWriter{}
	nn, err := enc.WriteTo(failing)
	require.Error(t, err)

	// The destination receives at most one write, and it is the single complete keystore: never a partial prefix.
	require.Equal(t, int64(0), nn)
	require.Equal(t, 1, failing.total)
	require.Equal(t, expected.Len(), failing.lastLen)

	// The Encoder itself is unaffected by the failed write and can be written again after a restart/retry.
	var retry bytes.Buffer
	_, err = enc.WriteTo(&retry)
	require.NoError(t, err)
	require.Equal(t, expected.Bytes(), retry.Bytes())

	// The emitted keystore is a complete, parseable store with intact integrity protection.
	reloaded, err := LoadFromReader(bytes.NewReader(expected.Bytes()), []byte("changeit"))
	require.NoError(t, err)
	require.Equal(t, []string{"ca1"}, reloaded.ListCerts())
}

type failingWriter struct {
	total   int
	lastLen int
}

func (fw *failingWriter) Write(p []byte) (int, error) {
	fw.total++
	fw.lastLen = len(p)

	return 0, errors.New("simulated destination failure")
}

// TestAddKeyStoreIsAtomicWhenDuplicatesProhibited verifies that a batch rejected because of a duplicate alias commits
// nothing at all, including its non-conflicting entries.
func TestAddKeyStoreIsAtomicWhenDuplicatesProhibited(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)

	var enc Encoder
	enc.SetProhibitDuplicateAliases(true)
	require.NoError(t, enc.AddTrustedCertificate("existing", now, cert.Raw))

	duplicate := &KeyStore{
		trustedCerts: map[string]*trustedCertEntry{
			"existing": {timestamp: now, cert: cert},
			"new-cert": {timestamp: now, cert: cert},
		},
	}

	err = enc.AddKeyStore(duplicate)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateAlias)

	// The rejected batch committed nothing, not even the non-conflicting "new-cert" entry.
	require.Equal(t, uint(1), enc.entryCount)
	require.Equal(t, []string{"existing"}, enc.aliasIndicesSortedForTest())
}
