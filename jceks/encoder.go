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
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"time"
)

var (
	ErrNoIntegrityPassword        = errors.New("no integrity password was set")
	ErrInvalidString              = errors.New("string cannot be expressed in JCEKS format")
	ErrInvalidKeyProtectionParams = errors.New("invalid key protection parameters")
	ErrKeyProtectionFailed        = errors.New("key protection failed")
	ErrInvalidCertificates        = errors.New("invalid certificates")
	ErrTooManyEntries             = errors.New("too many entries")
	ErrDuplicateAlias             = errors.New("duplicate alias")
)

// Encoder collects key material and then writes it in JCEKS format when WriteTo is called. The zero value of an Encoder
// is ready to use, but an integrity password must be set by calling SetIntegrityPassword before WriteTo can succeed.
type Encoder struct {
	integrityPassword        []byte
	setIntegrityPassword     bool
	prohibitDuplicateAliases bool
	entryCount               uint
	entries                  [][]byte
	aliasIndices             map[string]int

	_ [0]func() // Incomparable
}

// stagedEntry is a fully encoded keystore entry that has not yet been committed to the Encoder. Entries are staged
// while a batch is being built so that the Encoder is only modified once the whole batch is known to be valid. This
// keeps failed imports from leaving partial key material behind, which could otherwise be mixed into a later retry.
type stagedEntry struct {
	alias string
	data  []byte
}

// PrivateKeyCipher represents an encryption method that can protect the confidentiality of private keys in a JCEKS
// file.
type PrivateKeyCipher interface {
	encryptPrivateKey(info privateKeyInfo) (encryptedPrivateKeyInfo, error)
}

// SetIntegrityPassword sets a password that used to verify the integrity of the keystore as a whole. The metadata in
// the keystore can be read without providing the integrity password, but providing it may help to detect modifications
// by processes that do not know the password. A password must be set before the keystore can be written. Password runes
// must be from the basic multilingual plane.
func (e *Encoder) SetIntegrityPassword(password string) error {
	e.setIntegrityPassword = false

	integrityPassword, err := encodeIntegrityPassword(password)
	if err != nil {
		return err
	}

	e.integrityPassword = integrityPassword
	e.setIntegrityPassword = true

	return nil
}

// SetProhibitDuplicateAliases controls whether adding new entries with duplicate aliases is allowed. When prohibit is
// false (the default), newly written aliases overwrite old entries with the same alias. This matches the behavior of
// readers. As an optimization, the overwritten entries will not be written to the output at all. When prohibit is true,
// attempting to add an entry with a duplicate alias returns an error that is ErrDuplicateAlias. Calling this function
// does not change the behavior with respect to previous calls (e.g., setting prohibit to true does not undo any
// previous overwrites).
func (e *Encoder) SetProhibitDuplicateAliases(prohibit bool) {
	e.prohibitDuplicateAliases = prohibit
}

// commitEntries applies a batch of fully encoded entries to the Encoder atomically. It either commits every entry
// in the batch or, if the batch contains a duplicate alias while duplicates are prohibited, changes nothing. Entries
// that overwrite an earlier entry in the same batch or an existing alias replace it, matching reader semantics.
func (e *Encoder) commitEntries(batch []stagedEntry) error {
	if e.aliasIndices == nil {
		e.aliasIndices = make(map[string]int)
	}

	// Validate the whole batch against both the current state and the batch itself before touching the Encoder. A
	// failed import must never leave partial key material behind that could be mixed into a later retry.
	if e.prohibitDuplicateAliases {
		batchAliases := make(map[string]struct{}, len(batch))
		for _, entry := range batch {
			if _, exists := e.aliasIndices[entry.alias]; exists {
				return fmt.Errorf("%w: %q", ErrDuplicateAlias, entry.alias)
			}
			if _, repeated := batchAliases[entry.alias]; repeated {
				return fmt.Errorf("%w: %q", ErrDuplicateAlias, entry.alias)
			}
			batchAliases[entry.alias] = struct{}{}
		}
	}

	for _, entry := range batch {
		if idx, exists := e.aliasIndices[entry.alias]; exists {
			e.entries[idx] = nil
			e.entryCount--
		}

		e.aliasIndices[entry.alias] = len(e.entries)
		e.entries = append(e.entries, entry.data)
		e.entryCount++
	}

	return nil
}

// AddPrivateKeyPKCS1 adds a private key and an associated certificate chain to the keystore. The method uses the given
// PrivateKeyCipher to encrypt the key for storage. The private key must be provided in PKCS#1 private key DER form, and
// the certificates must be provided in X.509 DER form.
func (e *Encoder) AddPrivateKeyPKCS1(alias string, timestamp time.Time,
	keyPKCS1 []byte, certificatesDER [][]byte, cipher PrivateKeyCipher) error {

	protectedKeyInfo, err := cipher.encryptPrivateKey(privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: keyPKCS1,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyProtectionFailed, err)
	}

	protectedKey, err := asn1.Marshal(protectedKeyInfo)
	if err != nil {
		return fmt.Errorf("failed to encode encrypted private key info: %w", err)
	}

	entry, err := buildPrivateKeyEntry(alias, timestamp, protectedKey, certificatesDER)
	if err != nil {
		return err
	}

	return e.commitEntries([]stagedEntry{entry})
}

func buildPrivateKeyEntry(alias string, timestamp time.Time,
	protectedKey []byte, certificatesDER [][]byte) (stagedEntry, error) {
	if len(alias) > maxAliasLen {
		return stagedEntry{}, fmt.Errorf("%w: alias is too long", ErrInvalidString)
	}
	if len(certificatesDER) > math.MaxInt32 {
		return stagedEntry{}, fmt.Errorf("%w: too many certificates", ErrInvalidCertificates)
	}
	for i, certDER := range certificatesDER {
		if len(certDER) < 1 {
			return stagedEntry{}, fmt.Errorf("%w: certificate %d has no data", ErrInvalidCertificates, i)
		}
		if len(certDER) > math.MaxInt32 {
			return stagedEntry{}, fmt.Errorf("%w: certificate %d has a DER encoding that exceeds JCEKS capacity",
				ErrInvalidCertificates, i)
		}
	}
	if len(protectedKey) > math.MaxInt32 {
		return stagedEntry{}, fmt.Errorf("%w: protected key is too large", ErrKeyProtectionFailed)
	}

	var buf bytes.Buffer

	_ = writeUint32(&buf, privateKeyEntryTag)
	_ = writeString(&buf, alias)
	_ = writeDate(&buf, timestamp)
	_ = writeBytes(&buf, protectedKey)

	_ = writeInt32(&buf, int32(len(certificatesDER)))
	for _, certDER := range certificatesDER {
		_ = writeCertificate(&buf, certDER)
	}

	return stagedEntry{alias: alias, data: buf.Bytes()}, nil
}

// AddTrustedCertificate adds a trusted certificate to the keystore. The certificate is not associated with a private
// key and receives no confidentiality protection. Storing a certificate in the keystore provides a verifiable record of
// trust if the keystore's integrity protection is secure. The certificate must be provided in X.509 DER form.
func (e *Encoder) AddTrustedCertificate(alias string, timestamp time.Time, certDER []byte) error {
	entry, err := buildTrustedCertificateEntry(alias, timestamp, certDER)
	if err != nil {
		return err
	}

	return e.commitEntries([]stagedEntry{entry})
}

func buildTrustedCertificateEntry(alias string, timestamp time.Time, certDER []byte) (stagedEntry, error) {
	if len(alias) > maxAliasLen {
		return stagedEntry{}, fmt.Errorf("%w: alias is too long", ErrInvalidString)
	}

	var buf bytes.Buffer

	_ = writeUint32(&buf, trustedCertEntryTag)
	_ = writeString(&buf, alias)
	_ = writeDate(&buf, timestamp)
	_ = writeCertificate(&buf, certDER)

	return stagedEntry{alias: alias, data: buf.Bytes()}, nil
}

// AddKeyStore adds the trusted certificates and private keys from an existing keystore to the Encoder. The existing
// keystore's integrity password is ignored. Existing private keys are added to the Encoder without decrypting them, so
// no private key passwords are needed, but any existing problems with the private keys will be preserved.
func (e *Encoder) AddKeyStore(ks *KeyStore) error {
	// Build the whole batch before committing anything: if any entry cannot be encoded, the Encoder must remain
	// unchanged so that a retry does not mix partial key material with the entries committed before the failure.
	batch := make([]stagedEntry, 0, len(ks.trustedCerts)+len(ks.privateKeys))

	for alias, tc := range ks.trustedCerts {
		entry, err := buildTrustedCertificateEntry(alias, tc.timestamp, tc.cert.Raw)
		if err != nil {
			return fmt.Errorf("failed to add trusted certificate %q: %w", alias, err)
		}
		batch = append(batch, entry)
	}
	for alias, sk := range ks.privateKeys {
		certificatesDER := make([][]byte, 0, len(sk.certs))
		for _, cert := range sk.certs {
			certificatesDER = append(certificatesDER, cert.Raw)
		}
		entry, err := buildPrivateKeyEntry(alias, sk.timestamp, sk.protectedKey, certificatesDER)
		if err != nil {
			return fmt.Errorf("failed to add private key %q: %w", alias, err)
		}
		batch = append(batch, entry)
	}

	return e.commitEntries(batch)
}

// counterWriter passes through writes to an underlying io.Writer, but keeps track of the number of bytes written and
// the first error encountered. It simplifies the implementation of multi-write algorithms.
type counterWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (cw *counterWriter) Write(p []byte) (int, error) {
	if cw.err == nil {
		nn, err := cw.w.Write(p)
		cw.n += int64(nn)
		cw.err = err
	}

	return len(p), nil
}

func (cw *counterWriter) Results() (int64, error) {
	return cw.n, cw.err
}

// jceksDigester computes the JCEKS SHA1 integrity protection hash for the JCEKS file written into it.
type jceksDigester struct {
	h hash.Hash
}

func newJCEKSDigester(encodedPassword []byte) *jceksDigester {
	return &jceksDigester{
		h: makeIntegrityHash(encodedPassword),
	}
}

func (j *jceksDigester) Write(p []byte) (n int, err error) {
	return j.h.Write(p)
}

// WriteDigest writes the computed JCEKS integrity hash to the underlying io.Writer.
func (j *jceksDigester) WriteDigest(w io.Writer) error {
	_, err := w.Write(j.h.Sum(nil))

	return err
}

// WriteTo writes a JCEKS file to the given io.Writer. The keystore contains the key material that has been added to the
// Encoder in previous calls. The complete keystore, including its integrity checksum, is assembled in memory before
// anything is written to w. A failure therefore never leaves a truncated or otherwise partial keystore behind, which a
// caller or a process restart could otherwise mistake for valid key material.
func (e *Encoder) WriteTo(w io.Writer) (n int64, err error) {
	if !e.setIntegrityPassword {
		return 0, fmt.Errorf("refusing to write JCEKS due to likely bug: %w", ErrNoIntegrityPassword)
	}
	if e.entryCount > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %d entries exceeds JCEKS limit", ErrTooManyEntries, e.entryCount)
	}

	var complete bytes.Buffer
	jd := newJCEKSDigester(e.integrityPassword)
	out := io.MultiWriter(&complete, jd)

	if err = writeUint32(out, uint32(jceksMagic)); err != nil {
		return 0, err
	}
	if err = writeUint32(out, uint32(jceksVersion)); err != nil {
		return 0, err
	}
	if err = writeUint32(out, uint32(e.entryCount)); err != nil {
		return 0, err
	}
	for _, entry := range e.entries {
		if len(entry) < 1 {
			continue
		}
		if _, err = out.Write(entry); err != nil {
			return 0, err
		}
	}
	if err = jd.WriteDigest(out); err != nil {
		return 0, err
	}

	// The keystore is fully formed and checksummed at this point, so the caller only ever receives a complete store.
	nn, err := w.Write(complete.Bytes())

	return int64(nn), err
}
