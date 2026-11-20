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
	"encoding/binary"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func readTestData(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	return data
}

func TestParseRejectsNilPassword(t *testing.T) {
	t.Parallel()

	data := readTestData(t, "testdata/trusted-cert.jceks")

	_, err := LoadFromReader(bytes.NewReader(data), nil)
	require.ErrorIs(t, err, ErrInvalidPassword)

	var ks KeyStore
	err = ks.Parse(bytes.NewReader(data), nil)
	require.ErrorIs(t, err, ErrInvalidPassword)

	// A tampered key store must not parse even when no password is supplied.
	tampered := bytes.Clone(data)
	tampered[len(tampered)/2] ^= 0xFF
	_, err = LoadFromReader(bytes.NewReader(tampered), nil)
	require.Error(t, err)
}

func TestParseRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	for _, filename := range []string{"testdata/trusted-cert.jceks", "testdata/private-key.jceks"} {
		data := readTestData(t, filename)
		_, err := LoadFromReader(bytes.NewReader(data), []byte("wrong-password"))
		require.ErrorIs(t, err, ErrIntegrityProtectionViolation, "file: %s", filename)
	}
}

func TestParseRejectsTamperedContent(t *testing.T) {
	t.Parallel()

	data := readTestData(t, "testdata/trusted-cert.jceks")

	// Flip a bit inside the first entry's timestamp. The entry still parses, so only the integrity check can
	// catch the modification. The timestamp sits right after the header, entry tag, and alias.
	tampered := bytes.Clone(data)
	tampered[45] ^= 0x01
	_, err := LoadFromReader(bytes.NewReader(tampered), []byte("store-password"))
	require.ErrorIs(t, err, ErrIntegrityProtectionViolation)

	// Flip a bit in the trailing integrity checksum itself.
	tampered = bytes.Clone(data)
	tampered[len(tampered)-1] ^= 0x01
	_, err = LoadFromReader(bytes.NewReader(tampered), []byte("store-password"))
	require.ErrorIs(t, err, ErrIntegrityProtectionViolation)
}

func TestParseRejectsTruncated(t *testing.T) {
	t.Parallel()

	data := readTestData(t, "testdata/trusted-cert.jceks")
	_, err := LoadFromReader(bytes.NewReader(data[:len(data)-10]), []byte("store-password"))
	require.ErrorIs(t, err, ErrInvalidJCEKSData)
}

// buildStoreWithMAC assembles a key store from a raw body (everything after the 8-byte header) and appends a valid
// integrity checksum for the given password.
func buildStoreWithMAC(t *testing.T, password string, body []byte) []byte {
	t.Helper()

	encodedPassword, err := encodeIntegrityPassword(password)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksVersion)))
	buf.Write(body)

	md := makeIntegrityHash(encodedPassword)
	md.Write(buf.Bytes())
	buf.Write(md.Sum(nil))

	return buf.Bytes()
}

func TestParseRejectsMalformedLengths(t *testing.T) {
	t.Parallel()

	const password = "store-password"

	writePrivateKeyPrefix := func(buf *bytes.Buffer) {
		require.NoError(t, binary.Write(buf, binary.BigEndian, int32(1)))                   // entry count
		require.NoError(t, binary.Write(buf, binary.BigEndian, uint32(privateKeyEntryTag))) // tag
		require.NoError(t, writeString(buf, "alias"))
		require.NoError(t, writeDate(buf, time.UnixMilli(0)))
		require.NoError(t, writeBytes(buf, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	}

	t.Run("negative entry count", func(t *testing.T) {
		t.Parallel()
		var body bytes.Buffer
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(-1)))
		data := buildStoreWithMAC(t, password, body.Bytes())
		_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
		require.ErrorIs(t, err, ErrInvalidJCEKSData)
	})

	t.Run("negative certificate count", func(t *testing.T) {
		t.Parallel()
		var body bytes.Buffer
		writePrivateKeyPrefix(&body)
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(-1)))
		data := buildStoreWithMAC(t, password, body.Bytes())
		_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
		require.ErrorIs(t, err, ErrInvalidJCEKSData)
	})

	t.Run("oversized byte field", func(t *testing.T) {
		t.Parallel()
		var body bytes.Buffer
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(1)))
		require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))
		require.NoError(t, writeString(&body, "alias"))
		require.NoError(t, writeDate(&body, time.UnixMilli(0)))
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(0x7fffffff)))
		data := buildStoreWithMAC(t, password, body.Bytes())
		_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
		require.ErrorIs(t, err, ErrJCEKSDataTooLarge)
	})

	t.Run("corrupt certificate in private key entry", func(t *testing.T) {
		t.Parallel()
		var body bytes.Buffer
		writePrivateKeyPrefix(&body)
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(1))) // cert count
		require.NoError(t, writeString(&body, x509CertTag))
		require.NoError(t, writeBytes(&body, []byte{0xde, 0xad, 0xbe, 0xef}))
		data := buildStoreWithMAC(t, password, body.Bytes())
		_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
		require.ErrorIs(t, err, ErrInvalidJCEKSData)
	})

	t.Run("truncated modified UTF-8 alias", func(t *testing.T) {
		t.Parallel()
		var body bytes.Buffer
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(1)))
		require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))
		require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(6)))
		body.Write([]byte{0xed, 0xa0, 0x80}) // truncated surrogate pair encoding
		data := buildStoreWithMAC(t, password, body.Bytes())
		_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
		require.Error(t, err)
	})
}

func TestEncodedAliasRoundTrip(t *testing.T) {
	t.Parallel()

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	// Aliases requiring modified UTF-8 encodings whose lengths differ from their UTF-8 lengths must round-trip.
	aliases := []string{"𝄞", "nul\x00alias", "plain"}

	var enc Encoder
	for _, alias := range aliases {
		require.NoError(t, enc.AddTrustedCertificate(alias, now, cert.Raw))
	}
	require.NoError(t, enc.SetIntegrityPassword("changeit"))

	var buf bytes.Buffer
	_, err = enc.WriteTo(&buf)
	require.NoError(t, err)

	ks, err := LoadFromReader(bytes.NewReader(buf.Bytes()), []byte("changeit"))
	require.NoError(t, err)
	require.Equal(t, []string{"nul\x00alias", "plain", "𝄞"}, ks.ListCerts())
	for _, alias := range aliases {
		got, err := ks.GetCert(alias)
		require.NoError(t, err)
		require.True(t, cert.Equal(got))
	}
}

func TestEncodedAliasTooLong(t *testing.T) {
	t.Parallel()

	cert, err := LoadPEMCert("testdata/trusted-cert.crt")
	require.NoError(t, err)
	now := time.Date(2025, 4, 24, 0, 0, 0, 0, time.UTC)

	// The UTF-8 length of this alias fits in a uint16, but its modified UTF-8 encoding does not.
	var enc Encoder
	err = enc.AddTrustedCertificate(strings.Repeat("𝄞", 12000), now, cert.Raw)
	require.ErrorIs(t, err, ErrInvalidString)
}
