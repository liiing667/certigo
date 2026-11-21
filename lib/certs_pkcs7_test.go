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
	"encoding/pem"
	"io"
	"os"
	"testing"
)

// A PKCS7 SignedData block may contain several signer certificates. Every
// certificate must be passed to the callback, in a stable order, including
// when the same input is read again after a retry.
func TestReadAsX509PKCS7AllSignerCertificates(t *testing.T) {
	fixture, _ := readPKCS7Fixture(t)

	var previous [][]byte
	for attempt := 0; attempt < 2; attempt++ {
		var certs []*x509.Certificate
		err := ReadAsX509([]io.Reader{bytes.NewReader(fixture)}, "PEM", func(string) string {
			return ""
		}, func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return err
			}
			if format != "PEM" {
				t.Errorf("unexpected input format: %q", format)
			}
			certs = append(certs, cert)
			return nil
		})
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if len(certs) != 2 {
			t.Fatalf("attempt %d: got %d certificates, want 2", attempt, len(certs))
		}
		names := map[string]bool{}
		for _, cert := range certs {
			names[cert.Subject.CommonName] = true
		}
		for _, want := range []string{"example-small-key", "example-custom-oids"} {
			if !names[want] {
				t.Fatalf("attempt %d: missing signer certificate %q", attempt, want)
			}
		}
		if attempt > 0 {
			for i, cert := range certs {
				if !bytes.Equal(previous[i], cert.Raw) {
					t.Fatalf("attempt %d: certificate %d changed between reads", attempt, i)
				}
			}
		}
		previous = make([][]byte, len(certs))
		for i, cert := range certs {
			previous[i] = cert.Raw
		}
	}
}

// PEM output must keep the original SignedData bytes intact so signatures and
// content digests remain valid.
func TestReadAsPEMPKCS7PreservesSignedData(t *testing.T) {
	fixture, fixtureBlock := readPKCS7Fixture(t)

	var blocks []*pem.Block
	err := ReadAsPEM([]io.Reader{bytes.NewReader(fixture)}, "PEM", func(string) string {
		return ""
	}, func(block *pem.Block, format string) error {
		if format != "PEM" {
			t.Errorf("unexpected input format: %q", format)
		}
		blocks = append(blocks, block)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 {
		t.Fatalf("got %d PEM blocks, want 1", len(blocks))
	}
	if blocks[0].Type != "PKCS7" || !bytes.Equal(blocks[0].Bytes, fixtureBlock.Bytes) {
		t.Fatal("PKCS7 SignedData bytes changed while reading the input")
	}
}

func readPKCS7Fixture(t *testing.T) ([]byte, *pem.Block) {
	t.Helper()

	fixture, err := os.ReadFile("../test-certs/example-multi-signer.p7b")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(fixture)
	if block == nil || block.Type != "PKCS7" {
		t.Fatal("expected a PKCS7 PEM block in test fixture")
	}
	return fixture, block
}
