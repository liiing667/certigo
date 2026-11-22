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

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/square/certigo/cli/terminal"
)

func writeSCTRegressionInput(t *testing.T, contents []byte) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "certigo-sct-input-*")
	require.NoError(t, err)
	_, err = file.Write(contents)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	return file.Name()
}

func TestDumpSCTPerCertificateRegression(t *testing.T) {
	sctPEM, err := os.ReadFile("../lib/testdata/ct-sct-cert.pem")
	require.NoError(t, err)

	contents := append(append([]byte(nil), sctPEM...), []byte(testCert)...)
	path := writeSCTRegressionInput(t, contents)

	// Passing the same file twice exercises reading a certificate, then a
	// certificate without SCTs, then the same certificate again.
	args := []string{"dump", "--verbose", "--format", "PEM", path, path}
	term := &terminal.TestTerminal{Width: 80}
	require.Equal(t, 0, Run(args, term))
	require.Empty(t, term.ErrorBuf.String())

	sections := strings.Split(term.OutputBuf.String(), "** CERTIFICATE ")
	require.Len(t, sections, 5, "expected four certificates")
	for i, section := range sections[1:] {
		wantSCTs := 0
		if i == 0 || i == 2 {
			wantSCTs = 3
		}
		assert.Equal(t, wantSCTs, strings.Count(section, "Signed Certificate Timestamp:"),
			"certificate %d has the wrong number of SCTs", i+1)
	}

	// A second read of the exact same file must produce the same per-certificate
	// SCT assignment rather than reusing state from the previous invocation.
	again := &terminal.TestTerminal{Width: 80}
	require.Equal(t, 0, Run(args, again))
	require.Empty(t, again.ErrorBuf.String())
	assert.Equal(t, term.OutputBuf.String(), again.OutputBuf.String())
}

func TestDumpSCTRetryRegression(t *testing.T) {
	badPath := writeSCTRegressionInput(t, []byte(
		"-----BEGIN CERTIFICATE-----\n"+
			"bm90IGEgY2VydGlmaWNhdGU=\n"+
			"-----END CERTIFICATE-----\n"))

	badTerm := &terminal.TestTerminal{Width: 80}
	require.Equal(t, 2, Run([]string{"dump", "--verbose", "--format", "PEM", badPath}, badTerm))
	assert.NotEmpty(t, badTerm.ErrorBuf.String())
	assert.Zero(t, strings.Count(badTerm.OutputBuf.String(), "Signed Certificate Timestamp:"))

	goodPath := writeSCTRegressionInput(t, []byte(testCert))
	goodTerm := &terminal.TestTerminal{Width: 80}
	require.Equal(t, 0, Run([]string{"dump", "--verbose", "--format", "PEM", goodPath}, goodTerm))
	require.Empty(t, goodTerm.ErrorBuf.String())
	assert.Zero(t, strings.Count(goodTerm.OutputBuf.String(), "Signed Certificate Timestamp:"),
		"a failed read must not leak SCTs into the next certificate")
}
