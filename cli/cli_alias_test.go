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
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/square/certigo/cli/terminal"
)

const multiAliasPKCS12 = "../lib/testdata/multi-alias.p12"

func aliasTestDecodePEMBlocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()

	var blocks []*pem.Block
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		data = rest
	}
	return blocks
}

func runAliasDump(t *testing.T, args ...string) (int, *terminal.TestTerminal) {
	t.Helper()
	testTerminal := &terminal.TestTerminal{Width: 80, Password: "password"}
	return Run(append([]string{"dump"}, args...), testTerminal), testTerminal
}

func TestSecretExportCLIExportsOnlySelectedEntry(t *testing.T) {
	code, targetTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "target", multiAliasPKCS12)
	require.Equal(t, 0, code)
	require.Empty(t, targetTerminal.ErrorBuf.Bytes())

	targetBlocks := aliasTestDecodePEMBlocks(t, targetTerminal.OutputBuf.Bytes())
	require.Len(t, targetBlocks, 3)
	var targetCerts, targetKeys int
	for _, block := range targetBlocks {
		switch block.Type {
		case "CERTIFICATE":
			targetCerts++
		case "RSA PRIVATE KEY":
			targetKeys++
		}
	}
	require.Equal(t, 2, targetCerts)
	require.Equal(t, 1, targetKeys)

	code, neighborTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "neighbor", multiAliasPKCS12)
	require.Equal(t, 0, code)
	neighborBlocks := aliasTestDecodePEMBlocks(t, neighborTerminal.OutputBuf.Bytes())
	require.Len(t, neighborBlocks, 2)

	// No block from the neighboring alias may appear in the target export.
	for _, neighborBlock := range neighborBlocks {
		for _, targetBlock := range targetBlocks {
			require.NotEqual(t, neighborBlock.Bytes, targetBlock.Bytes)
		}
	}

	// Calls without --alias keep the historical behavior and export every
	// entry in the store.
	code, allTerminal := runAliasDump(t, "--pem", "--password", "password", multiAliasPKCS12)
	require.Equal(t, 0, code)
	require.Len(t, aliasTestDecodePEMBlocks(t, allTerminal.OutputBuf.Bytes()), 5)
}

func TestSecretExportCLIJSONContainsOnlyTargetChain(t *testing.T) {
	code, testTerminal := runAliasDump(t, "--json", "--password", "password", "--alias", "target", multiAliasPKCS12)
	require.Equal(t, 0, code)
	require.Empty(t, testTerminal.ErrorBuf.Bytes())

	var output struct {
		Certificates []struct {
			Alias   string `json:"alias"`
			Subject struct {
				CommonName string `json:"common_name"`
			} `json:"subject"`
		} `json:"certificates"`
	}
	require.NoError(t, json.Unmarshal(testTerminal.OutputBuf.Bytes(), &output))
	require.Len(t, output.Certificates, 2)
	require.Equal(t, "target", output.Certificates[0].Alias)
	require.Equal(t, "target", output.Certificates[1].Alias)
	require.Equal(t, "Test User", output.Certificates[0].Subject.CommonName)
	require.Equal(t, "Test CA", output.Certificates[1].Subject.CommonName)
}

func TestSecretExportCLITextReportsTargetAlias(t *testing.T) {
	code, testTerminal := runAliasDump(t, "--password", "password", "--alias", "target", multiAliasPKCS12)
	require.Equal(t, 0, code)
	require.Contains(t, testTerminal.OutputBuf.String(), "target\nValid:")
}

func TestSecretExportCLIMissingRejectsWithoutPartialOutput(t *testing.T) {
	code, testTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "missing", multiAliasPKCS12)
	require.Equal(t, 2, code)
	require.Empty(t, testTerminal.OutputBuf.Bytes())
	require.Contains(t, testTerminal.ErrorBuf.String(), "alias \"missing\"")
	require.Contains(t, testTerminal.ErrorBuf.String(), "select")

	// Alias selection is only meaningful for key stores. It is rejected
	// rather than silently exporting every certificate from a PEM file.
	code, testTerminal = runAliasDump(t, "--pem", "--alias", "missing", "../test-certs/example-leaf.crt")
	require.Equal(t, 2, code)
	require.Empty(t, testTerminal.OutputBuf.Bytes())
	require.Contains(t, testTerminal.ErrorBuf.String(), "PKCS12 or JCEKS")
}

func TestSecretExportCLIRetryDoesNotReusePreviousStoreOrAlias(t *testing.T) {
	code, wrongPasswordTerminal := runAliasDump(t, "--pem", "--password", "wrong", "--alias", "example-leaf", "../test-certs/example-leaf.p12")
	require.Equal(t, 2, code)
	require.Empty(t, wrongPasswordTerminal.OutputBuf.Bytes())
	require.Contains(t, wrongPasswordTerminal.ErrorBuf.String(), "unlock")

	code, correctPasswordTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "example-leaf", "../test-certs/example-leaf.p12")
	require.Equal(t, 0, code)
	require.Len(t, aliasTestDecodePEMBlocks(t, correctPasswordTerminal.OutputBuf.Bytes()), 2)

	// Changing the alias in the same process must not leave the previous
	// entry in the export.
	code, targetTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "target", multiAliasPKCS12)
	require.Equal(t, 0, code)
	targetBlocks := aliasTestDecodePEMBlocks(t, targetTerminal.OutputBuf.Bytes())
	require.Len(t, targetBlocks, 3)

	code, neighborTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "neighbor", multiAliasPKCS12)
	require.Equal(t, 0, code)
	neighborBlocks := aliasTestDecodePEMBlocks(t, neighborTerminal.OutputBuf.Bytes())
	require.Len(t, neighborBlocks, 2)
	for _, neighborBlock := range neighborBlocks {
		for _, targetBlock := range targetBlocks {
			require.NotEqual(t, neighborBlock.Bytes, targetBlock.Bytes)
		}
	}
}

type aliasFailingOutput struct {
	bytes.Buffer
}

func (f *aliasFailingOutput) Write([]byte) (int, error) {
	return 0, errors.New("output is unavailable")
}

type aliasFailingOutputTerminal struct {
	*terminal.TestTerminal
	output aliasFailingOutput
}

func (t *aliasFailingOutputTerminal) Output() io.Writer {
	return &t.output
}

func TestSecretExportCLIOutputFailurePublishesNothing(t *testing.T) {
	testTerminal := &aliasFailingOutputTerminal{
		TestTerminal: &terminal.TestTerminal{Width: 80, Password: "password"},
	}

	code := Run([]string{
		"dump", "--pem", "--password", "password", "--alias", "target", multiAliasPKCS12,
	}, testTerminal)

	require.Equal(t, 2, code)
	require.Empty(t, testTerminal.output.Bytes())
	require.Contains(t, testTerminal.ErrorBuf.String(), "output")
	require.Contains(t, testTerminal.ErrorBuf.String(), "alias \"target\"")
}

func TestSecretExportCLIPKCS12AliasPreservesLegacyBlocks(t *testing.T) {
	code, allTerminal := runAliasDump(t, "--pem", "--password", "password", "../test-certs/example-leaf.p12")
	require.Equal(t, 0, code)

	code, aliasTerminal := runAliasDump(t, "--pem", "--password", "password", "--alias", "example-leaf", "../test-certs/example-leaf.p12")
	require.Equal(t, 0, code)

	require.Equal(t, allTerminal.OutputBuf.Bytes(), aliasTerminal.OutputBuf.Bytes())
}
