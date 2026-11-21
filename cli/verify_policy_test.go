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
	"path/filepath"
	"testing"

	"github.com/square/certigo/cli/terminal"
)

func TestChainPolicyCLIExitCodeUsesAnchorReport(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	rootsPath := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(certPath, localhostCert, 0o600); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}
	if err := os.WriteFile(rootsPath, localhostRoot, 0o600); err != nil {
		t.Fatalf("failed to write roots: %v", err)
	}

	args := []string{"verify", "--name", "127.0.0.1", "--ca", rootsPath, certPath}
	if code := Run(args, &terminal.TestTerminal{Width: 80}); code != 0 {
		t.Fatalf("trusted verification exit code = %d, want 0", code)
	}

	// Replace the trust anchor with an unrelated certificate. The same
	// invocation must now fail, using the same report that supplies the exit
	// code.
	if err := os.WriteFile(rootsPath, []byte(testCert), 0o600); err != nil {
		t.Fatalf("failed to replace roots: %v", err)
	}
	if code := Run(args, &terminal.TestTerminal{Width: 80}); code != 1 {
		t.Fatalf("untrusted verification exit code = %d, want 1", code)
	}
}
