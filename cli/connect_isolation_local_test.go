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
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/square/certigo/cli/terminal"
)

// Concurrent Run calls must not share the SNI or expected-name flags. The
// successful call verifies against 127.0.0.1 while the other deliberately
// verifies against the wrong name and must still fail.
func TestCertigoSnapshotConcurrentVerificationIsolation(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}
	rootPath := writeRetryFixtureRoot(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	ts.TLS.Certificates = []tls.Certificate{cert}
	addr := ts.URL[len("https://"):]

	start := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(2)

	var goodCode, badCode int
	goodTerminal := &terminal.TestTerminal{Width: 80}
	badTerminal := &terminal.TestTerminal{Width: 80}

	go func() {
		defer wait.Done()
		<-start
		goodCode = Run([]string{
			"connect",
			"--ca", rootPath,
			"--verify",
			"--expected-name", "127.0.0.1",
			addr,
		}, goodTerminal)
	}()
	go func() {
		defer wait.Done()
		<-start
		badCode = Run([]string{
			"connect",
			"--ca", rootPath,
			"--verify",
			"--expected-name", "wrong.example.com",
			addr,
		}, badTerminal)
	}()

	close(start)
	wait.Wait()

	if goodCode != 0 {
		t.Fatalf("valid connection returned %d, stderr: %s", goodCode, goodTerminal.ErrorBuf.String())
	}
	if badCode != 1 {
		t.Fatalf("wrong-name connection returned %d, want 1; stderr: %s", badCode, badTerminal.ErrorBuf.String())
	}
	if !strings.Contains(goodTerminal.OutputBuf.String(), "Found 1 valid certificate chain(s)") {
		t.Fatalf("valid connection did not report its own chain:\n%s", goodTerminal.OutputBuf.String())
	}
	if !strings.Contains(badTerminal.OutputBuf.String(), "Failed to verify certificate chain:") {
		t.Fatalf("wrong-name connection did not report its own verification failure:\n%s", badTerminal.OutputBuf.String())
	}
}
