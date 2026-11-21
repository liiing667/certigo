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
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/square/certigo/cli/terminal"
)

func writeConnectionGenerationSMTPLine(conn net.Conn, line string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", line)
	return err
}

func serveConnectionGenerationStartTLS(conn net.Conn, cert tls.Certificate, failHandshake bool) error {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if err := writeConnectionGenerationSMTPLine(conn, "220 test SMTP"); err != nil {
		return err
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "EHLO ") {
		return fmt.Errorf("expected EHLO, got %q", line)
	}
	if err := writeConnectionGenerationSMTPLine(conn, "250-test"); err != nil {
		return err
	}
	if err := writeConnectionGenerationSMTPLine(conn, "250 STARTTLS"); err != nil {
		return err
	}

	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.ToUpper(strings.TrimSpace(line)) != "STARTTLS" {
		return fmt.Errorf("expected STARTTLS, got %q", line)
	}
	if err := writeConnectionGenerationSMTPLine(conn, "220 Ready to start TLS"); err != nil {
		return err
	}

	if failHandshake {
		return nil
	}

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	_ = tlsConn.Close()
	return nil
}

// A failed StartTLS handshake is retried once, but the retry and the final
// verification report must use the frozen target and the certificate chain
// from the successful connection.
func TestConnectionGenerationRetriesStartTLSHandshake(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}

	rootFile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("create CA file: %v", err)
	}
	defer func() { _ = os.Remove(rootFile.Name()) }()
	if _, err := rootFile.Write(localhostRoot); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := rootFile.Close(); err != nil {
		t.Fatalf("close CA file: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))

	serverErr := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			if err := serveConnectionGenerationStartTLS(conn, cert, i == 0); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	testTerminal := &terminal.TestTerminal{Width: 80}
	args := []string{
		"connect",
		"--start-tls", "smtp",
		"--ca", rootFile.Name(),
		"--verify",
		"--expected-name", "127.0.0.1",
		listener.Addr().String(),
	}
	code := Run(args, testTerminal)

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("SMTP fixture: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for SMTP fixture")
	}

	if code != 0 {
		t.Fatalf("Run returned %d, stderr: %s", code, testTerminal.ErrorBuf.String())
	}
	output := testTerminal.OutputBuf.String()
	if !strings.Contains(output, "Attempts: 2") {
		t.Fatalf("output does not report the retry count:\n%s", output)
	}
	if !strings.Contains(output, "Failure Stage: tls_handshake") {
		t.Fatalf("output does not report the failed handshake stage:\n%s", output)
	}
	if !strings.Contains(output, "Found 1 valid certificate chain(s)") {
		t.Fatalf("retry did not verify the second connection's certificate chain:\n%s", output)
	}
}
