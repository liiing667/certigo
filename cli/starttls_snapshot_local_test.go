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

func writeRetryFixtureLine(conn net.Conn, line string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", line)
	return err
}

func serveSMTPRetryFixture(conn net.Conn, cert tls.Certificate, failHandshake, requestClientCert bool) error {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if err := writeRetryFixtureLine(conn, "220 test SMTP"); err != nil {
		return err
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "EHLO ") {
		return fmt.Errorf("expected EHLO, got %q", line)
	}
	if err := writeRetryFixtureLine(conn, "250-test"); err != nil {
		return err
	}
	if err := writeRetryFixtureLine(conn, "250 STARTTLS"); err != nil {
		return err
	}

	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.ToUpper(strings.TrimSpace(line)) != "STARTTLS" {
		return fmt.Errorf("expected STARTTLS, got %q", line)
	}
	if err := writeRetryFixtureLine(conn, "220 Ready to start TLS"); err != nil {
		return err
	}

	if failHandshake {
		serverConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MaxVersion:   tls.VersionTLS12,
		}
		if requestClientCert {
			serverConfig.ClientAuth = tls.RequireAnyClientCert
		}
		// The fixture deliberately lets this handshake fail after the client
		// certificate request so the retry can prove that the request
		// information does not survive into the successful connection.
		_ = tls.Server(conn, serverConfig).Handshake()
		return nil
	}

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	// net/smtp historically issues a new EHLO inside StartTLS after the TLS
	// handshake. Respond when it arrives, but do not require it on Go
	// versions that consider the handshake complete without re-EHLO.
	_ = tlsConn.SetReadDeadline(time.Now().Add(time.Second))
	tlsReader := bufio.NewReader(tlsConn)
	line, err = tlsReader.ReadString('\n')
	if err == nil {
		if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "EHLO ") {
			return fmt.Errorf("expected EHLO after TLS, got %q", line)
		}
		if err := writeRetryFixtureLine(tlsConn, "250 OK"); err != nil {
			return err
		}
	}
	_ = tlsConn.Close()
	return nil
}

func serveIMAPRetryFixture(conn net.Conn, cert tls.Certificate, reject bool) error {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	if err := writeRetryFixtureLine(conn, "* OK IMAP ready"); err != nil {
		return err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(strings.ToUpper(line), "STARTTLS") {
		return fmt.Errorf("expected STARTTLS, got %q", line)
	}
	if reject {
		return writeRetryFixtureLine(conn, "1 NO not now")
	}
	if err := writeRetryFixtureLine(conn, "1 OK begin TLS"); err != nil {
		return err
	}

	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	_ = tlsConn.Close()
	return nil
}

func writeRetryFixtureRoot(t *testing.T) string {
	t.Helper()
	rootFile, err := os.CreateTemp("", t.Name())
	if err != nil {
		t.Fatalf("create CA file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(rootFile.Name()) })
	if _, err := rootFile.Write(localhostRoot); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	if err := rootFile.Close(); err != nil {
		t.Fatalf("close CA file: %v", err)
	}
	return rootFile.Name()
}

func waitForRetryFixture(t *testing.T, errs <-chan error) {
	t.Helper()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("StartTLS fixture: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for StartTLS fixture")
	}
}

// A failed StartTLS handshake is retried once, and the successful connection's
// certificate chain and (empty) client-certificate request state are the only
// ones that reach the report.
func TestCertigoSnapshotSMTPRetryPublishesOnlyFinalState(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}
	rootPath := writeRetryFixtureRoot(t)

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
			if err := serveSMTPRetryFixture(conn, cert, i == 0, i == 0); err != nil {
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
		"--ca", rootPath,
		"--verify",
		"--expected-name", "127.0.0.1",
		listener.Addr().String(),
	}
	code := Run(args, testTerminal)
	waitForRetryFixture(t, serverErr)

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
	if strings.Contains(output, "Server has requested a client certificate") {
		t.Fatalf("previous connection's client-certificate request leaked into the report:\n%s", output)
	}
	if !strings.Contains(output, "Found 1 valid certificate chain(s)") {
		t.Fatalf("retry did not verify the second connection's certificate chain:\n%s", output)
	}
}

// A rejected IMAP STARTTLS upgrade is retried on a fresh connection. Only the
// connection that actually completes TLS may supply the certificate state.
func TestCertigoSnapshotIMAPRejectionReconnectsBeforePublishing(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}
	rootPath := writeRetryFixtureRoot(t)

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
			if err := serveIMAPRetryFixture(conn, cert, i == 0); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	testTerminal := &terminal.TestTerminal{Width: 80}
	args := []string{
		"connect",
		"--start-tls", "imap",
		"--ca", rootPath,
		"--verify",
		"--expected-name", "127.0.0.1",
		listener.Addr().String(),
	}
	code := Run(args, testTerminal)
	waitForRetryFixture(t, serverErr)

	if code != 0 {
		t.Fatalf("Run returned %d, stderr: %s", code, testTerminal.ErrorBuf.String())
	}
	output := testTerminal.OutputBuf.String()
	if !strings.Contains(output, "Attempts: 2") {
		t.Fatalf("output does not report the retry count:\n%s", output)
	}
	if !strings.Contains(output, "Failure Stage: starttls") {
		t.Fatalf("output does not report the rejected upgrade stage:\n%s", output)
	}
	if !strings.Contains(output, "Found 1 valid certificate chain(s)") {
		t.Fatalf("retry did not verify the completed connection's certificate chain:\n%s", output)
	}
}
