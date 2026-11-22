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

package starttls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
)

func dumpTLSConnStateFromIMAP(dialer Dialer, address string, config *tls.Config) (*tls.ConnectionState, error) {
	c, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, &ConnectError{Stage: stageForDialError(err), Err: err}
	}
	defer func() { _ = c.Close() }()

	reader := bufio.NewReader(c)
	status, err := readIMAPLine(reader)
	if err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	if !strings.EqualFold(status, "OK") {
		return nil, &ConnectError{Stage: stageStartTLS, Err: fmt.Errorf("IMAP server responded with %s, was expecting OK", status)}
	}

	if _, err := fmt.Fprint(c, "1 STARTTLS\r\n"); err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	status, err = readIMAPLine(reader)
	if err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	if !strings.EqualFold(status, "OK") {
		return nil, &ConnectError{Stage: stageStartTLS, Err: fmt.Errorf("IMAP server responded with %s, was expecting OK", status)}
	}

	tlsConn := tls.Client(c, config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, &ConnectError{Stage: stageForNetworkError(err, stageTLSHandshake), Err: err}
	}

	state := tlsConn.ConnectionState()
	return &state, nil
}

// readIMAP retains the historical helper signature for callers that pass a
// single TCP connection.
//nolint:unused // Retained for compatibility with package-level callers.
func readIMAP(conn *net.TCPConn) (string, error) {
	return readIMAPLine(bufio.NewReader(conn))
}

func readIMAPLine(reader *bufio.Reader) (string, error) {
	response, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	response = strings.TrimRight(response, "\r\n")
	fields := strings.Fields(response)
	if len(fields) < 2 {
		return "", fmt.Errorf("IMAP server response %q did not contain a status", response)
	}
	return strings.ToUpper(fields[1]), nil
}
