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
	"strconv"
	"strings"
)

func dumpTLSConnStateFromFTP(dialer Dialer, address string, config *tls.Config) (*tls.ConnectionState, error) {
	c, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, &ConnectError{Stage: stageForDialError(err), Err: err}
	}
	defer func() { _ = c.Close() }()

	reader := bufio.NewReader(c)
	status, err := readFTPLine(reader)
	if err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	if status != 220 {
		return nil, &ConnectError{Stage: stageStartTLS, Err: fmt.Errorf("FTP server responded with status %d, was expecting 220", status)}
	}

	if _, err := fmt.Fprint(c, "AUTH TLS\r\n"); err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	status, err = readFTPLine(reader)
	if err != nil {
		return nil, &ConnectError{Stage: stageStartTLS, Err: err}
	}
	if status != 234 {
		return nil, &ConnectError{Stage: stageStartTLS, Err: fmt.Errorf("FTP server responded with status %d, was expecting 234", status)}
	}

	tlsConn := tls.Client(c, config)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, &ConnectError{Stage: stageForNetworkError(err, stageTLSHandshake), Err: err}
	}

	state := tlsConn.ConnectionState()
	return &state, nil
}

// readFTP retains the historical helper signature for callers that pass a
// single TCP connection.
//nolint:unused // Retained for compatibility with package-level callers.
func readFTP(conn *net.TCPConn) (int, error) {
	return readFTPLine(bufio.NewReader(conn))
}

func readFTPLine(reader *bufio.Reader) (int, error) {
	for {
		rawResponse, err := reader.ReadString('\n')
		if err != nil {
			return 0, err
		}
		response := strings.TrimRight(rawResponse, "\r\n")
		if len(response) < 3 {
			return 0, fmt.Errorf("Error parsing ftp protocol: Status code too short: '%s'", rawResponse)
		}
		status, err := strconv.Atoi(response[:3])
		if err != nil {
			return 0, err
		}
		if len(response) == 3 {
			return status, nil
		}
		// A hyphen after the status code starts a multi-line response. Keep
		// reading until the final line whose status code is followed by a
		// space.
		if response[3] == '-' {
			continue
		}
		return status, nil
	}
}
