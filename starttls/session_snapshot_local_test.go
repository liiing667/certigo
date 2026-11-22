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
	"errors"
	"testing"
)

func TestCertigoSnapshotHostnameFromConnectTarget(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"example.com", "example.com"},
		{"example.com:443", "example.com"},
		{"127.0.0.1", "127.0.0.1"},
		{"127.0.0.1:443", "127.0.0.1"},
		{"[::1]", "::1"},
		{"[::1]:443", "::1"},
		{"::1", "::1"},
	}

	for _, test := range tests {
		if got := HostnameFromConnectTarget(test.target); got != test.want {
			t.Errorf("HostnameFromConnectTarget(%q) = %q, want %q", test.target, got, test.want)
		}
	}
}

func TestCertigoSnapshotDefaultSNI(t *testing.T) {
	tests := []struct {
		name       string
		connectTo  string
		wantServer string
	}{
		{"hostname target sends SNI", "example.com:443", "example.com"},
		{"IP target does not send SNI", "127.0.0.1:443", ""},
		{"IPv6 target does not send SNI", "[::1]:443", ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conf, _, err := tlsConfigForConnect("", test.connectTo, "", "")
			if err != nil {
				t.Fatalf("tlsConfigForConnect: %v", err)
			}
			if conf.ServerName != test.wantServer {
				t.Errorf("ServerName = %q, want %q", conf.ServerName, test.wantServer)
			}
		})
	}
}

func TestCertigoSnapshotExplicitSNIOverride(t *testing.T) {
	conf, _, err := tlsConfigForConnect("sni.example.com", "127.0.0.1:443", "", "")
	if err != nil {
		t.Fatalf("tlsConfigForConnect: %v", err)
	}
	if conf.ServerName != "sni.example.com" {
		t.Errorf("ServerName = %q, want sni.example.com", conf.ServerName)
	}
}

func TestCertigoSnapshotIPv6DefaultPort(t *testing.T) {
	if got := withDefaultPort("[::1]", 443); got != "[::1]:443" {
		t.Errorf("withDefaultPort([::1]) = %q, want [::1]:443", got)
	}
	if got := withDefaultPort("::1", 443); got != "[::1]:443" {
		t.Errorf("withDefaultPort(::1) = %q, want [::1]:443", got)
	}
	if got := withDefaultPort("example.com:443", 443); got != "example.com:443" {
		t.Errorf("withDefaultPort(example.com:443) = %q, want example.com:443", got)
	}
}

func TestCertigoSnapshotErrorStage(t *testing.T) {
	err := &ConnectError{Stage: "tls_handshake", Err: errors.New("handshake failed")}
	if got := ErrorStage(err); got != "tls_handshake" {
		t.Errorf("ErrorStage = %q, want tls_handshake", got)
	}
	if got := ErrorStage(errors.New("plain error")); got != "" {
		t.Errorf("ErrorStage(plain error) = %q, want empty", got)
	}
}
