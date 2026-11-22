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
	"testing"
	"time"
)

func TestCertigoSnapshotAttemptLimits(t *testing.T) {
	if got := connectAttemptLimit(""); got != 1 {
		t.Errorf("plain TLS attempt limit = %d, want 1", got)
	}
	if got := connectAttemptLimit("smtp"); got != maxStartTLSConnectionAttempts {
		t.Errorf("StartTLS attempt limit = %d, want %d", got, maxStartTLSConnectionAttempts)
	}
}

func TestCertigoSnapshotConnectionReport(t *testing.T) {
	attempt := connectAttempt{
		protocol: "smtp",
		target:   "mail.example.com:25",
		host:     "mail.example.com",
	}

	if report := connectionReport(attempt, connectOutcome{attempts: 1}); report != nil {
		t.Fatalf("single successful attempt unexpectedly produced a report: %+v", report)
	}

	report := connectionReport(attempt, connectOutcome{attempts: 2, generation: 7, failureStage: "starttls"})
	if report == nil {
		t.Fatal("retry did not produce a connection report")
	}
	if report.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", report.Attempts)
	}
	if report.Generation != 7 {
		t.Errorf("Generation = %d, want 7", report.Generation)
	}
	if report.Target != attempt.target || report.Host != attempt.host {
		t.Errorf("report target = %q/%q, want %q/%q", report.Target, report.Host, attempt.target, attempt.host)
	}
	if report.FailureStage != "starttls" {
		t.Errorf("FailureStage = %q, want starttls", report.FailureStage)
	}
}

func TestCertigoSnapshotResetFlags(t *testing.T) {
	runMu.Lock()
	defer runMu.Unlock()

	*connectName = "old.example.com"
	*connectStartTLS = "smtp"
	*connectTimeout = time.Millisecond
	*connectVerify = true
	*connectVerifyExpectedName = "old.example.com"
	*connectInsecure = true

	resetFlags()

	if *connectName != "" || *connectStartTLS != "" || *connectVerifyExpectedName != "" {
		t.Fatal("connect name, protocol, or expected name leaked across invocations")
	}
	if *connectTimeout != 5*time.Second {
		t.Fatalf("timeout = %s, want 5s", *connectTimeout)
	}
	if *connectVerify || *connectInsecure {
		t.Fatal("verification mode leaked across invocations")
	}
}
