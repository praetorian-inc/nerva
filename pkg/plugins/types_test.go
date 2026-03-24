// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugins

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSecurityFinding_JSONRoundTrip(t *testing.T) {
	original := SecurityFinding{
		ID:          "ftp-anon-access",
		Severity:    SeverityHigh,
		Description: "Anonymous FTP login permitted",
		Evidence:    "220 FTP server ready\n331 Anonymous login ok",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var got SecurityFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if got.ID != original.ID {
		t.Errorf("ID: got %q, want %q", got.ID, original.ID)
	}
	if got.Severity != original.Severity {
		t.Errorf("Severity: got %q, want %q", got.Severity, original.Severity)
	}
	if got.Description != original.Description {
		t.Errorf("Description: got %q, want %q", got.Description, original.Description)
	}
	if got.Evidence != original.Evidence {
		t.Errorf("Evidence: got %q, want %q", got.Evidence, original.Evidence)
	}
}

func TestSecurityFinding_OmitemptyEvidence(t *testing.T) {
	finding := SecurityFinding{
		ID:          "ssh-weak-algo",
		Severity:    SeverityMedium,
		Description: "Weak MAC algorithm negotiated",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	if strings.Contains(string(data), `"evidence"`) {
		t.Errorf("expected no 'evidence' key in JSON when Evidence is empty, got: %s", string(data))
	}
}

func TestService_OmitemptyNoFindingsNoAnonymousAccess(t *testing.T) {
	svc := Service{
		IP:        "10.0.0.1",
		Port:      21,
		Protocol:  "ftp",
		TLS:       false,
		Transport: "tcp",
		Raw:       json.RawMessage(`{}`),
	}

	data, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	output := string(data)
	if strings.Contains(output, `"security_findings"`) {
		t.Errorf("expected no 'security_findings' key when findings is nil, got: %s", output)
	}
	if strings.Contains(output, `"anonymous_access"`) {
		t.Errorf("expected no 'anonymous_access' key when AnonymousAccess is false, got: %s", output)
	}
}

func TestService_WithFindingsAndAnonymousAccess(t *testing.T) {
	svc := Service{
		IP:        "10.0.0.2",
		Port:      21,
		Protocol:  "ftp",
		TLS:       false,
		Transport: "tcp",
		Raw:       json.RawMessage(`{}`),
		AnonymousAccess: true,
		SecurityFindings: []SecurityFinding{
			{
				ID:          "ftp-anon-access",
				Severity:    SeverityHigh,
				Description: "Anonymous FTP login permitted",
				Evidence:    "331 Anonymous login ok",
			},
		},
	}

	data, err := json.Marshal(svc)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	output := string(data)
	if !strings.Contains(output, `"anonymous_access":true`) {
		t.Errorf("expected 'anonymous_access':true in JSON, got: %s", output)
	}
	if !strings.Contains(output, `"security_findings"`) {
		t.Errorf("expected 'security_findings' key in JSON, got: %s", output)
	}
	if !strings.Contains(output, `"ftp-anon-access"`) {
		t.Errorf("expected finding ID 'ftp-anon-access' in JSON, got: %s", output)
	}

	// Round-trip the SecurityFindings to verify they decode correctly.
	var decoded Service
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if !decoded.AnonymousAccess {
		t.Error("expected decoded AnonymousAccess to be true")
	}
	if len(decoded.SecurityFindings) != 1 {
		t.Fatalf("expected 1 decoded finding, got %d", len(decoded.SecurityFindings))
	}
	if decoded.SecurityFindings[0].ID != "ftp-anon-access" {
		t.Errorf("finding ID: got %q, want %q", decoded.SecurityFindings[0].ID, "ftp-anon-access")
	}
	if decoded.SecurityFindings[0].Severity != SeverityHigh {
		t.Errorf("finding Severity: got %q, want %q", decoded.SecurityFindings[0].Severity, SeverityHigh)
	}
}

func TestSeverity_Valid(t *testing.T) {
	valid := []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("expected Severity(%q).Valid() == true", s)
		}
	}

	invalid := Severity("unknown")
	if invalid.Valid() {
		t.Errorf("expected Severity(%q).Valid() == false", invalid)
	}
}
