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
		ID:             "ftp-anon-access",
		Severity:       SeverityHigh,
		Title:          "FTP Anonymous Access",
		Description:    "Anonymous FTP login permitted",
		Impact:         "Attackers can read files without credentials.",
		Recommendation: "Disable anonymous FTP access.",
		Evidence:       "220 FTP server ready\n331 Anonymous login ok",
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
	if got.Title != original.Title {
		t.Errorf("Title: got %q, want %q", got.Title, original.Title)
	}
	if got.Description != original.Description {
		t.Errorf("Description: got %q, want %q", got.Description, original.Description)
	}
	if got.Impact != original.Impact {
		t.Errorf("Impact: got %q, want %q", got.Impact, original.Impact)
	}
	if got.Recommendation != original.Recommendation {
		t.Errorf("Recommendation: got %q, want %q", got.Recommendation, original.Recommendation)
	}
	if got.Evidence != original.Evidence {
		t.Errorf("Evidence: got %q, want %q", got.Evidence, original.Evidence)
	}
}

func TestSecurityFinding_OmitemptyFields(t *testing.T) {
	finding := SecurityFinding{
		ID:          "ssh-weak-algo",
		Severity:    SeverityMedium,
		Description: "Weak MAC algorithm negotiated",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	output := string(data)
	for _, key := range []string{"evidence", "title", "impact", "recommendation"} {
		if strings.Contains(output, `"`+key+`"`) {
			t.Errorf("expected no %q key in JSON when field is empty, got: %s", key, output)
		}
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

func TestEnrich_KnownFinding(t *testing.T) {
	f := SecurityFinding{
		ID:          "http-missing-hsts",
		Severity:    SeverityMedium, // wrong severity, should be corrected
		Description: "HTTP response missing Strict-Transport-Security header",
	}
	f.Enrich()

	if f.Title != "Missing HTTP Strict Transport Security" {
		t.Errorf("Title: got %q, want %q", f.Title, "Missing HTTP Strict Transport Security")
	}
	if f.Severity != SeverityLow {
		t.Errorf("Severity: got %q, want %q", f.Severity, SeverityLow)
	}
	if f.Impact == "" {
		t.Error("Impact should be populated after Enrich()")
	}
	if f.Recommendation == "" {
		t.Error("Recommendation should be populated after Enrich()")
	}
	// Description should remain unchanged.
	if f.Description != "HTTP response missing Strict-Transport-Security header" {
		t.Errorf("Description should not be modified by Enrich()")
	}
}

func TestEnrich_PresetFieldsNotOverwritten(t *testing.T) {
	f := SecurityFinding{
		ID:             "http-missing-hsts",
		Severity:       SeverityHigh,
		Title:          "Custom Title",
		Impact:         "Custom Impact",
		Recommendation: "Custom Recommendation",
	}
	f.Enrich()

	if f.Title != "Custom Title" {
		t.Errorf("Title should not be overwritten when already set, got %q", f.Title)
	}
	if f.Impact != "Custom Impact" {
		t.Errorf("Impact should not be overwritten when already set, got %q", f.Impact)
	}
	if f.Recommendation != "Custom Recommendation" {
		t.Errorf("Recommendation should not be overwritten when already set, got %q", f.Recommendation)
	}
	// Severity IS always overwritten by catalog.
	if f.Severity != SeverityLow {
		t.Errorf("Severity should be overwritten to catalog value, got %q", f.Severity)
	}
}

func TestEnrich_UnknownFinding(t *testing.T) {
	f := SecurityFinding{
		ID:          "unknown-finding-id",
		Severity:    SeverityHigh,
		Description: "Some unknown finding",
	}
	f.Enrich()

	if f.Title != "" {
		t.Errorf("Title should remain empty for unknown finding, got %q", f.Title)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity should remain unchanged for unknown finding, got %q", f.Severity)
	}
}

func TestEnrichFindings_Service(t *testing.T) {
	svc := Service{
		IP:        "10.0.0.1",
		Port:      443,
		Protocol:  "https",
		TLS:       true,
		Transport: "tcp",
		Raw:       json.RawMessage(`{}`),
		SecurityFindings: []SecurityFinding{
			{
				ID:          "tls-certificate-expired",
				Severity:    SeverityMedium,
				Description: "TLS certificate has expired",
			},
			{
				ID:          "http-missing-hsts",
				Severity:    SeverityMedium,
				Description: "Missing HSTS header",
			},
		},
	}

	svc.EnrichFindings()

	if svc.SecurityFindings[0].Severity != SeverityLow {
		t.Errorf("tls-certificate-expired severity: got %q, want %q", svc.SecurityFindings[0].Severity, SeverityLow)
	}
	if svc.SecurityFindings[0].Title != "Expired TLS Certificate" {
		t.Errorf("tls-certificate-expired title: got %q, want %q", svc.SecurityFindings[0].Title, "Expired TLS Certificate")
	}
	if svc.SecurityFindings[1].Severity != SeverityLow {
		t.Errorf("http-missing-hsts severity: got %q, want %q", svc.SecurityFindings[1].Severity, SeverityLow)
	}
}

func TestFindingCatalog_AllSeveritiesValid(t *testing.T) {
	for id, meta := range findingCatalog {
		if !meta.Severity.Valid() {
			t.Errorf("finding catalog entry %q has invalid severity %q", id, meta.Severity)
		}
		if meta.Title == "" {
			t.Errorf("finding catalog entry %q has empty Title", id)
		}
		if meta.Impact == "" {
			t.Errorf("finding catalog entry %q has empty Impact", id)
		}
		if meta.Recommendation == "" {
			t.Errorf("finding catalog entry %q has empty Recommendation", id)
		}
	}
}
