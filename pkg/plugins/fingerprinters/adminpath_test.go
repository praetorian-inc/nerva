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

package fingerprinters

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// noRedirectClient returns an *http.Client that does not follow redirects,
// matching the production behavior where callers handle 302 as a signal.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestAdminPathFingerprinter_Name(t *testing.T) {
	fp := &AdminPathFingerprinter{}
	if fp.Name() != "adminpath" {
		t.Errorf("Name() = %q, want %q", fp.Name(), "adminpath")
	}
}

func TestAdminPathFingerprinter_Match(t *testing.T) {
	fp := &AdminPathFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
	}{
		{"200 OK", 200, nil},
		{"302 Found", 302, nil},
		{"404 Not Found", 404, nil},
		{"403 Forbidden", 403, nil},
		{"500 Internal Server Error", 500, nil},
		{"200 with JSON body", 200, map[string]string{"Content-Type": "application/json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			if got := fp.Match(resp); got != false {
				t.Errorf("Match() = %v, want false — adminpath is deep-only and must never match on root response", got)
			}
		})
	}
}

func TestAdminPathFingerprinter_Fingerprint(t *testing.T) {
	fp := &AdminPathFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	result, err := fp.Fingerprint(resp, []byte("anything"))
	if err != nil {
		t.Errorf("Fingerprint() returned unexpected error: %v", err)
	}
	if result != nil {
		t.Errorf("Fingerprint() = %+v, want nil — adminpath never fingerprints on root response", result)
	}
}

func TestAdminPathFingerprinter_DeepProbe_200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	var wpAdminFinding *plugins.SecurityFinding
	for i := range findings {
		if findings[i].ID == "http-admin-path-wp-admin" {
			wpAdminFinding = &findings[i]
			break
		}
	}

	if wpAdminFinding == nil {
		t.Fatalf("DeepProbe() returned no finding with ID %q; findings: %+v", "http-admin-path-wp-admin", findings)
	}
	if wpAdminFinding.Severity != plugins.SeverityInfo {
		t.Errorf("finding Severity = %q, want %q", wpAdminFinding.Severity, plugins.SeverityInfo)
	}
	if !strings.Contains(wpAdminFinding.Evidence, "path: /wp-admin/") {
		t.Errorf("Evidence %q does not contain %q", wpAdminFinding.Evidence, "path: /wp-admin/")
	}
	if !strings.Contains(wpAdminFinding.Evidence, "status: 200") {
		t.Errorf("Evidence %q does not contain %q", wpAdminFinding.Evidence, "status: 200")
	}
}

func TestAdminPathFingerprinter_DeepProbe_302Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	var wpLoginFinding *plugins.SecurityFinding
	for i := range findings {
		if strings.Contains(findings[i].Evidence, "/wp-login.php") {
			wpLoginFinding = &findings[i]
			break
		}
	}

	if wpLoginFinding == nil {
		t.Fatalf("DeepProbe() returned no finding for /wp-login.php; findings: %+v", findings)
	}
	if !strings.Contains(wpLoginFinding.Evidence, "302 Found") {
		t.Errorf("Evidence %q does not contain %q", wpLoginFinding.Evidence, "302 Found")
	}
	if !strings.Contains(wpLoginFinding.Evidence, "location: /login") {
		t.Errorf("Evidence %q does not contain %q", wpLoginFinding.Evidence, "location: /login")
	}
}

func TestAdminPathFingerprinter_DeepProbe_404ReturnsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 0 {
		t.Errorf("DeepProbe() returned %d finding(s) for all-404 server, want 0; findings: %+v", len(findings), findings)
	}
}

func TestAdminPathFingerprinter_DeepProbe_403ReturnsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 0 {
		t.Errorf("DeepProbe() returned %d finding(s) for all-403 server, want 0; findings: %+v", len(findings), findings)
	}
}

func TestAdminPathFingerprinter_DeepProbe_MultiplePaths(t *testing.T) {
	// Map from path to slug — must stay consistent with adminPaths variable.
	respondWith200 := map[string]string{
		"/wp-admin/":   "wp-admin",
		"/phpmyadmin/": "phpmyadmin",
		"/admin/":      "admin",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := respondWith200[r.URL.Path]; ok {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 3 {
		t.Fatalf("DeepProbe() returned %d finding(s), want 3; findings: %+v", len(findings), findings)
	}

	// Build ID set for membership check.
	foundIDs := make(map[string]bool, len(findings))
	for _, f := range findings {
		foundIDs[f.ID] = true
	}
	for path, slug := range respondWith200 {
		wantID := "http-admin-path-" + slug
		if !foundIDs[wantID] {
			t.Errorf("no finding with ID %q for path %q; got IDs: %v", wantID, path, foundIDs)
		}
	}
}

func TestAdminPathFingerprinter_DeepProbe_HostHeader(t *testing.T) {
	var receivedHost string

	// The server requires the correct Host header AND a known admin path.
	// Returning 200 for all paths under a given host would trigger the canary
	// false-positive guard, so the canary path must 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		if r.Host == "example.com" && r.URL.Path == "/wp-admin/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "example.com")

	if receivedHost != "example.com" {
		t.Errorf("server received Host header %q, want %q", receivedHost, "example.com")
	}
	if len(findings) == 0 {
		t.Error("DeepProbe() returned no findings when Host matched; expected at least one finding")
	}
}

func TestAdminPathFingerprinter_DeepProbe_500ReturnsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 0 {
		t.Errorf("DeepProbe() returned %d finding(s) for all-500 server, want 0; findings: %+v", len(findings), findings)
	}
}

func TestAdminPathFingerprinter_DeepProbe_WildcardServerReturnsNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 0 {
		t.Errorf("DeepProbe() returned %d finding(s) for wildcard server, want 0; findings: %+v", len(findings), findings)
	}
}

func TestAdminPathFingerprinter_DeepProbe_WordPressIDCollision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/" || r.URL.Path == "/wp-login.php" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fp := &AdminPathFingerprinter{}
	findings := fp.DeepProbe(noRedirectClient(), srv.URL, "")

	if len(findings) != 2 {
		t.Fatalf("DeepProbe() returned %d finding(s), want 2; findings: %+v", len(findings), findings)
	}

	ids := make(map[string]bool, len(findings))
	for _, f := range findings {
		ids[f.ID] = true
	}
	if len(ids) != 2 {
		t.Errorf("expected 2 distinct IDs, got %d: %v", len(ids), ids)
	}
	if !ids["http-admin-path-wp-admin"] {
		t.Errorf("missing expected ID %q; got %v", "http-admin-path-wp-admin", ids)
	}
	if !ids["http-admin-path-wp-login"] {
		t.Errorf("missing expected ID %q; got %v", "http-admin-path-wp-login", ids)
	}
}

func TestRunDeepProbes_AggregatesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-admin/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	findings := RunDeepProbes(noRedirectClient(), srv.URL, "")

	found := false
	for _, f := range findings {
		if f.ID == "http-admin-path-wp-admin" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("RunDeepProbes() did not return wp-admin finding; got %+v", findings)
	}
}
