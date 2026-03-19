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
	"testing"
)

func TestWordPressFingerprinter_Name(t *testing.T) {
	fp := &WordPressFingerprinter{}
	if got := fp.Name(); got != "wordpress" {
		t.Errorf("Name() = %q, want %q", got, "wordpress")
	}
}

func TestWordPressFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &WordPressFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/wp-json/wp/v2/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/wp-json/wp/v2/")
	}
}

func TestWordPressFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		linkHeader string
		want       bool
	}{
		{
			name:       "Link header with api.w.org - definitive WordPress signal",
			statusCode: 200,
			linkHeader: `<https://example.com/wp-json/>; rel="https://api.w.org/"`,
			want:       true,
		},
		{
			name:       "No Link header, 200 status - accept for body-based detection",
			statusCode: 200,
			linkHeader: "",
			want:       true,
		},
		{
			name:       "No Link header, 404 status - accept for body-based detection",
			statusCode: 404,
			linkHeader: "",
			want:       true,
		},
		{
			name:       "500 internal server error - reject",
			statusCode: 500,
			linkHeader: "",
			want:       false,
		},
		{
			name:       "503 service unavailable - reject",
			statusCode: 503,
			linkHeader: "",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WordPressFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.linkHeader != "" {
				resp.Header.Set("Link", tt.linkHeader)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWordPressFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		linkHeader  string
		wantVersion string
		wantPlugins []string
		wantThemes  []string
		wantSite    string
	}{
		{
			name: "Meta generator tag with version",
			body: `<html>
<head>
<meta name="generator" content="WordPress 6.4.2" />
<link rel="stylesheet" href="/wp-includes/css/dashicons.min.css">
</head>
<body></body>
</html>`,
			wantVersion: "6.4.2",
		},
		{
			name: "Body with wp-content/plugins/ paths - plugin detection",
			body: `<html>
<head></head>
<body>
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css">
<script src="/wp-content/plugins/woocommerce/assets/js/frontend/cart.js"></script>
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>
</body>
</html>`,
			wantPlugins: []string{"contact-form-7", "woocommerce"},
		},
		{
			name: "Body with wp-content/themes/ paths - theme detection",
			body: `<html>
<head>
<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
<script src="/wp-content/themes/twentytwentyfour/assets/js/main.js"></script>
</head>
<body></body>
</html>`,
			wantThemes: []string{"twentytwentyfour"},
		},
		{
			name: "JSON probe response with wp/v2 namespace - REST API confirmation",
			body: `{
				"name": "My WordPress Site",
				"description": "Just another WordPress site",
				"namespaces": ["wp/v2", "oembed/1.0"]
			}`,
			wantSite: "My WordPress Site",
		},
		{
			name: "Combined: meta generator, plugins, and themes in same body",
			body: `<html>
<head>
<meta name="generator" content="WordPress 6.3.1" />
<link rel="stylesheet" href="/wp-content/themes/astra/style.css">
<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">
<script src="/wp-content/plugins/wpforms-lite/assets/js/frontend/wpforms.js"></script>
</head>
<body></body>
</html>`,
			wantVersion: "6.3.1",
			wantPlugins: []string{"elementor", "wpforms-lite"},
			wantThemes:  []string{"astra"},
		},
		{
			name: "Link header api.w.org with no body WordPress markers",
			body:       `<html><head><title>My Site</title></head><body></body></html>`,
			linkHeader: `<https://example.com/wp-json/>; rel="https://api.w.org/"`,
		},
		{
			name: "CPE injection blocked by version regex - four-component version rejected",
			body: `<html>
<link href="/wp-includes/css/dashicons.min.css">
<meta name="generator" content="WordPress 6.0.1.2" />
</html>`,
			wantVersion: "", // 6.0.1.2 has four components, rejected by ^\d+\.\d+(\.\d+)?$
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WordPressFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.linkHeader != "" {
				resp.Header.Set("Link", tt.linkHeader)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "wordpress" {
				t.Errorf("Technology = %q, want %q", result.Technology, "wordpress")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check CPE is present
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := buildWordPressCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			// Check plugins
			if len(tt.wantPlugins) > 0 {
				gotPlugins, ok := result.Metadata["plugins"].([]string)
				if !ok {
					t.Errorf("Metadata[plugins] missing or wrong type, got %T", result.Metadata["plugins"])
				} else if !stringSlicesEqual(gotPlugins, tt.wantPlugins) {
					t.Errorf("Metadata[plugins] = %v, want %v", gotPlugins, tt.wantPlugins)
				}
			}

			// Check themes
			if len(tt.wantThemes) > 0 {
				gotThemes, ok := result.Metadata["themes"].([]string)
				if !ok {
					t.Errorf("Metadata[themes] missing or wrong type, got %T", result.Metadata["themes"])
				} else if !stringSlicesEqual(gotThemes, tt.wantThemes) {
					t.Errorf("Metadata[themes] = %v, want %v", gotThemes, tt.wantThemes)
				}
			}

			// Check site name
			if tt.wantSite != "" {
				gotSite, ok := result.Metadata["siteName"].(string)
				if !ok || gotSite != tt.wantSite {
					t.Errorf("Metadata[siteName] = %v, want %q", result.Metadata["siteName"], tt.wantSite)
				}
			}
		})
	}
}

func TestWordPressFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Random HTML without WordPress markers",
			body: "<html><head><title>Apache Tomcat</title></head><body>Hello World</body></html>",
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "Body with 'wp' but not in expected paths",
			body: "<html><head><title>swap market</title></head><body>swap is a popular operation</body></html>",
		},
		{
			name: "JSON without wp/v2 namespace",
			body: `{"name": "Some API", "namespaces": ["custom/v1", "oembed/1.0"]}`,
		},
		{
			name: "Body with wp markers but no WordPress-specific paths",
			body: `<meta name="generator" content="WordPress 6.0:*:*:*" />`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WordPressFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildWordPressCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With full version",
			version: "6.4.2",
			want:    "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*",
		},
		{
			name:    "With major.minor version",
			version: "6.4",
			want:    "cpe:2.3:a:wordpress:wordpress:6.4:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildWordPressCPE(tt.version); got != tt.want {
				t.Errorf("buildWordPressCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWordPressFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &WordPressFingerprinter{}
	Register(fp)

	// Create a valid WordPress REST API response
	body := []byte(`{
		"name": "Test WordPress Site",
		"description": "Just another WordPress site",
		"namespaces": ["wp/v2", "oembed/1.0"]
	}`)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	results := RunFingerprinters(resp, body)

	// Should find at least the WordPress fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "wordpress" {
			found = true
			// Verify site name was extracted
			if siteName, ok := result.Metadata["siteName"].(string); !ok || siteName != "Test WordPress Site" {
				t.Errorf("siteName = %v, want %q", result.Metadata["siteName"], "Test WordPress Site")
			}
		}
	}

	if !found {
		t.Error("WordPressFingerprinter not found in results")
	}
}

// stringSlicesEqual returns true if two string slices contain the same elements
// in the same order.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
