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
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realisticIvantiLoginPage is a representative Ivanti Connect Secure login page
// body used across multiple test cases.
const realisticIvantiLoginPage = `<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="robots" content="none">
<title>Ivanti Connect Secure</title>
<link rel="stylesheet" type="text/css" href="/dana-na/css/ds.css">
</head>
<body id="body" onload="FinishLoad()">
<form name="frmLogin" action="login.cgi" method="post" autocomplete="off">
<input type="text" name="username" size="20">
<input type="password" name="password" size="20">
<select size="1" name="realm">
<option value="Users">Users</option>
<option value="Admins">Admins</option>
</select>
<input type="submit" name="btnSubmit" value="Sign In">
</form>
<img src="/dana-na/imgs/loginfo.gif">
</body>
</html>`

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Name(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}
	assert.Equal(t, "ivanti-connect-secure", fp.Name())
}

func TestIvantiConnectSecureFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}
	assert.Equal(t, "/dana-na/auth/url_default/welcome.cgi", fp.ProbeEndpoint())
}

func TestIvantiConnectSecureFingerprinter_ProbeAccept(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		cookies     []string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 application/json without DS cookies → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 with DSID + DSSignInURL cookies → true",
			statusCode:  200,
			contentType: "application/json",
			cookies:     []string{"DSID=abc123; Path=/", "DSSignInURL=https://vpn.example.com/; Path=/"},
			want:        true,
		},
		{
			name:        "200 with single DS cookie → true (match is a pre-filter)",
			statusCode:  200,
			contentType: "application/json",
			cookies:     []string{"DSID=abc123; Path=/"},
			want:        true,
		},
		{
			name:        "500 → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "100 informational → false",
			statusCode:  100,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "302 text/html redirect → true",
			statusCode:  302,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &IvantiConnectSecureFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: Login page structure (Signal 1) ──────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_LoginPageStructure(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("body with /dana-na/css/ds.css reference → detected, detection_method=login_page", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		body := []byte(`<html><head><title>VPN Login</title>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ivanti-connect-secure", result.Technology)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})

	t.Run("body with /dana-na/css/ds_abc123.css hash variant → detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds_abc123.css">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})

	t.Run("body with frmLogin form → detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head><title>VPN</title></head>
<body>
<form name="frmLogin" action="login.cgi">
<input type="text" name="username">
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})

	t.Run("body with both CSS and form → detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi">
<input type="text" name="username">
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})

	t.Run("active probe path → detection_method=active_probe", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/dana-na/auth/url_default/welcome.cgi"},
			},
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi">
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	})
}

// ── Fingerprint: DS cookies (Signal 2) ───────────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_DSCookies(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("2 DS cookies (DSID + DSSignInURL) → detected, detection_method=response_cookie", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/; HttpOnly; Secure")
		resp.Header.Add("Set-Cookie", "DSSignInURL=https://vpn.example.com/; Path=/")
		body := []byte(`<html><head><title>Generic Portal</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ivanti-connect-secure", result.Technology)
		assert.Equal(t, "response_cookie", result.Metadata["detection_method"])
		dsCookies, ok := result.Metadata["ds_cookies"]
		require.True(t, ok, "ds_cookies metadata key must be present")
		assert.NotEmpty(t, dsCookies)
	})

	t.Run("3 DS cookies → detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/")
		resp.Header.Add("Set-Cookie", "DSSignInURL=https://vpn.example.com/; Path=/")
		resp.Header.Add("Set-Cookie", "DSBrowserID=xyz789; Path=/")
		body := []byte(`<html><head><title>Some Page</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "response_cookie", result.Metadata["detection_method"])
		dsCookies, ok := result.Metadata["ds_cookies"].([]string)
		require.True(t, ok)
		assert.Len(t, dsCookies, 3)
	})

	t.Run("only 1 DS cookie (DSID alone) → nil (insufficient)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/")
		body := []byte(`<html><head><title>Some Page</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result, "single DS cookie alone must not trigger detection")
	})

	t.Run("DS cookies + login page structure → detection_method=login_page (login page takes priority)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/")
		resp.Header.Add("Set-Cookie", "DSSignInURL=https://vpn.example.com/; Path=/")
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi"></form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})
}

// ── Fingerprint: Corroborated branding (Signal 3) ────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_TitleBranding(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("title 'Ivanti Connect Secure' + body has /dana-na/ reference → detected, detection_method=title_branding", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Ivanti Connect Secure</title>
</head><body>
<a href="/dana-na/static/resource.js">Resource</a>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "ivanti-connect-secure", result.Technology)
		assert.Equal(t, "title_branding", result.Metadata["detection_method"])
	})

	t.Run("title 'Pulse Secure SSL VPN' + body has /dana/ reference → detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Pulse Secure SSL VPN</title>
</head><body>
<img src="/dana/imgs/logo.gif">
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "title_branding", result.Metadata["detection_method"])
	})

	t.Run("title 'Ivanti Connect Secure' but NO /dana-na/ in body → nil (brand alone insufficient)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Ivanti Connect Secure</title>
</head><body>
<p>Welcome to the portal. Please log in.</p>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result, "title alone without /dana-na/ path must not trigger detection")
	})

	t.Run("title 'My Router' + body has /dana-na/ path → nil (path alone without structural markers insufficient)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>My Router</title>
</head><body>
<p>Visit /dana-na/ for more info.</p>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result, "/dana-na/ path without matching title must not trigger title_branding")
	})
}

// ── Fingerprint: Realm extraction ─────────────────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_RealmExtraction(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("login form with realm selector → metadata realms extracted", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi">
<select name="realm">
<option value="Users">Users</option>
<option value="Admins">Admins</option>
</select>
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		realms, ok := result.Metadata["realms"].([]string)
		require.True(t, ok, "realms metadata must be a []string")
		assert.ElementsMatch(t, []string{"Users", "Admins"}, realms)
	})

	t.Run("login form without realm selector → no realms key in metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi">
<input type="text" name="username">
<input type="password" name="password">
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		_, hasRealms := result.Metadata["realms"]
		assert.False(t, hasRealms, "realms key must not be set when no realm selector is present")
	})

	t.Run("hidden input with realm value — no option tags → no realms extracted", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		// name="realm" is present but as hidden input with no <option> tags
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<form name="frmLogin" action="login.cgi">
<input type="hidden" name="realm" value="Default">
<input type="text" name="username">
</form>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		// name="realm" is present but no <option> elements, so realms should be absent
		realms, hasRealms := result.Metadata["realms"]
		if hasRealms {
			// If present, must be empty (hidden input won't match option regex)
			assert.Empty(t, realms, "hidden input realm value must not produce realm entries")
		}
	})
}

// ── Fingerprint: Legacy branding detection ────────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_LegacyBranding(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("body containing 'Pulse Secure' → metadata legacy_branding=Pulse Secure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
<title>Pulse Secure SSL VPN</title>
</head><body>
<p>Pulse Secure VPN</p>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Pulse Secure", result.Metadata["legacy_branding"])
	})

	t.Run("body containing 'Pulse Connect Secure' → metadata legacy_branding=Pulse Secure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body>
<p>Welcome to Pulse Connect Secure</p>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Pulse Secure", result.Metadata["legacy_branding"])
	})

	t.Run("body with only 'Ivanti' → no legacy_branding key", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
<title>Ivanti Connect Secure</title>
</head><body>
<p>Ivanti VPN Portal</p>
</body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		_, hasLegacy := result.Metadata["legacy_branding"]
		assert.False(t, hasLegacy, "modern Ivanti branding must not set legacy_branding key")
	})
}

// ── Fingerprint: Product variant extraction ─────────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_ProductVariant(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("title 'Ivanti Connect Secure' → product_variant=Connect Secure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Ivanti Connect Secure</title>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})

	t.Run("title 'Ivanti Policy Secure' → product_variant=Connect Secure (always Connect Secure)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Ivanti Policy Secure</title>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})

	t.Run("title 'Pulse Secure SSL VPN' → product_variant=Connect Secure (legacy)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Pulse Secure SSL VPN</title>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body><p>Pulse Secure</p></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})

	t.Run("no variant in title → defaults to Connect Secure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head><title>VPN Login</title>
<link rel="stylesheet" href="/dana-na/css/ds.css">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})

	t.Run("DS cookies only (no title) → defaults to Connect Secure", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/")
		resp.Header.Add("Set-Cookie", "DSSignInURL=https://vpn.example.com/; Path=/")
		body := []byte(`<html><head><title>Portal</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})
}

// ── Fingerprint: Negative cases (must return nil) ─────────────────────────────

func TestIvantiConnectSecureFingerprinter_Fingerprint_NegativeCases(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       string
		cookies    []string
	}{
		{
			name:       "generic HTML page — no Ivanti signals",
			statusCode: 200,
			body:       `<html><head><title>My Company Portal</title></head><body><p>Welcome</p></body></html>`,
		},
		{
			name:       "JSON response — no signals",
			statusCode: 200,
			body:       `{"status":"ok","version":"1.0.0"}`,
		},
		{
			name:       "prose mention of 'Ivanti' in paragraph but not in title and no /dana-na/ paths",
			statusCode: 200,
			body:       `<html><head><title>Security Blog</title></head><body><p>We reviewed an Ivanti Connect Secure appliance.</p></body></html>`,
		},
		{
			name:       "status 500 with valid login page structure",
			statusCode: 500,
			body: `<html><head>
<link rel="stylesheet" href="/dana-na/css/ds.css">
<title>Ivanti Connect Secure</title>
</head><body>
<form name="frmLogin" action="login.cgi"></form>
</body></html>`,
		},
		{
			name:       "body larger than 2 MiB → nil",
			statusCode: 200,
			body:       `/dana-na/css/ds.css` + strings.Repeat("x", 2*1024*1024+1),
		},
		{
			name:       "single DSID cookie with no other signals → nil",
			statusCode: 200,
			body:       `<html><head><title>Generic</title></head><body></body></html>`,
			cookies:    []string{"DSID=abc123; Path=/"},
		},
		{
			name:       "title has 'Pulse Secure' but body has no /dana/ paths — branding alone insufficient",
			statusCode: 200,
			body:       `<html><head><title>Pulse Secure SSL VPN</title></head><body><p>Please contact support.</p></body></html>`,
		},
		{
			name:       "empty body",
			statusCode: 200,
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "expected nil result for %q", tt.name)
		})
	}
}

// ── CPE building tests ────────────────────────────────────────────────────────

func TestBuildIvantiConnectSecureCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version → wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version 22.7R2.4 → versioned CPE",
			version: "22.7R2.4",
			want:    "cpe:2.3:a:ivanti:connect_secure:22.7R2.4:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildIvantiConnectSecureCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Integration: Match + Fingerprint round-trip ───────────────────────────────

func TestIvantiConnectSecureFingerprinter_Integration_LoginPage(t *testing.T) {
	fp := &IvantiConnectSecureFingerprinter{}

	t.Run("full realistic Ivanti Connect Secure login page", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/dana-na/auth/url_default/welcome.cgi"},
			},
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Add("Set-Cookie", "DSID=abc123; Path=/; HttpOnly; Secure")
		resp.Header.Add("Set-Cookie", "DSSignInURL=https://vpn.example.com/; Path=/")
		body := []byte(realisticIvantiLoginPage)

		require.True(t, fp.Match(resp), "Match() must return true for realistic login page")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "ivanti-connect-secure", result.Technology)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])

		realms, ok := result.Metadata["realms"].([]string)
		require.True(t, ok, "realms must be present and typed as []string")
		assert.ElementsMatch(t, []string{"Users", "Admins"}, realms)

		_, hasDSCookies := result.Metadata["ds_cookies"]
		assert.True(t, hasDSCookies, "ds_cookies metadata must be set when DS cookies are present")

		_, hasLegacy := result.Metadata["legacy_branding"]
		assert.False(t, hasLegacy, "legacy_branding must not be set for modern Ivanti branding")

		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])

		require.Len(t, result.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*", result.CPEs[0])
	})

	t.Run("full realistic Pulse Secure legacy login page", func(t *testing.T) {
		fp := &IvantiConnectSecureFingerprinter{}

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		body := []byte(`<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Pulse Secure SSL VPN</title>
<link rel="stylesheet" type="text/css" href="/dana-na/css/ds.css">
</head>
<body id="body" onload="FinishLoad()">
<form name="frmLogin" action="login.cgi" method="post" autocomplete="off">
<input type="text" name="username" size="20">
<input type="password" name="password" size="20">
<input type="submit" name="btnSubmit" value="Sign In">
</form>
<img src="/dana-na/imgs/loginfo.gif">
<p>Powered by Pulse Secure</p>
</body>
</html>`)

		require.True(t, fp.Match(resp), "Match() must return true for Pulse Secure login page")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "ivanti-connect-secure", result.Technology)
		assert.Equal(t, "Pulse Secure", result.Metadata["legacy_branding"])
		_, hasRealms := result.Metadata["realms"]
		assert.False(t, hasRealms, "no realm selector present in legacy page")
		assert.Equal(t, "Connect Secure", result.Metadata["product_variant"])
	})
}
