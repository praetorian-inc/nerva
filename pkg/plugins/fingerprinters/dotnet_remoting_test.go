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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ── Fixtures ─────────────────────────────────────────────────────────────────────

// Body from a live .NET Remoting HTTP channel capture. Detection is
// header-only, so the body must never influence the result.
const dotNetRemotingSampleBody = "Server encountered an internal error. To get more info turn on customErrors in the server's config file."

func newDotNetRemotingResp(status int, serverHeader string) *http.Response {
	h := http.Header{}
	if serverHeader != "" {
		h.Set("Server", serverHeader)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     h,
	}
}

// ── Identity / wiring ─────────────────────────────────────────────────────────────

func TestDotNetRemotingFingerprinter_Identity(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	assert.Equal(t, "dotnet-remoting-http", fp.Name())
}

// DotNetRemotingFingerprinter must not implement ActiveHTTPFingerprinter:
// the passive pass skips fingerprinters with a non-root ProbeEndpoint, and
// the channel identifies itself on the root response.
func TestDotNetRemotingFingerprinter_MustStayPassive(t *testing.T) {
	_, isActive := any(&DotNetRemotingFingerprinter{}).(ActiveHTTPFingerprinter)
	assert.False(t, isActive,
		"adding a ProbeEndpoint would make the passive pass skip this fingerprinter and the root response go unevaluated")
}

func TestDotNetRemotingFingerprinter_NotInProbeEndpoints(t *testing.T) {
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	Register(&DotNetRemotingFingerprinter{})

	_, ok := GetProbeEndpoints()["dotnet-remoting-http"]
	assert.False(t, ok, "passive by design; declares no probe endpoint")
}

// ── Match ─────────────────────────────────────────────────────────────────────────

func TestDotNetRemotingFingerprinter_Match(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	tests := []struct {
		name         string
		serverHeader string
		want         bool
	}{
		{"standard banner", "MS .NET Remoting, MS .NET CLR 4.0.30319.42000", true},
		{"banner without CLR", "MS .NET Remoting", true},
		{"lowercase banner", "ms .net remoting, ms .net clr 4.0.30319.42000", true},
		{"no Server header", "", false},
		{"IIS banner", "Microsoft-IIS/10.0", false},
		{"Apache banner", "Apache/2.4.52 (Ubuntu)", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(newDotNetRemotingResp(500, tt.serverHeader)))
		})
	}
}

// ── Fingerprint: positive detection ─────────────────────────────────────────────

func TestDotNetRemotingFingerprinter_Fingerprint_LiveCapture(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	resp := newDotNetRemotingResp(500, "MS .NET Remoting, MS .NET CLR 4.0.30319.42000")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(dotNetRemotingSampleBody))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "dotnet-remoting-http", result.Technology)
	// CLR 4.0.30319.42000 covers .NET 4.6-4.8.1: not exact, so no version.
	assert.Empty(t, result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*")
	assert.Equal(t, "server_header", result.Metadata["detection_method"])
	assert.Equal(t, "4.0.30319.42000", result.Metadata["clr_version"])
	assert.Equal(t, "4.6-4.8.1", result.Metadata["framework_version"])
}

func TestDotNetRemotingFingerprinter_Fingerprint_ExactFrameworkVersion(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	resp := newDotNetRemotingResp(404, "MS .NET Remoting, MS .NET CLR 4.0.30319.18000")

	result, err := fp.Fingerprint(resp, []byte("404 Not Found"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "server_header", result.Metadata["detection_method"])
	// CLR 4.0.30319.18000 maps exactly to .NET Framework 4.5.
	assert.Equal(t, "4.5", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:microsoft:.net_framework:4.5:*:*:*:*:*:*:*")
}

// Older CLR (2.0.50727) — the .NET 2.0-3.5 era channel.
func TestDotNetRemotingFingerprinter_Fingerprint_LegacyCLR(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	resp := newDotNetRemotingResp(500, "MS .NET Remoting, MS .NET CLR 2.0.50727.8763")

	result, err := fp.Fingerprint(resp, []byte(dotNetRemotingSampleBody))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "2.0.50727.8763", result.Metadata["clr_version"])
	assert.Equal(t, "2.0-3.5", result.Metadata["framework_version"])
	assert.Empty(t, result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*")
}

// Banner present but no CLR component.
func TestDotNetRemotingFingerprinter_Fingerprint_NoCLRComponent(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}
	resp := newDotNetRemotingResp(500, "MS .NET Remoting")

	result, err := fp.Fingerprint(resp, []byte(dotNetRemotingSampleBody))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotContains(t, result.Metadata, "clr_version")
	assert.NotContains(t, result.Metadata, "framework_version")
	assert.Empty(t, result.Version)
}

// ── Fingerprint: negative / false-positive prevention ─────────────────────────────

// Regression guard for the deliberate single-signal design: the body is
// never inspected, so body content alone must never trigger detection —
// not even the exact framework error message. If this test starts failing,
// someone reintroduced body-based matching and the false-positive trade-off
// needs to be re-evaluated.
func TestDotNetRemotingFingerprinter_Fingerprint_BodyAloneRejected(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}

	cases := []struct {
		name         string
		status       int
		serverHeader string
		body         string
	}{
		{"remoting error message without banner", 500, "Microsoft-IIS/8.5", dotNetRemotingSampleBody},
		{"error message quoted on a 200 page", 200, "nginx/1.24.0", `<p>"Server encountered an internal error. To get more info turn on customErrors in the server's config file."</p>`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			result, err := fp.Fingerprint(newDotNetRemotingResp(tt.status, tt.serverHeader), []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Severity / SecurityFindings contract ─────────────────────────────────────────

// Every positive detection attaches exactly one High finding; the result's
// own Severity field stays empty (customFindings carry the severity).
func TestDotNetRemotingFingerprinter_Finding(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}

	for _, header := range []string{
		"MS .NET Remoting, MS .NET CLR 4.0.30319.42000",
		"MS .NET Remoting",
		"MS .NET Remoting, MS .NET CLR 2.0.50727.8763",
	} {
		result, err := fp.Fingerprint(newDotNetRemotingResp(500, header), nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Empty(t, result.Severity)
		require.Len(t, result.SecurityFindings, 1)

		f := result.SecurityFindings[0]
		assert.Equal(t, "dotnet-remoting-http-exposed", f.ID)
		assert.Equal(t, plugins.SeverityHigh, f.Severity)
		assert.NotEmpty(t, f.Description)
		assert.Contains(t, f.Evidence, "MS .NET Remoting")
	}
}

// The catalog is the authoritative severity source. If this fails, the
// catalog entry was removed or its severity changed away from High.
func TestDotNetRemotingFinding_CatalogEnrichment(t *testing.T) {
	f := plugins.SecurityFinding{
		ID:          "dotnet-remoting-http-exposed",
		Severity:    plugins.SeverityHigh,
		Description: ".NET Remoting HTTP channel exposed",
	}
	f.Enrich()

	assert.Equal(t, plugins.SeverityHigh, f.Severity)
	assert.NotEmpty(t, f.Title)
	assert.NotEmpty(t, f.Impact)
	assert.NotEmpty(t, f.Recommendation)
	assert.NotEmpty(t, f.CVSS)
}

// ── CLR → Framework mapping ──────────────────────────────────────────────────────

func TestDotNetCLRToFramework(t *testing.T) {
	tests := []struct {
		clr    string
		wantFW string
		wantEx bool
	}{
		{"", "", false},
		{"4.0.30319.42000", "4.6-4.8.1", false},
		{"4.0.30319.18000", "4.5", true},
		{"4.0.30319.18400", "4.5.1", true},
		{"4.0.30319.19000", "4.5.2", true},
		{"4.0.30319.1", "4.x", false},
		{"4.0.30319.1022", "4.x", false},
		{"2.0.50727.8763", "2.0-3.5", false},
		{"2.0.50727.5426", "2.0-3.5", false},
		{"3.0.99999.0", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.clr, func(t *testing.T) {
			fw, exact := dotNetCLRToFramework(tt.clr)
			assert.Equal(t, tt.wantFW, fw)
			assert.Equal(t, tt.wantEx, exact)
		})
	}
}

// ── CPE builder ───────────────────────────────────────────────────────────────────

func TestBuildDotNetFrameworkCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:microsoft:.net_framework:4.5.2:*:*:*:*:*:*:*", buildDotNetFrameworkCPE("4.5.2"))
	assert.Equal(t, "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*", buildDotNetFrameworkCPE(""))
	// Defense-in-depth against future loosening of the CLR regex.
	assert.Equal(t, "cpe:2.3:a:microsoft:.net_framework:*:*:*:*:*:*:*:*", buildDotNetFrameworkCPE("4.5:*:*:*"))
}

// The CLR extraction regex must never yield CPE metacharacters, no matter
// what the Server header contains.
func TestDotNetRemotingFingerprinter_CLRInjectionGuard(t *testing.T) {
	fp := &DotNetRemotingFingerprinter{}

	malicious := []string{
		"MS .NET Remoting, MS .NET CLR 4.0.30319.42000:*:*:*:*:*:*:*",
		"MS .NET Remoting, MS .NET CLR ?*:*:*:*:*",
	}
	for _, header := range malicious {
		result, err := fp.Fingerprint(newDotNetRemotingResp(500, header), nil)
		require.NoError(t, err)
		require.NotNil(t, result)

		if clr, ok := result.Metadata["clr_version"].(string); ok {
			assert.NotContains(t, clr, ":")
			assert.NotContains(t, clr, "*")
			assert.NotContains(t, clr, "?")
		}
	}
}

// ── Integration: passive engine path ─────────────────────────────────────────────

// Because no ProbeEndpoint is declared, the engine's passive pass must
// include this fingerprinter and detect the channel from the root response.
func TestDotNetRemotingFingerprinter_RunFingerprinters(t *testing.T) {
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	Register(&DotNetRemotingFingerprinter{})

	resp := newDotNetRemotingResp(500, "MS .NET Remoting, MS .NET CLR 4.0.30319.42000")
	results := RunFingerprinters(resp, []byte(dotNetRemotingSampleBody))
	require.Len(t, results, 1)
	assert.Equal(t, "dotnet-remoting-http", results[0].Technology)
	assert.Equal(t, "dotnet-remoting-http-exposed", results[0].SecurityFindings[0].ID)

	// A banner-less IIS 404 produces no results, regardless of body.
	results = RunFingerprinters(newDotNetRemotingResp(404, "Microsoft-IIS/10.0"), []byte("Not Found"))
	assert.Empty(t, results)
}

func TestDotNetRemotingFingerprinter_Registered(t *testing.T) {
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	Register(&DotNetRemotingFingerprinter{})

	assert.NotNil(t, GetFingerprinterByName("dotnet-remoting-http"))
}
