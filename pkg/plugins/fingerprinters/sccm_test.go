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
)

// --- Shared helpers -----------------------------------------------------------

func TestBuildSCCMCPEs(t *testing.T) {
	tests := []struct {
		name string
		rel  string
		site string
		want []string
	}{
		{
			name: "empty rel and site uses wildcard and omits site CPE",
			rel:  "",
			site: "",
			want: []string{
				"cpe:2.3:a:microsoft:system_center_configuration_manager:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:endpoint_configuration_manager:*:*:*:*:*:*:*:*",
			},
		},
		{
			name: "rel set but site empty omits site CPE",
			rel:  "2403",
			site: "",
			want: []string{
				"cpe:2.3:a:microsoft:system_center_configuration_manager:2403:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:endpoint_configuration_manager:2403:*:*:*:*:*:*:*",
			},
		},
		{
			name: "rel and site set appends site CPE",
			rel:  "2403",
			site: "5.00.9128",
			want: []string{
				"cpe:2.3:a:microsoft:system_center_configuration_manager:2403:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:endpoint_configuration_manager:2403:*:*:*:*:*:*:*",
				"cpe:2.3:a:microsoft:configuration_manager_2403:5.00.9128:*:*:*:*:*:*:*",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSCCMCPEs(tt.rel, tt.site)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSCCMReleaseFromBuild(t *testing.T) {
	tests := []struct {
		build string
		want  string
	}{
		{build: "7711", want: "2012"},
		{build: "9106", want: "2303"},
		{build: "9128", want: "2403"},
		{build: "9132", want: "2409"},
		{build: "0000", want: ""},
		{build: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.build, func(t *testing.T) {
			assert.Equal(t, tt.want, sccmReleaseFromBuild(tt.build))
		})
	}
}

func TestVersionFromBuild(t *testing.T) {
	tests := []struct {
		name        string
		build       string
		wantRel     string
		wantSiteVer string
	}{
		{
			name:        "empty build is unknown",
			build:       "",
			wantRel:     "unknown",
			wantSiteVer: "*",
		},
		{
			name:        "unrecognized build is unknown",
			build:       "0000",
			wantRel:     "unknown",
			wantSiteVer: "*",
		},
		{
			name:        "known build resolves release and site version",
			build:       "9128",
			wantRel:     "2403",
			wantSiteVer: "5.00.9128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, siteVer := versionFromBuild(tt.build)
			assert.Equal(t, tt.wantRel, rel)
			assert.Equal(t, tt.wantSiteVer, siteVer)
		})
	}
}

// --- Management Point ---------------------------------------------------------

func TestSCCMManagementPointFingerprinter_Name(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}
	assert.Equal(t, "sccm-mp", fp.Name())
}

func TestSCCMManagementPointFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}
	assert.Equal(t, "/sms_mp/.sms_aut?mplist", fp.ProbeEndpoint())
}

func TestSCCMManagementPointFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{name: "Microsoft-IIS returns true", server: "Microsoft-IIS/10.0", want: true},
		{name: "nginx returns false", server: "nginx", want: false},
		{name: "no Server header returns false", server: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMManagementPointFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestSCCMManagementPointFingerprinter_Fingerprint_MPList(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")
	body := []byte(`<MPList><MP Name="MP01" FQDN="mp01.contoso.com" SiteCode="ABC"><Version>9128</Version></MP></MPList>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "sccm-mp", result.Technology)
	assert.Equal(t, "5.00.9128", result.Version)

	assert.Equal(t, "Microsoft", result.Metadata["vendor"])
	assert.Equal(t, "management_point", result.Metadata["role"])
	assert.Equal(t, "9128", result.Metadata["build_number"])
	assert.Equal(t, "5.00.9128", result.Metadata["site_version"])
	assert.Equal(t, "2403", result.Metadata["release"])
	assert.Equal(t, "ABC", result.Metadata["site_code"])

	names, ok := result.Metadata["management_points"].([]string)
	require.True(t, ok, "management_points should be []string type")
	assert.Equal(t, []string{"mp01.contoso.com"}, names)

	assert.Contains(t, result.CPEs, "cpe:2.3:a:microsoft:configuration_manager_2403:5.00.9128:*:*:*:*:*:*:*")
}

func TestSCCMManagementPointFingerprinter_Fingerprint_VersionRegexFallback(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")
	// MPList present but Version is not inside an MP element, so struct parse
	// yields no MPs and the regex fallback recovers the build.
	body := []byte(`<MPList><Version>9106</Version></MPList>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "sccm-mp", result.Technology)
	assert.Equal(t, "9106", result.Metadata["build_number"])
	assert.Equal(t, "5.00.9106", result.Metadata["site_version"])
	assert.Equal(t, "2303", result.Metadata["release"])
	assert.NotContains(t, result.Metadata, "site_code")
	assert.NotContains(t, result.Metadata, "management_points")
}

func TestSCCMManagementPointFingerprinter_Fingerprint_NotMPList(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")
	body := []byte("<html>not an mplist</html>")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// --- Distribution Point -------------------------------------------------------

func TestSCCMDistributionPointFingerprinter_Name(t *testing.T) {
	fp := &SCCMDistributionPointFingerprinter{}
	assert.Equal(t, "sccm-dp", fp.Name())
}

func TestSCCMDistributionPointFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SCCMDistributionPointFingerprinter{}
	assert.Equal(t, "/SMS_DP_SMSPKG$/", fp.ProbeEndpoint())
}

func TestSCCMDistributionPointFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{name: "Microsoft-IIS returns true", server: "Microsoft-IIS/10.0", want: true},
		{name: "nginx returns false", server: "nginx", want: false},
		{name: "no Server header returns false", server: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMDistributionPointFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestSCCMDistributionPointFingerprinter_Fingerprint_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wwwAuth    string
	}{
		{name: "401 with NTLM", statusCode: 401, wwwAuth: "NTLM"},
		{name: "403 with Negotiate", statusCode: 403, wwwAuth: "Negotiate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMDistributionPointFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			resp.Header.Set("Server", "Microsoft-IIS/10.0")

			result, err := fp.Fingerprint(resp, nil)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "sccm-dp", result.Technology)
			assert.Equal(t, "distribution_point", result.Metadata["role"])
			require.NotEmpty(t, result.CPEs)
		})
	}
}

func TestSCCMDistributionPointFingerprinter_Fingerprint_NotDP(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wwwAuth    string
		server     string
	}{
		{name: "wrong status code", statusCode: 200, wwwAuth: "NTLM", server: "Microsoft-IIS/10.0"},
		{name: "unsupported auth scheme", statusCode: 401, wwwAuth: "Basic", server: "Microsoft-IIS/10.0"},
		{name: "non-IIS server", statusCode: 401, wwwAuth: "NTLM", server: "nginx"},
		{name: "missing WWW-Authenticate", statusCode: 401, wwwAuth: "", server: "Microsoft-IIS/10.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMDistributionPointFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.wwwAuth != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuth)
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// --- Site Server / SMS Provider (AdminService) --------------------------------

func TestSCCMAdminServiceFingerprinter_Name(t *testing.T) {
	fp := &SCCMAdminServiceFingerprinter{}
	assert.Equal(t, "sccm-adminservice", fp.Name())
}

func TestSCCMAdminServiceFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SCCMAdminServiceFingerprinter{}
	assert.Equal(t, "/AdminService/v1.0/$metadata", fp.ProbeEndpoint())
}

func TestSCCMAdminServiceFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{name: "Microsoft-IIS returns true", server: "Microsoft-IIS/10.0", want: true},
		{name: "nginx returns false", server: "nginx", want: false},
		{name: "no Server header returns false", server: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMAdminServiceFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestSCCMAdminServiceFingerprinter_Fingerprint_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{name: "401 unauthorized", statusCode: 401, body: nil},
		{name: "200 with Edmx body", statusCode: 200, body: []byte(`<edmx:Edmx Version="4.0">`)},
		{name: "200 with lowercase edmx body", statusCode: 200, body: []byte(`<root>edmx</root>`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMAdminServiceFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", "Microsoft-IIS/10.0")

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "sccm-adminservice", result.Technology)
			assert.Equal(t, "site_server", result.Metadata["role"])
			require.NotEmpty(t, result.CPEs)
		})
	}
}

func TestSCCMAdminServiceFingerprinter_Fingerprint_NotSiteServer(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{name: "200 without edmx body", statusCode: 200, body: []byte("<html>other</html>")},
		{name: "403 forbidden", statusCode: 403, body: nil},
		{name: "404 not found", statusCode: 404, body: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SCCMAdminServiceFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", "Microsoft-IIS/10.0")

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// --- Integration --------------------------------------------------------------

func TestSCCMManagementPointFingerprinter_Integration(t *testing.T) {
	fp := &SCCMManagementPointFingerprinter{}

	body := []byte(`<MPList><MP Name="MP01" FQDN="mp01.contoso.com" SiteCode="ABC"><Version>9128</Version></MP></MPList>`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "sccm-mp", result.Technology)
	assert.Equal(t, "5.00.9128", result.Version)
}

func TestSCCMDistributionPointFingerprinter_Integration(t *testing.T) {
	fp := &SCCMDistributionPointFingerprinter{}

	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("WWW-Authenticate", "NTLM")
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "sccm-dp", result.Technology)
}

func TestSCCMAdminServiceFingerprinter_Integration(t *testing.T) {
	fp := &SCCMAdminServiceFingerprinter{}

	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "sccm-adminservice", result.Technology)
}
