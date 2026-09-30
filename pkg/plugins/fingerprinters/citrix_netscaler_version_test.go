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
	"encoding/binary"
	"net/http"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildCitrixRdxGz builds a synthetic rdx_en.json.gz body: the gzip magic
// {0x1f,0x8b,0x08,0x08} in bytes[0:4], the RFC 1952 MTIME (little-endian) in
// bytes[4:8], and the embedded original filename "rdx_en.json" that Fingerprint
// requires as a corroborating marker.
func buildCitrixRdxGz(stamp uint32) []byte {
	b := []byte{0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(b[4:8], stamp)
	b = append(b, 0x00, 0x03)               // XFL, OS
	b = append(b, []byte("rdx_en.json")...) // FNAME (FLG.FNAME set in magic)
	b = append(b, 0x00)                     // NUL terminator
	return b
}

// --- TestCitrixNetScalerVersionFingerprinter_Name ---

func TestCitrixNetScalerVersionFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "citrix-netscaler-version", (&CitrixNetScalerVersionFingerprinter{}).Name())
}

// --- TestCitrixNetScalerVersionFingerprinter_ProbeEndpoint ---

func TestCitrixNetScalerVersionFingerprinter_ProbeEndpoint(t *testing.T) {
	assert.Equal(t, "/vpn/js/rdx/core/lang/rdx_en.json.gz",
		(&CitrixNetScalerVersionFingerprinter{}).ProbeEndpoint())
}

// --- TestCitrixNetScalerVersionFingerprinter_ProbeAccept ---

func TestCitrixNetScalerVersionFingerprinter_ProbeAccept(t *testing.T) {
	assert.Equal(t, "*/*", (&CitrixNetScalerVersionFingerprinter{}).ProbeAccept())
}

// --- TestCitrixNetScalerVersionFingerprinter_Match ---

func TestCitrixNetScalerVersionFingerprinter_Match(t *testing.T) {
	fp := &CitrixNetScalerVersionFingerprinter{}
	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"nil response", nil, false},
		{"200 OK", &http.Response{StatusCode: http.StatusOK}, true},
		{"404 Not Found", &http.Response{StatusCode: http.StatusNotFound}, false},
		{"302 redirect", &http.Response{StatusCode: http.StatusFound}, false},
		{"500 error", &http.Response{StatusCode: http.StatusInternalServerError}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(tt.resp))
		})
	}
}

// --- TestCitrixNetScalerVersionFingerprinter_Fingerprint ---

func TestCitrixNetScalerVersionFingerprinter_Fingerprint(t *testing.T) {
	fp := &CitrixNetScalerVersionFingerprinter{}
	resp := &http.Response{StatusCode: http.StatusOK}

	t.Run("known affected stamp resolves version and emits CTX697096 finding", func(t *testing.T) {
		// 1762663520 -> "13.1-61.23" (Fox-IT dataset). 13.1-61.23 < 13.1-64.23,
		// so this build IS affected by CTX697096.
		body := buildCitrixRdxGz(1762663520)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "citrix-netscaler", result.Technology)
		assert.Equal(t, "13.1-61.23", result.Version)
		assert.Equal(t, plugins.SeverityHigh, result.Severity)

		require.Len(t, result.SecurityFindings, 1)
		finding := result.SecurityFindings[0]
		assert.Equal(t, "citrix-netscaler-ctx697096", finding.ID)
		assert.Equal(t, plugins.SeverityHigh, finding.Severity)
	})

	t.Run("unknown stamp confirms asset but leaves version empty with no finding", func(t *testing.T) {
		// Valid gzip + rdx_en.json marker but a stamp far beyond the shipped
		// table (year ~2096); build cannot be resolved and no CVE is inferred.
		body := buildCitrixRdxGz(4000000000)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "citrix-netscaler", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.NotEmpty(t, result.Metadata["version_status"])
		assert.Empty(t, result.SecurityFindings)
	})

	t.Run("zeroed stamp (gzip -n) returns nil", func(t *testing.T) {
		body := buildCitrixRdxGz(0)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("non-gzip body returns nil", func(t *testing.T) {
		body := []byte("this is not a gzip stream but mentions rdx_en.json anyway")
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("missing rdx_en.json marker returns nil", func(t *testing.T) {
		body := []byte{0x1f, 0x8b, 0x08, 0x08, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(body[4:8], 1762663520)
		body = append(body, 0x00, 0x03) // valid header, no filename marker
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body shorter than 8 bytes returns nil", func(t *testing.T) {
		body := []byte{0x1f, 0x8b, 0x08}
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// --- TestCitrixIsVulnCTX697096 ---

func TestCitrixIsVulnCTX697096(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		// 14.1 branch: fixed in 14.1-73.37.
		{"14.1-73.36", true},
		{"14.1-73.37", false},
		{"14.1-73.38", false},
		// 13.1 branch: fixed in 13.1-64.23.
		{"13.1-64.22", true},
		{"13.1-64.23", false},
		{"13.1-64.24", false},
		// 13.1-FIPS / NDcPP branch: fixed in 13.1-37.279.
		{"13.1-37.278", true},
		{"13.1-37.279", false},
		// EOL branches (no fix): treated affected.
		{"13.0-90.7", true},
		{"12.1-65.39", true},
		// 12.1-FIPS is not enumerated in CTX697096: must NOT assert vulnerability.
		{"12.1-55.300", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v, ok := parseCitrixVersion(tt.version)
			require.True(t, ok, "parseCitrixVersion(%q) should succeed", tt.version)
			assert.Equal(t, tt.want, isVulnCTX697096(v))
		})
	}
}

// --- TestParseCitrixVersion ---

func TestParseCitrixVersion(t *testing.T) {
	t.Run("well-formed build parses to tuple", func(t *testing.T) {
		v, ok := parseCitrixVersion("14.1-73.37")
		require.True(t, ok)
		assert.Equal(t, citrixVersionTuple{14, 1, 73, 37}, v)
	})

	invalid := []struct{ name, version string }{
		{"literal unknown", "unknown"},
		{"empty string", ""},
		{"three fields only", "14.1-73"},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := parseCitrixVersion(tt.version)
			assert.False(t, ok)
		})
	}
}
