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

// ── Fixtures (shapes verified against rancher source, unit tests, Nuclei templates) ──

// /rancherversion response (Rancher 2.7.0+). PascalCase fields, no json tags.
const rancherVersionJSON = `{"Version":"v2.8.5","GitCommit":"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0","RancherPrime":"false"}`

const rancherVersionPrimeJSON = `{"Version":"v2.9.1","GitCommit":"deadbeefdeadbeef","RancherPrime":"true"}`

// An unbuilt/dev server: Version is not a semver.
const rancherVersionDevJSON = `{"Version":"dev","GitCommit":"HEAD","RancherPrime":"false"}`

// Generic version document from unrelated software — must NOT match (no RancherPrime).
const genericVersionJSON = `{"Version":"3.1.4","GitCommit":"abc1234","Build":"release"}`

// Modern Vue dashboard SPA shell (GET /dashboard/), faithful to the shipped
// rancher/dashboard index.html: <title>Rancher</title>, the R_PCS cookie read in the
// inline bootstrap script, and the initial-load-spinner container. (Real Rancher has no
// <meta name="description">, so the fixture deliberately omits one.)
const rancherDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Rancher</title>
  <link rel="shortcut icon" type="image/x-icon" href="/favicon.png">
  <script>if(document.cookie.includes('R_PCS=dark')){document.documentElement.classList.add('dark')}</script>
</head>
<body>
  <div id="app"></div>
  <div class="initial-load-spinner-container"><div class="initial-load-spinner"></div></div>
</body>
</html>`

// A non-Rancher page that merely contains the words "Rancher Dashboard" (e.g. a monitoring
// page or blog) with a non-Rancher title and no structural markers — must NOT match.
const rancherDashboardTextNoStructureHTML = `<!DOCTYPE html>
<html><head><title>Acme Cloud</title></head>
<body><h1>Rancher Dashboard status: OK</h1></body></html>`

// Generic SPA that merely says "Rancher" in the title but has no Rancher structure.
const genericRancherTitleHTML = `<!DOCTYPE html>
<html><head><title>Rancher</title></head><body><div id="root">hello</div></body></html>`

func newRespWithPath(status int, contentType, rawPath string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	resp := &http.Response{StatusCode: status, Header: h}
	if rawPath != "" {
		resp.Request = &http.Request{URL: &url.URL{Path: rawPath}}
	}
	return resp
}

// ── FP1: identity / wiring ──────────────────────────────────────────────────────

func TestRancherFingerprinter_Identity(t *testing.T) {
	fp := &RancherFingerprinter{}
	assert.Equal(t, "rancher", fp.Name())
	assert.Equal(t, "/rancherversion", fp.ProbeEndpoint())
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ── FP1: Match ────────────────────────────────────────────────────────────────

func TestRancherFingerprinter_Match(t *testing.T) {
	fp := &RancherFingerprinter{}
	tests := []struct {
		name        string
		status      int
		contentType string
		path        string
		want        bool
	}{
		{"json content-type", 200, "application/json", "", true},
		{"probe path no CT", 200, "", "/rancherversion", true},
		{"probe path suffix proxied", 200, "", "/rancher/rancherversion", true},
		{"html only, not probe path", 200, "text/html", "/", false},
		{"5xx rejected", 503, "application/json", "/rancherversion", false},
		{"1xx rejected", 100, "application/json", "/rancherversion", false},
		{"404 still a candidate by path", 404, "", "/rancherversion", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(newRespWithPath(tt.status, tt.contentType, tt.path)))
		})
	}
}

// ── FP1: Fingerprint ──────────────────────────────────────────────────────────

func TestRancherFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	result, err := fp.Fingerprint(resp, []byte(rancherVersionJSON))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "rancher", result.Technology)
	assert.Equal(t, "2.8.5", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:suse:rancher:2.8.5:*:*:*:*:*:*:*")
	assert.Equal(t, "SUSE", result.Metadata["vendor"])
	assert.Equal(t, "Rancher", result.Metadata["product"])
	assert.Equal(t, "rancherversion_api", result.Metadata["detection_method"])
	assert.Equal(t, false, result.Metadata["rancher_prime"])
	assert.Equal(t, "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0", result.Metadata["git_commit"])
	// Pure detection: no severity, no findings.
	assert.Empty(t, result.Severity)
	assert.Empty(t, result.SecurityFindings)
}

func TestRancherFingerprinter_Fingerprint_PrimeTrue(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	result, err := fp.Fingerprint(resp, []byte(rancherVersionPrimeJSON))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "2.9.1", result.Version)
	assert.Equal(t, true, result.Metadata["rancher_prime"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:suse:rancher:2.9.1:*:*:*:*:*:*:*")
}

func TestRancherFingerprinter_Fingerprint_PrimeNativeBool(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	// Future-proofing: if RancherPrime is ever emitted as a native JSON boolean (no
	// surrounding quotes), the rancher_prime metadata must still resolve.
	result, err := fp.Fingerprint(resp, []byte(`{"Version":"v2.9.1","GitCommit":"deadbeef","RancherPrime":true}`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, true, result.Metadata["rancher_prime"])
	assert.Equal(t, "2.9.1", result.Version)
}

func TestRancherFingerprinter_Fingerprint_Prerelease(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	// The full prerelease version is preserved for display/metadata, but the CPE uses the
	// core version (rc lives in NVD's update field, which we wildcard).
	result, err := fp.Fingerprint(resp, []byte(`{"Version":"v2.8.0-rc1","GitCommit":"abc1234","RancherPrime":"false"}`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "2.8.0-rc1", result.Version)
	assert.Equal(t, "2.8.0-rc1", result.Metadata["version"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:suse:rancher:2.8.0:*:*:*:*:*:*:*")
}

func TestRancherFingerprinter_Fingerprint_DevVersionGraceful(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	// "dev" is not a semver: still a confirmed Rancher (RancherPrime present),
	// but version is empty and the CPE is wildcarded.
	result, err := fp.Fingerprint(resp, []byte(rancherVersionDevJSON))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "rancher", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*")
	assert.NotContains(t, result.Metadata, "version")
}

func TestRancherFingerprinter_Fingerprint_GenericJSONRejected(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/version")

	// No RancherPrime marker → not Rancher.
	result, err := fp.Fingerprint(resp, []byte(genericVersionJSON))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestRancherFingerprinter_Fingerprint_StatusAndBodyGates(t *testing.T) {
	fp := &RancherFingerprinter{}

	// 5xx → nil.
	result, err := fp.Fingerprint(newRespWithPath(503, "application/json", "/rancherversion"), []byte(rancherVersionJSON))
	require.NoError(t, err)
	assert.Nil(t, result)

	// Oversized body (> cap) → nil.
	oversized := append([]byte(rancherVersionJSON), make([]byte, 512*1024)...)
	result, err = fp.Fingerprint(newRespWithPath(200, "application/json", "/rancherversion"), oversized)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Exactly at the 512 KiB cap → accepted (guards against a >→>= regression).
	exact := append([]byte(rancherVersionJSON), []byte(strings.Repeat(" ", 512*1024-len(rancherVersionJSON)))...)
	require.Equal(t, 512*1024, len(exact))
	result, err = fp.Fingerprint(newRespWithPath(200, "application/json", "/rancherversion"), exact)
	require.NoError(t, err)
	require.NotNil(t, result, "a body of exactly 512 KiB must be accepted")
	assert.Equal(t, "2.8.5", result.Version)
}

func TestRancherFingerprinter_Fingerprint_NilAndEmptyBody(t *testing.T) {
	fp := &RancherFingerprinter{}
	resp := newRespWithPath(200, "application/json", "/rancherversion")

	for _, body := range [][]byte{nil, {}, []byte("   "), []byte("not json")} {
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	}
}

// ── FP1: version extraction + CPE-injection guard ──────────────────────────────

func TestExtractRancherVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"v-prefixed", `{"Version":"v2.8.5"}`, "2.8.5"},
		{"bare semver", `{"Version":"2.7.0"}`, "2.7.0"},
		{"prerelease", `{"Version":"v2.8.0-rc1"}`, "2.8.0-rc1"},
		// Four-part: the extract regex requires a closing quote immediately after the
		// 3-part semver, so "v2.8.5.1" (".1" before the quote) matches nothing at all.
		{"malformed four-part rejected", `{"Version":"v2.8.5.1"}`, ""},
		{"dev not a version", `{"Version":"dev"}`, ""},
		{"empty", `{"Version":""}`, ""},
		{"missing field", `{"GitCommit":"abc"}`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractRancherVersion([]byte(tt.body)))
		})
	}
}

func TestExtractRancherVersion_CPEInjectionGuard(t *testing.T) {
	// Even if a malicious server tried to smuggle CPE metacharacters, the anchored
	// validator rejects anything that is not a clean semver.
	malicious := []string{
		`{"Version":"2.8.5:*:*:root"}`,
		`{"Version":"*"}`,
		`{"Version":"2.8.5*extra"}`,
	}
	for _, body := range malicious {
		got := extractRancherVersion([]byte(body))
		assert.NotContains(t, got, ":")
		assert.NotContains(t, got, "*")
	}
}

func TestBuildRancherCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:suse:rancher:2.8.5:*:*:*:*:*:*:*", buildRancherCPE("2.8.5"))
	assert.Equal(t, "cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*", buildRancherCPE(""))
	// Prerelease is reduced to the core version (NVD encodes rc in the update field;
	// the wildcard update still matches both the rc and final NVD CPEs).
	assert.Equal(t, "cpe:2.3:a:suse:rancher:2.8.0:*:*:*:*:*:*:*", buildRancherCPE("2.8.0-rc1"))
}

// ── FP2: identity / wiring ──────────────────────────────────────────────────────

func TestRancherDashboardFingerprinter_Identity(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}
	assert.Equal(t, "rancher_dashboard", fp.Name())
	assert.Equal(t, "/dashboard/", fp.ProbeEndpoint())
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── FP2: Match ────────────────────────────────────────────────────────────────

func TestRancherDashboardFingerprinter_Match(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}
	tests := []struct {
		name        string
		status      int
		contentType string
		want        bool
	}{
		{"html", 200, "text/html; charset=utf-8", true},
		{"empty CT", 200, "", true},
		{"json rejected", 200, "application/json", false},
		{"5xx rejected", 500, "text/html", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(newRespWithPath(tt.status, tt.contentType, "")))
		})
	}
}

// ── FP2: Fingerprint ──────────────────────────────────────────────────────────

func TestRancherDashboardFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}
	resp := newRespWithPath(200, "text/html", "/dashboard/")

	result, err := fp.Fingerprint(resp, []byte(rancherDashboardHTML))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "rancher_dashboard", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:suse:rancher:*:*:*:*:*:*:*:*")
	assert.Equal(t, "SUSE", result.Metadata["vendor"])
	assert.Equal(t, "dashboard_spa", result.Metadata["detection_method"])
	assert.Equal(t, "vue", result.Metadata["ui_framework"])
	assert.Empty(t, result.Severity)
}

func TestRancherDashboardFingerprinter_Fingerprint_RancherTextWithoutStructureRejected(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}
	resp := newRespWithPath(200, "text/html", "/dashboard/")

	// A page that merely contains the words "Rancher Dashboard" but has a non-Rancher
	// title and no structural markers must NOT be flagged (false-positive guard).
	result, err := fp.Fingerprint(resp, []byte(rancherDashboardTextNoStructureHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestRancherDashboardFingerprinter_Fingerprint_TitleAloneRejected(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}
	resp := newRespWithPath(200, "text/html", "/dashboard/")

	// A page whose title merely says "Rancher" but has no Rancher structure must not match.
	result, err := fp.Fingerprint(resp, []byte(genericRancherTitleHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestRancherDashboardFingerprinter_Fingerprint_Gates(t *testing.T) {
	fp := &RancherDashboardFingerprinter{}

	// 5xx → nil.
	result, err := fp.Fingerprint(newRespWithPath(500, "text/html", "/dashboard/"), []byte(rancherDashboardHTML))
	require.NoError(t, err)
	assert.Nil(t, result)

	// Oversized (> cap) → nil.
	oversized := append([]byte(rancherDashboardHTML), make([]byte, 2*1024*1024)...)
	result, err = fp.Fingerprint(newRespWithPath(200, "text/html", "/dashboard/"), oversized)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Exactly at the 2 MiB cap → accepted (guards against a >→>= regression).
	exact := append([]byte(rancherDashboardHTML), []byte(strings.Repeat(" ", 2*1024*1024-len(rancherDashboardHTML)))...)
	require.Equal(t, 2*1024*1024, len(exact))
	result, err = fp.Fingerprint(newRespWithPath(200, "text/html", "/dashboard/"), exact)
	require.NoError(t, err)
	require.NotNil(t, result, "a body of exactly 2 MiB must be accepted")

	// Nil / empty body → nil.
	for _, body := range [][]byte{nil, {}, []byte("<html></html>")} {
		result, err := fp.Fingerprint(newRespWithPath(200, "text/html", "/dashboard/"), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	}
}

// ── Registration / contract (order-independent) ─────────────────────────────────

func TestRancherFingerprinters_Registered(t *testing.T) {
	saved := httpFingerprinters
	defer func() { httpFingerprinters = saved }()

	httpFingerprinters = nil
	Register(&RancherFingerprinter{})
	Register(&RancherDashboardFingerprinter{})

	assert.NotNil(t, GetFingerprinterByName("rancher"))
	assert.NotNil(t, GetFingerprinterByName("rancher_dashboard"))

	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/rancherversion", endpoints["rancher"])
	assert.Equal(t, "/dashboard/", endpoints["rancher_dashboard"])
}

// The two fingerprinters MUST use distinct Technology values, otherwise the engine's
// metadata map (keyed by Technology) would collide and lose one fingerprinter's data.
func TestRancherFingerprinters_DistinctTechnology(t *testing.T) {
	v := &RancherFingerprinter{}
	d := &RancherDashboardFingerprinter{}

	vRes, err := v.Fingerprint(newRespWithPath(200, "application/json", "/rancherversion"), []byte(rancherVersionJSON))
	require.NoError(t, err)
	require.NotNil(t, vRes)

	dRes, err := d.Fingerprint(newRespWithPath(200, "text/html", "/dashboard/"), []byte(rancherDashboardHTML))
	require.NoError(t, err)
	require.NotNil(t, dRes)

	assert.NotEqual(t, vRes.Technology, dRes.Technology)
}

// Both fingerprinters must only ever emit the suse:rancher CPE (never rancher_desktop).
func TestRancherFingerprinters_NeverEmitRancherDesktop(t *testing.T) {
	v := &RancherFingerprinter{}
	d := &RancherDashboardFingerprinter{}

	vRes, _ := v.Fingerprint(newRespWithPath(200, "application/json", "/rancherversion"), []byte(rancherVersionJSON))
	dRes, _ := d.Fingerprint(newRespWithPath(200, "text/html", "/dashboard/"), []byte(rancherDashboardHTML))

	for _, res := range []*FingerprintResult{vRes, dRes} {
		require.NotNil(t, res)
		for _, cpe := range res.CPEs {
			assert.False(t, strings.Contains(cpe, "rancher_desktop"), "must not emit rancher_desktop CPE: %s", cpe)
			assert.True(t, strings.HasPrefix(cpe, "cpe:2.3:a:suse:rancher:"), "unexpected CPE: %s", cpe)
		}
	}
}
