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
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSynologyResp builds a minimal *http.Response with the given Content-Type
// and optional extra headers (key→value pairs applied one at a time).
func newSynologyResp(ct string, extra map[string]string) *http.Response {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	for k, v := range extra {
		h.Add(k, v)
	}
	return &http.Response{Header: h}
}

// newSynologyRespCSPs builds a response carrying one Content-Security-Policy
// header value per entry in csps.
func newSynologyRespCSPs(csps []string) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	for _, csp := range csps {
		h.Add("Content-Security-Policy", csp)
	}
	return &http.Response{Header: h}
}

// --- Name -------------------------------------------------------------------

func TestSynologyDSMFingerprinter_Name(t *testing.T) {
	f := &SynologyDSMFingerprinter{}
	assert.Equal(t, "synology-dsm", f.Name())
}

// --- Match ------------------------------------------------------------------

func TestSynologyDSMFingerprinter_Match(t *testing.T) {
	f := &SynologyDSMFingerprinter{}
	cases := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"nil response", nil, false},
		{"empty content-type", newSynologyResp("", nil), true},
		{"text/html", newSynologyResp("text/html; charset=utf-8", nil), true},
		{"text/html uppercase", newSynologyResp("TEXT/HTML", nil), true},
		{"application/xhtml+xml", newSynologyResp("application/xhtml+xml", nil), true},
		{"application/json rejected", newSynologyResp("application/json", nil), false},
		{"text/plain rejected", newSynologyResp("text/plain", nil), false},
		{"image/png rejected", newSynologyResp("image/png", nil), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, f.Match(tc.resp))
		})
	}
}

// --- Fingerprint ------------------------------------------------------------

const (
	synoVersionBody = `<html><head><title>Synology DiskStation Manager (DSM)</title></head><body>
Synology DiskStation Manager (DSM): Version: 7.2.1-69057
webman/index.cgi</body></html>`

	synoTitleClassB = `<html><head><title>Synology DiskStation</title></head><body>
<script src="/webman/ext.js"></script></body></html>`

	synoTitleOnly = `<html><head><title>Synology NAS Comparison Guide</title></head><body>nothing else</body></html>`

	synoRackStation = `<html><head><title>Synology RackStation NAS</title></head><body>
<script src="/webman/main.js"></script></body></html>`
)

func TestSynologyDSMFingerprinter_Fingerprint(t *testing.T) {
	f := &SynologyDSMFingerprinter{}
	htmlCT := "text/html"

	cases := []struct {
		name        string
		resp        *http.Response
		body        []byte
		wantNil     bool
		wantTech    string
		wantVersion string
		wantFF      string
		wantCPE     string
	}{
		// nil / empty guard
		{
			name:    "nil response",
			resp:    nil,
			body:    []byte(synoVersionBody),
			wantNil: true,
		},
		{
			name:    "empty body",
			resp:    newSynologyResp(htmlCT, nil),
			body:    []byte{},
			wantNil: true,
		},
		// Class A: version-leak block (iron-clad)
		{
			name:        "version leak detected with version",
			resp:        newSynologyResp(htmlCT, nil),
			body:        []byte(synoVersionBody),
			wantTech:    "synology-dsm",
			wantVersion: "7.2.1-69057",
			wantFF:      "DiskStation",
			wantCPE:     "cpe:2.3:o:synology:diskstation_manager:7.2.1-69057:*:*:*:*:*:*:*",
		},
		{
			name:        "version leak no title → form_factor unknown",
			resp:        newSynologyResp(htmlCT, nil),
			body:        []byte("Synology DiskStation Manager (DSM): Version: 6.2.4\nwebman/"),
			wantTech:    "synology-dsm",
			wantVersion: "6.2.4",
			wantFF:      "unknown",
			wantCPE:     "cpe:2.3:o:synology:diskstation_manager:6.2.4:*:*:*:*:*:*:*",
		},
		{
			// DSM marker present but Version: is followed by non-numeric chars —
			// the version regex does not match, so dsmVersion="" and CPE uses "*".
			name:        "version leak no parseable version → wildcard CPE",
			resp:        newSynologyResp(htmlCT, nil),
			body:        []byte("Synology DiskStation Manager (DSM): Version: UNKNOWN\nfoo"),
			wantTech:    "synology-dsm",
			wantVersion: "",
			wantFF:      "unknown",
			wantCPE:     "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		// Class A: CSP synology.com (iron-clad)
		{
			name:     "CSP synology.com detected no other signals",
			resp:     newSynologyRespCSPs([]string{"default-src 'self' *.synology.com"}),
			body:     []byte("<html><body>generic page</body></html>"),
			wantTech: "synology-dsm",
			wantFF:   "unknown",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:     "CSP case-insensitive SYNOLOGY.COM detected",
			resp:     newSynologyRespCSPs([]string{"default-src HTTPS://SYNOLOGY.COM"}),
			body:     []byte("<html><body>page</body></html>"),
			wantTech: "synology-dsm",
			wantFF:   "unknown",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:     "multiple CSP headers first has synology.com",
			resp:     newSynologyRespCSPs([]string{"default-src *.synology.com", "img-src *"}),
			body:     []byte("<html></html>"),
			wantTech: "synology-dsm",
			wantFF:   "unknown",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		// Class A: title + Class B corroborator
		{
			name:     "title DiskStation + webman ClassB → detected",
			resp:     newSynologyResp(htmlCT, nil),
			body:     []byte(synoTitleClassB),
			wantTech: "synology-dsm",
			wantFF:   "DiskStation",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			// Title "Synology RackStation NAS" — the regex has a greedy [^<]{0,30}
			// wildcard before the alternation (DiskStation|NAS|RackStation), so the
			// engine advances as far right as possible within the 30-char budget and
			// matches "NAS" rather than "RackStation" (which appears earlier).
			// To match the first-appearing form factor, the wildcard would need to be
			// lazy ([^<]{0,30}?); the current greedy form is intentionally preserved.
			name:     "title RackStation NAS + webman ClassB → form_factor NAS",
			resp:     newSynologyResp(htmlCT, nil),
			body:     []byte(synoRackStation),
			wantTech: "synology-dsm",
			wantFF:   "NAS",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:     "title + synoSDSjslib ClassB → detected",
			resp:     newSynologyResp(htmlCT, nil),
			body:     []byte(`<title>Synology DiskStation Manager</title><script src="synoSDSjslib/sds.js"></script>`),
			wantTech: "synology-dsm",
			wantFF:   "DiskStation",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:     "title + SYNO.Core.Desktop ClassB → detected",
			resp:     newSynologyResp(htmlCT, nil),
			body:     []byte(`<title>Synology NAS Login</title> SYNO.Core.Desktop.foo`),
			wantTech: "synology-dsm",
			wantFF:   "NAS",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		// Title-only: NO Class B → rejected
		{
			name:    "title-only no ClassB → not detected",
			resp:    newSynologyResp(htmlCT, nil),
			body:    []byte(synoTitleOnly),
			wantNil: true,
		},
		// No signals → rejected
		{
			name:    "no signals → not detected",
			resp:    newSynologyResp(htmlCT, nil),
			body:    []byte("<html><body>random page</body></html>"),
			wantNil: true,
		},
		{
			name:    "CSP unrelated domain → not detected",
			resp:    newSynologyRespCSPs([]string{"default-src 'self' *.example.com"}),
			body:    []byte("<html></html>"),
			wantNil: true,
		},
		// Fix 1: CSP-only iron-clad detection on empty body
		{
			name: "CSP-only iron-clad detection on empty body",
			resp: newSynologyRespCSPs([]string{"default-src 'self' https://*.synology.com"}),
			body: []byte{},
			// CSP alone is iron-clad Class A; empty body is fine — no version, no title.
			wantTech: "synology-dsm",
			wantFF:   "unknown",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		{
			// 204 No Content carries an empty body by definition; CSP header alone suffices.
			name: "CSP-only iron-clad on 204 No Content with empty body",
			resp: func() *http.Response {
				h := http.Header{}
				h.Set("Content-Type", "text/html")
				h.Add("Content-Security-Policy", "default-src 'self' https://*.synology.com")
				return &http.Response{StatusCode: 204, Header: h}
			}(),
			body:     []byte{},
			wantTech: "synology-dsm",
			wantFF:   "unknown",
			wantCPE:  "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		},
		// Fix 2: marker in prose then version block appears later — simplified scan must find it
		{
			name: "marker appears in prose then version block appears later",
			resp: newSynologyResp("text/html", nil),
			body: []byte(
				`<p>The string "Synology DiskStation Manager (DSM):" is mentioned here in prose.</p>` +
					"\n" + strings.Repeat("padding\n", 500) +
					"Synology DiskStation Manager (DSM):\n  Version: 7.1.1-42962\n  Hostname: x",
			),
			wantTech:    "synology-dsm",
			wantVersion: "7.1.1-42962",
			wantFF:      "unknown",
			wantCPE:     "cpe:2.3:o:synology:diskstation_manager:7.1.1-42962:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := f.Fingerprint(tc.resp, tc.body)
			require.NoError(t, err)
			if tc.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tc.wantTech, result.Technology)
			assert.Equal(t, tc.wantVersion, result.Version)
			assert.Equal(t, tc.wantFF, result.Metadata["form_factor"])
			assert.Equal(t, "/webman/index.cgi", result.Metadata["login_path"])
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tc.wantCPE, result.CPEs[0])
		})
	}
}

// --- sanitizeSynologyDSMVersion --------------------------------------------

func TestSanitizeSynologyDSMVersion(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"7.2.1-69057", "7.2.1-69057"},
		{"7.2-69057", "7.2-69057"},
		{"6.2.4", "6.2.4"},
		{"7.2.1-12345; rm -rf /", ""},
		{"7.2.1\n", ""},
		{"../../etc/passwd", ""},
		{"7.2.1-12345-extra", ""},
		// Passes charset (only digits/dots/dashes) but fails structural check (trailing dash).
		{"7.2.1-", ""},
		{strings.Repeat("1", 33), ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeSynologyDSMVersion(tc.input))
		})
	}
}

// --- buildSynologyDSMCPE ---------------------------------------------------

func TestBuildSynologyDSMCPE(t *testing.T) {
	assert.Equal(t,
		"cpe:2.3:o:synology:diskstation_manager:7.2.1-69057:*:*:*:*:*:*:*",
		buildSynologyDSMCPE("7.2.1-69057"),
	)
	assert.Equal(t,
		"cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
		buildSynologyDSMCPE(""),
	)
}

// --- C3: hostname must never appear in metadata (BLOCKING) -----------------

func TestSynologyDSMFingerprinter_HostnameNeverInMetadata(t *testing.T) {
	const sentinel = "RECON_TARGET_HOSTNAME_PII_xyz"
	f := &SynologyDSMFingerprinter{}

	body := []byte(`<html><head><title>Synology DiskStation ` + sentinel + `</title></head><body>
Synology DiskStation Manager (DSM): Version: 7.2.1-69057
webman/index.cgi</body></html>`)

	result, err := f.Fingerprint(newSynologyResp("text/html", nil), body)
	require.NoError(t, err)
	require.NotNil(t, result)

	serialized, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Equal(t, 0, strings.Count(string(serialized), sentinel),
		"hostname sentinel must not appear in serialized FingerprintResult (C3 PII control)")
}

// --- C2: no ReDoS on 10 MB pathological body (BLOCKING) --------------------

func TestSynologyDSMFingerprinter_NoReDoSOn10MBBody(t *testing.T) {
	f := &SynologyDSMFingerprinter{}

	// Build a 10 MB body of near-miss patterns that stress the version-leak and
	// title regexes without ever completing a match.
	chunk := []byte("Synology DiskStation Manager (DSM): Version: XXXXXXXXX\n")
	var buf bytes.Buffer
	buf.Grow(10 * 1024 * 1024)
	for buf.Len() < 10*1024*1024 {
		buf.Write(chunk)
	}
	body := buf.Bytes()[:10*1024*1024]

	start := time.Now()
	_, err := f.Fingerprint(newSynologyResp("text/html", nil), body)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, 100*time.Millisecond,
		"Fingerprint must complete in <100 ms on 10 MB pathological body (C2 ReDoS control); took %s", elapsed)
}
