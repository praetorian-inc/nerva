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
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TestRoundcubeFingerprinter_Name ---

func TestRoundcubeFingerprinter_Name(t *testing.T) {
	fp := &RoundcubeFingerprinter{}
	assert.Equal(t, "roundcube", fp.Name())
}

// --- TestRoundcubeFingerprinter_Match ---

func TestRoundcubeFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{name: "matches text/html", contentType: "text/html", expected: true},
		{name: "matches text/html with charset", contentType: "text/html; charset=utf-8", expected: true},
		{name: "matches application/xhtml+xml", contentType: "application/xhtml+xml", expected: true},
		{name: "matches empty content type", contentType: "", expected: true},
		{name: "rejects application/json", contentType: "application/json", expected: false},
		{name: "rejects image/png", contentType: "image/png", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RoundcubeFingerprinter{}
			resp := &http.Response{Header: http.Header{"Content-Type": []string{tt.contentType}}}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}

	t.Run("nil response returns false", func(t *testing.T) {
		fp := &RoundcubeFingerprinter{}
		assert.False(t, fp.Match(nil))
	})
}

// --- TestRoundcubeFingerprinter_Fingerprint ---

func TestRoundcubeFingerprinter_Fingerprint(t *testing.T) {
	const sessToken = "SECRET_SESSION_TOKEN_abc123"
	titleBody := `<html><head><title>Roundcube Webmail</title></head></html>`
	formBody := `<input id="rcmloginuser" name="rcmloginuser" />`
	skinElastic := `<link href="/skins/elastic/style.css" />`
	skinLarry := `<link href="/skins/larry/style.css" />`
	rcv10411 := `"rcversion" : 10411`
	rcv10600 := `"rcversion" : 10600`
	rcv10608 := `"rcversion" : 10608`
	respWithCookie := func() *http.Response {
		r := &http.Response{Header: http.Header{}}
		r.Header.Add("Set-Cookie", "roundcube_sessid="+sessToken+"; path=/; HttpOnly")
		return r
	}
	plainResp := func() *http.Response { return &http.Response{Header: http.Header{}} }

	tests := []struct {
		name        string
		resp        *http.Response
		body        string
		wantNil     bool
		wantVersion string
		wantSkin    string
		wantCPE     string
	}{
		{
			name:        "full happy path rcversion 10411 larry",
			resp:        plainResp(),
			body:        titleBody + skinLarry + `<script>rcmail.set_env({` + rcv10411 + `})</script>` + formBody,
			wantNil:     false,
			wantVersion: "1.4.11",
			wantSkin:    "larry",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:1.4.11:*:*:*:*:*:*:*",
		},
		{
			name:        "full happy path rcversion 10600 elastic",
			resp:        plainResp(),
			body:        titleBody + skinElastic + `<script>rcmail.set_env({` + rcv10600 + `})</script>` + formBody,
			wantNil:     false,
			wantVersion: "1.6.0",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:1.6.0:*:*:*:*:*:*:*",
		},
		{
			name:        "full happy path rcversion 10608 elastic",
			resp:        plainResp(),
			body:        titleBody + skinElastic + `<script>{"` + rcv10608 + `"}</script>` + formBody,
			wantNil:     false,
			wantVersion: "1.6.8",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:1.6.8:*:*:*:*:*:*:*",
		},
		{
			name:        "title + cookie 2 signals no version",
			resp:        respWithCookie(),
			body:        titleBody,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "unknown",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:        "cookie + form 2 signals no title skin rcversion",
			resp:        respWithCookie(),
			body:        formBody,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "unknown",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:        "login-form + skin 2 signals",
			resp:        plainResp(),
			body:        formBody + skinElastic,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:    "rcversion alone 1 of 5 signals",
			resp:    plainResp(),
			body:    `<html><body><script>{"` + rcv10600 + `"}</script></body></html>`,
			wantNil: true,
		},
		{
			name:    "skin-only 1 signal",
			resp:    plainResp(),
			body:    skinElastic,
			wantNil: true,
		},
		{
			name:    "empty body no cookie",
			resp:    plainResp(),
			body:    "",
			wantNil: true,
		},
		{
			name:    "non-HTML JSON body no markers no cookie",
			resp:    plainResp(),
			body:    `{"msg":"Roundcube Webmail service is running"}`,
			wantNil: true,
		},
		{
			name:        "malicious rcversion injection blocked by regex",
			resp:        plainResp(),
			body:        titleBody + formBody + `<script>{"rcversion":"1.6.0;DROP TABLE"}</script>`,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "unknown",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:        "rcversion 999 below threshold version empty",
			resp:        plainResp(),
			body:        titleBody + formBody + `<script>{"rcversion":999}</script>`,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "unknown",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:        "unknown skin classic not matched",
			resp:        plainResp(),
			body:        titleBody + formBody + `<link href="/skins/classic/style.css" />`,
			wantNil:     false,
			wantVersion: "",
			wantSkin:    "unknown",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
		{
			name:        "roundcube 2.x future rcversion 20000",
			resp:        plainResp(),
			body:        titleBody + skinElastic + `<script>{"rcversion":20000}</script>` + formBody,
			wantNil:     false,
			wantVersion: "2.0.0",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:2.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "benign page roundcube in copy only no signals",
			resp:    plainResp(),
			body:    `<html><body><p>We use Roundcube Webmail for email.</p></body></html>`,
			wantNil: true,
		},
		{
			name:    "title-only 1 of 5 signals",
			resp:    plainResp(),
			body:    titleBody,
			wantNil: true,
		},
		{
			name:    "nil response",
			resp:    nil,
			body:    titleBody + formBody,
			wantNil: true,
		},
		{
			name: "skin + rcversion only (bonus-signal 2-of-5 match)",
			resp: plainResp(),
			body: `<html><body>
        <div class="theme">/skins/elastic/styles.css</div>
        <script>rcmail.set_env({"rcversion":10608});</script>
    </body></html>`,
			wantNil:     false,
			wantVersion: "1.6.8",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:1.6.8:*:*:*:*:*:*:*",
		},
		{
			name: "relative skin path (real Shodan capture pattern)",
			resp: plainResp(),
			body: `<html><head>
  <title>Roundcube Webmail</title>
  <link rel="stylesheet" href="skins/elastic/deps/bootstrap.min.css">
  <script>rcmail.set_env({"rcversion":10608});</script>
</head></html>`,
			wantNil:     false,
			wantVersion: "1.6.8",
			wantSkin:    "elastic",
			wantCPE:     "cpe:2.3:a:roundcube:webmail:1.6.8:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RoundcubeFingerprinter{}
			result, err := fp.Fingerprint(tt.resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, "roundcube", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Equal(t, tt.wantSkin, result.Metadata["skin"])
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			// C3/C4: cookie value must never appear in metadata
			assert.NotContains(t, fmt.Sprintf("%v", result.Metadata), sessToken)
		})
	}
}

// --- TestSanitizeRoundcubeVersion ---

func TestSanitizeRoundcubeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "valid semver passes", version: "1.6.0", want: "1.6.0"},
		{name: "valid three-part version passes", version: "1.4.11", want: "1.4.11"},
		{name: "empty string rejected", version: "", want: ""},
		{name: "two-part version rejected", version: "1.6", want: ""},
		{name: "rc suffix rejected", version: "1.6.0-rc1", want: ""},
		{name: "semicolon injection rejected", version: "1.6.0; DROP", want: ""},
		{name: "17-char string exceeds length cap", version: "1.6.0000000000000", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeRoundcubeVersion(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- TestDecodeRoundcubeVersion ---

func TestDecodeRoundcubeVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "10411 decodes to 1.4.11", raw: "10411", want: "1.4.11"},
		{name: "10600 decodes to 1.6.0", raw: "10600", want: "1.6.0"},
		{name: "10608 decodes to 1.6.8", raw: "10608", want: "1.6.8"},
		{name: "999 below threshold returns empty", raw: "999", want: ""},
		{name: "empty string returns empty", raw: "", want: ""},
		{name: "non-numeric returns empty", raw: "abc", want: ""},
		{name: "20000 decodes to 2.0.0", raw: "20000", want: "2.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeRoundcubeVersion(tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- TestBuildRoundcubeCPE ---

func TestBuildRoundcubeCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "known version produces specific CPE",
			version: "1.6.0",
			want:    "cpe:2.3:a:roundcube:webmail:1.6.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:roundcube:webmail:*:*:*:*:*:*:*:*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRoundcubeCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
