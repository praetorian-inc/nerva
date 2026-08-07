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
	"regexp"
	"strings"
)

const papercutMaxBodySize = 1 << 20

// PaperCutFingerprinter detects PaperCut MF/NG print management instances.
//
// Detection Strategy:
//
// PaperCut MF and NG share the same web UI (built on the Tapestry framework) and
// are indistinguishable via HTTP, so both CPEs are always emitted together.
//
//  1. Standalone: HTML <title> contains "PaperCut" (case-insensitive). The title
//     is a reliable structural marker on the login page and admin UI.
//  2. Corroborated: body contains "papercut" (case-insensitive) AND the Tapestry
//     URL pattern "?service=page/" — both required together, since "papercut"
//     alone can appear in unrelated documentation or prose.
//
// Version Detection:
// PaperCut does not expose a version unauthenticated, so Version is always "".
//
// CPE:
//
//	cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*
//	cpe:2.3:a:papercut:papercut_ng:*:*:*:*:*:*:*:*
type PaperCutFingerprinter struct{}

func init() {
	Register(&PaperCutFingerprinter{})
}

// papercutTitleRegex matches the PaperCut <title> tag, case-insensitively.
// Precompiled to avoid per-call allocation.
var papercutTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*papercut[^<]*</title>`)

func (f *PaperCutFingerprinter) Name() string {
	return "papercut"
}

// ProbeEndpoint returns the PaperCut web UI application root.
func (f *PaperCutFingerprinter) ProbeEndpoint() string {
	return "/app"
}

func (f *PaperCutFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match accepts 200-499 responses with a text/html content type.
func (f *PaperCutFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a PaperCut instance.
// Returns nil, nil for non-matching responses.
func (f *PaperCutFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return nil, nil
	}

	if len(body) > papercutMaxBodySize {
		body = body[:papercutMaxBodySize]
	}

	// Signal 1 (standalone): <title> contains "papercut".
	standalone := papercutTitleRegex.Match(body)

	// Signal 2 (corroborated): "papercut" brand in body AND Tapestry service page pattern.
	bodyStr := string(body)
	corroborated := strings.Contains(bodyStr, "?service=page/") && strings.Contains(strings.ToLower(bodyStr), "papercut")

	if !standalone && !corroborated {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "papercut",
		Version:    "",
		CPEs: []string{
			"cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:papercut:papercut_ng:*:*:*:*:*:*:*:*",
		},
		Metadata: map[string]any{
			"vendor":  "PaperCut",
			"product": "PaperCut MF/NG",
		},
	}, nil
}
