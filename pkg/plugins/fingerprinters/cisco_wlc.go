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
	"strings"
)

// CiscoWLCFingerprinter detects Cisco WLC (AireOS) and Aironet management UIs.
//
// Exclusive signals (generic Cisco HTML and ASA CSCOE/WebVPN must not match):
//
//  1. HTML title contains "wireless lan controller"
//  2. Body references /screens/frameset.html (AireOS WLC frameset)
//  3. HTML title contains "aironet"
//
// Each exclusive signal still requires a Cisco corroboration token. Product-name
// mentions in article body text are not exclusive.
type CiscoWLCFingerprinter struct{}

func init() {
	Register(&CiscoWLCFingerprinter{})
}

func (f *CiscoWLCFingerprinter) Name() string {
	return "cisco-wlc"
}

func (f *CiscoWLCFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func (f *CiscoWLCFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))
	title := strings.ToLower(extractHTMLTitle(body))
	hasCisco := strings.Contains(bodyLower, "cisco")
	if !hasCisco {
		return nil, nil
	}

	hasWLCTitle := strings.Contains(title, "wireless lan controller")
	hasFrameset := strings.Contains(bodyLower, `href="/screens/frameset.html`) ||
		strings.Contains(bodyLower, `src="/screens/frameset.html`) ||
		strings.Contains(bodyLower, `href='/screens/frameset.html`) ||
		strings.Contains(bodyLower, `src='/screens/frameset.html`) ||
		strings.Contains(bodyLower, `location='/screens/frameset.html`) ||
		strings.Contains(bodyLower, `location="/screens/frameset.html`)
	hasAironetTitle := strings.Contains(title, "aironet")

	switch {
	case hasWLCTitle || hasFrameset:
		return &FingerprintResult{
			Technology: "cisco-wlc",
			CPEs:       []string{"cpe:2.3:o:cisco:wireless_lan_controller_software:*:*:*:*:*:*:*:*"},
		}, nil
	case hasAironetTitle:
		return &FingerprintResult{
			Technology: "cisco-aironet",
			CPEs:       []string{"cpe:2.3:a:cisco:aironet_access_point_software:*:*:*:*:*:*:*:*"},
		}, nil
	default:
		return nil, nil
	}
}
