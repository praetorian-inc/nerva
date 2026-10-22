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

// ArubaInstantFingerprinter detects Aruba Instant AP management UIs.
//
// Detection requires a management-UI marker so generic HTML, reseller pages,
// and externally hosted captive-portal splash pages cannot match:
//
//  1. HTML title "Aruba Instant" or "Instant Access Point"
//  2. Instant UI script raphael-treemap.min.js
//  3. form posting to /swarm.cgi plus (1) or (2)
//
// A body link to instant.arubanetworks.com or swarm.cgi plus the word Aruba
// is not enough. Favicon aruba-networks is not Instant.
type ArubaInstantFingerprinter struct{}

func init() {
	Register(&ArubaInstantFingerprinter{})
}

func (f *ArubaInstantFingerprinter) Name() string {
	return "aruba-instant"
}

func (f *ArubaInstantFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func (f *ArubaInstantFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))
	title := strings.ToLower(extractHTMLTitle(body))

	hasInstantTitle := strings.Contains(title, "aruba instant") || strings.Contains(title, "instant access point")
	hasTreemapJS := strings.Contains(bodyLower, "raphael-treemap.min.js") &&
		(strings.Contains(bodyLower, `src="`) || strings.Contains(bodyLower, `src='`))
	if !hasInstantTitle && !hasTreemapJS {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "aruba-instant",
		CPEs:       []string{"cpe:2.3:o:arubanetworks:instant:*:*:*:*:*:*:*:*"},
	}, nil
}
