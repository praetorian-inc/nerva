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
// Detection uses exclusive Instant signals plus corroboration so generic HTML
// (and other Aruba products such as AirWave) cannot match:
//
//  1. Exclusive: /swarm.cgi, Instant UI JS (raphael-treemap.min.js),
//     instant.arubanetworks.com, title "Aruba Instant" or "Instant Access Point"
//  2. Corroboration: Aruba/arubanetworks brand, or a second exclusive signal
//
// Brand mention alone is not sufficient. Favicon aruba-networks is not Instant.
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

	hasSwarmCGI := strings.Contains(bodyLower, "swarm.cgi")
	hasRaphaelTreemap := strings.Contains(bodyLower, "raphael-treemap.min.js")
	hasInstantHost := strings.Contains(bodyLower, "instant.arubanetworks.com")
	titleArubaInstant := strings.Contains(title, "aruba instant")
	titleInstantAP := strings.Contains(title, "instant access point")
	hasArubaBrand := strings.Contains(bodyLower, "aruba")

	exclusiveCount := 0
	for _, signal := range []bool{hasSwarmCGI, hasRaphaelTreemap, hasInstantHost, titleArubaInstant, titleInstantAP} {
		if signal {
			exclusiveCount++
		}
	}
	if exclusiveCount == 0 {
		return nil, nil
	}
	if !hasArubaBrand && exclusiveCount < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "aruba-instant",
		CPEs:       []string{"cpe:2.3:a:arubanetworks:aruba_instant:*:*:*:*:*:*:*:*"},
	}, nil
}
