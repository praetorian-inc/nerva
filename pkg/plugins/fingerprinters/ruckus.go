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

// RuckusFingerprinter detects Ruckus Unleashed, ZoneDirector, and SmartZone
// management UIs.
//
// Exclusive signals (generic HTML and brand-only pages must not match):
//
//  1. Title "Unleashed Login" — Unleashed panel (nuclei/Shodan marker)
//  2. "zonedirector" plus Ruckus corroboration
//  3. "smartzone" plus Ruckus corroboration
//  4. Title "Ruckus Wireless Admin" plus Ruckus corroboration
//
// /admin/login.jsp alone is not exclusive.
type RuckusFingerprinter struct{}

func init() {
	Register(&RuckusFingerprinter{})
}

func (f *RuckusFingerprinter) Name() string {
	return "ruckus"
}

func (f *RuckusFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func (f *RuckusFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))
	title := strings.ToLower(extractHTMLTitle(body))
	hasRuckus := strings.Contains(bodyLower, "ruckus")

	switch {
	case strings.Contains(title, "unleashed login"):
		return ruckusResult("cpe:2.3:o:ruckuswireless:unleashed_firmware:*:*:*:*:*:*:*:*"), nil
	case strings.Contains(bodyLower, "zonedirector") && hasRuckus:
		return ruckusResult("cpe:2.3:o:ruckuswireless:zonedirector_firmware:*:*:*:*:*:*:*:*"), nil
	case strings.Contains(bodyLower, "smartzone") && hasRuckus:
		return ruckusResult("cpe:2.3:a:ruckuswireless:smartzone:*:*:*:*:*:*:*:*"), nil
	case strings.Contains(title, "ruckus wireless admin") && hasRuckus:
		return ruckusResult("cpe:2.3:o:ruckuswireless:zonedirector_firmware:*:*:*:*:*:*:*:*"), nil
	default:
		return nil, nil
	}
}

func ruckusResult(cpe string) *FingerprintResult {
	return &FingerprintResult{
		Technology: "ruckus",
		CPEs:       []string{cpe},
	}
}
