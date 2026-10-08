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

/*
Package fingerprinters provides HTTP fingerprinting for CUPS.

# Detection Strategy

CUPS sends Server: CUPS/<version> IPP/2.1 on the web interface, including
the open root page and the admin pages. The leading product token must be
"CUPS". A page that only mentions CUPS is not a match.

# Lab setup

The widely used container image bakes in an admin account. Upstream CUPS
does not. Nothing is installed on the host.

	docker run -d --name cups --platform linux/amd64 -p 631:631 olbat/cupsd

The web UI is http://127.0.0.1:631/. GET /admin is open. GET /admin/conf
and GET /admin/log challenge with Basic realm="CUPS". The image user is
print:print. A wrong password is 401. Server is "CUPS/2.4 IPP/2.1" on
CUPS 2.4.18.

# What We Do NOT Detect

Printers that speak IPP but do not send a CUPS Server header, and pages
that mention CUPS without that header.

# CPE

cpe:2.3:a:openprinting:cups:<version>:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var cupsServerRe = regexp.MustCompile(`(?i)^CUPS/(\d+\.\d+(?:\.\d+){0,2})\b`)

// CUPSFingerprinter detects the CUPS web interface.
type CUPSFingerprinter struct{}

func init() {
	Register(&CUPSFingerprinter{})
}

func (f *CUPSFingerprinter) Name() string {
	return "cups"
}

func (f *CUPSFingerprinter) Match(resp *http.Response) bool {
	return resp != nil && cupsServerRe.MatchString(strings.TrimSpace(resp.Header.Get("Server")))
}

func (f *CUPSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, nil
	}
	m := cupsServerRe.FindStringSubmatch(strings.TrimSpace(resp.Header.Get("Server")))
	if len(m) < 2 {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "cups",
		Version:    m[1],
		CPEs:       []string{fmt.Sprintf("cpe:2.3:a:openprinting:cups:%s:*:*:*:*:*:*:*", m[1])},
		Metadata: map[string]any{
			"vendor":  "OpenPrinting",
			"product": "CUPS",
		},
	}, nil
}
