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
Package fingerprinters provides HTTP fingerprinting for SHOUTcast DNAS.

# Detection Strategy

DNAS identifies itself on the admin endpoint. GET /admin.cgi returns
Server: Shoutcast DNAS and, when authentication is required,
WWW-Authenticate: Basic realm="Shoutcast Server". The listener port can
also send icy-notice1 containing "Shoutcast DNAS".

The product name in a page title or in unrelated HTML is not enough.
Documentation and comparison pages mention SHOUTcast without running it.

# Lab setup

Download sc_serv2_linux_x64-latest.tar.gz from download.nullsoft.com and extract it.
The shipped examples/sc_serv_simple.conf sets adminpassword=changeme. The binary
will not start without a config, and setup mode does not embed that password.

	docker run -d --name shoutcast --platform linux/amd64 -p 8000:8000 \
	  -v "$PWD":/opt/sc:ro debian:bookworm-slim \
	  /opt/sc/sc_serv /opt/sc/examples/sc_serv_simple.conf

GET /admin.cgi with no Authorization is 401, realm "Shoutcast Server", and
Server: Shoutcast DNAS. admin:changeme is 200 with title "Shoutcast Server
Administrator". A wrong password is 401. The listener root often omits the
Server header and sends icy-notice1 instead.

# What We Do NOT Detect

Icecast, other streaming servers, and pages that only discuss SHOUTcast.
A Server header that merely contains the substring is not a match; the
leading product token must be "Shoutcast DNAS".

# CPE

cpe:2.3:a:shoutcast:dnas:<version>:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// shoutcastServerRe matches the leading Server product token emitted by DNAS.
var shoutcastServerRe = regexp.MustCompile(`(?i)^shoutcast dnas\b`)

// shoutcastVersionRe extracts a dotted version from a DNAS banner.
var shoutcastVersionRe = regexp.MustCompile(`(?i)\bv(\d+\.\d+(?:\.\d+){0,2})\b`)

// shoutcastVersionValidRe rejects versions that are not safe to place in a CPE.
var shoutcastVersionValidRe = regexp.MustCompile(`^\d+\.\d+(?:\.\d+){0,2}$`)

// ShoutcastFingerprinter detects SHOUTcast DNAS.
type ShoutcastFingerprinter struct{}

func init() {
	Register(&ShoutcastFingerprinter{})
}

func (f *ShoutcastFingerprinter) Name() string {
	return "shoutcast"
}

// ProbeEndpoint is the admin page. The listener root often omits the Server header.
func (f *ShoutcastFingerprinter) ProbeEndpoint() string {
	return "/admin.cgi"
}

// ProbeAccept asks for the HTML admin page rather than the JSON default.
func (f *ShoutcastFingerprinter) ProbeAccept() string {
	return "text/html"
}

func (f *ShoutcastFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return shoutcastSignal(resp)
}

func (f *ShoutcastFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if !shoutcastSignal(resp) {
		return nil, nil
	}
	server := resp.Header.Get("Server")
	version := shoutcastVersion(server, resp.Header.Get("Icy-Notice1"), string(body))
	return &FingerprintResult{
		Technology: "shoutcast",
		Version:    version,
		CPEs:       []string{shoutcastCPE(version)},
		Metadata: map[string]any{
			"vendor":        "SHOUTcast",
			"product":       "DNAS",
			"server_header": server,
		},
	}, nil
}

func shoutcastSignal(resp *http.Response) bool {
	if shoutcastServerRe.MatchString(strings.TrimSpace(resp.Header.Get("Server"))) {
		return true
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Icy-Notice1")), "shoutcast dnas") {
		return true
	}
	auth := strings.ToLower(resp.Header.Get("Www-Authenticate"))
	return strings.Contains(auth, `realm="shoutcast`) || strings.Contains(auth, "realm=shoutcast")
}

func shoutcastVersion(parts ...string) string {
	for _, part := range parts {
		m := shoutcastVersionRe.FindStringSubmatch(part)
		if len(m) < 2 || !shoutcastVersionValidRe.MatchString(m[1]) {
			continue
		}
		return m[1]
	}
	return ""
}

func shoutcastCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:shoutcast:dnas:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:shoutcast:dnas:%s:*:*:*:*:*:*:*", version)
}
