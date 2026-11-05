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
Package fingerprinters provides HTTP fingerprinting for InterSystems IRIS.

# Detection Strategy

The management portal login is served at /csp/sys/UtilHome.csp. A match
requires the IRIS username field together with the product icon or the
"Login IRIS" title. The Apache Server header alone is not a match.

# Lab setup

Community Edition boots without a license key. Nothing is installed on the host.

	docker run -d --name iris --platform linux/arm64 \
	  -p 52773:52773 -p 1972:1972 \
	  intersystems/iris-community:latest-cd-linux-arm64

Wait until the log says "Private webserver started on 52773". The login form
is http://127.0.0.1:52773/csp/sys/UtilHome.csp. Fields are IRISUsername and
IRISPassword, plus the hidden IRISSessionToken from that same response. The
token is bound to the CSPSESSIONID cookie, so a login that drops the cookie
stays on the login page.

Shipped accounts are _SYSTEM:SYS and SuperUser:SYS. A hit on a fresh container
is the password-change page (title "Password change IRIS", field
IRISOldPassword). A wrong password stays on title "Login IRIS". The older
Cache pair system:sys is rejected. Password comparison is case-sensitive: SYS
works, sys does not.

# What We Do NOT Detect

Pages that merely mention InterSystems, and other CSP applications that
do not render the IRIS portal login.

# CPE

cpe:2.3:a:intersystems:iris:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"net/http"
	"strings"
)

// IRISFingerprinter detects the InterSystems IRIS management portal.
type IRISFingerprinter struct{}

func init() {
	Register(&IRISFingerprinter{})
}

func (f *IRISFingerprinter) Name() string {
	return "intersystems-iris"
}

func (f *IRISFingerprinter) ProbeEndpoint() string {
	return "/csp/sys/UtilHome.csp"
}

func (f *IRISFingerprinter) ProbeAccept() string {
	return "text/html"
}

func (f *IRISFingerprinter) Match(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 500
}

func (f *IRISFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	text := string(body)
	if !strings.Contains(text, `name="IRISUsername"`) {
		return nil, nil
	}
	if !strings.Contains(text, "ISC_IRIS_icon.ico") && !strings.Contains(text, "<title>Login IRIS</title>") {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "intersystems-iris",
		CPEs:       []string{"cpe:2.3:a:intersystems:iris:*:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"vendor":  "InterSystems",
			"product": "IRIS",
		},
	}, nil
}
