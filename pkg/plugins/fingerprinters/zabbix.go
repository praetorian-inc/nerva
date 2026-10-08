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
Package fingerprinters provides HTTP fingerprinting for Zabbix.

# Detection Strategy

The sign-in page is served at / and /index.php. A match requires the
Zabbix SIA author marker or the sign-in form together with a Zabbix title.
A page that only mentions Zabbix is not a match.

# Lab setup

The appliance image boots the server, database, and web UI in one container.
Nothing is installed on the host.

	docker run -d --name zabbix --platform linux/amd64 -p 80:80 zabbix/zabbix-appliance

Wait until http://127.0.0.1/index.php shows the sign-in form. Fields are
name and password. Admin:zabbix returns 302 to zabbix.php?action=dashboard.view.
The username is case-sensitive: admin:zabbix fails. Verified on appliance 4.4.6.
Current Zabbix still posts those fields to /index.php.

# What We Do NOT Detect

Pages that mention Zabbix without the sign-in form or the Zabbix SIA author
marker.

# CPE

cpe:2.3:a:zabbix:zabbix:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"net/http"
	"strings"
)

// ZabbixFingerprinter detects the Zabbix web UI.
type ZabbixFingerprinter struct{}

func init() {
	Register(&ZabbixFingerprinter{})
}

func (f *ZabbixFingerprinter) Name() string {
	return "zabbix"
}

func (f *ZabbixFingerprinter) ProbeEndpoint() string {
	return "/index.php"
}

func (f *ZabbixFingerprinter) ProbeAccept() string {
	return "text/html"
}

func (f *ZabbixFingerprinter) Match(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (f *ZabbixFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, nil
	}
	text := string(body)
	if !zabbixPage(text) {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "zabbix",
		CPEs:       []string{"cpe:2.3:a:zabbix:zabbix:*:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"vendor":  "Zabbix",
			"product": "Zabbix",
		},
	}, nil
}

func zabbixPage(text string) bool {
	hasTitle := strings.Contains(text, "<title>Zabbix") || strings.Contains(text, "Zabbix SIA")
	hasForm := strings.Contains(text, `name="name"`) && strings.Contains(text, `name="password"`)
	return hasTitle && (hasForm || strings.Contains(text, "Zabbix SIA"))
}
