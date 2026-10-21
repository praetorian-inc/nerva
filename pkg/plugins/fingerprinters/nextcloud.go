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
Package fingerprinters provides HTTP fingerprinting for Nextcloud (and ownCloud).

# Detection Strategy

Unauthenticated GET /status.php returns JSON that names the product and version:

	{"installed":true,"maintenance":false,"version":"28.0.4.1","versionstring":"28.0.4","productname":"Nextcloud"}

That endpoint is stable across branding. Login HTML, titles, and /favicon.ico
are not — custom themes miss the favicon hash table and yield no CPE version.

productname selects Nextcloud vs ownCloud. version/versionstring populate CPE.

# What We Do NOT Detect

Generic JSON with an "installed" flag, themed login pages without status.php,
or favicon-only hits (those stay with FaviconFingerprinter).

# CPE

	cpe:2.3:a:nextcloud:nextcloud:{version}:*:*:*:*:*:*:*
	cpe:2.3:a:owncloud:owncloud:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type NextcloudFingerprinter struct{}

func init() { Register(&NextcloudFingerprinter{}) }

func (f *NextcloudFingerprinter) Name() string { return "nextcloud" }

func (f *NextcloudFingerprinter) ProbeEndpoint() string { return "/status.php" }

func (f *NextcloudFingerprinter) ProbeAccept() string { return "application/json" }

type nextcloudStatus struct {
	Installed      bool   `json:"installed"`
	Maintenance    bool   `json:"maintenance"`
	NeedsDbUpgrade bool   `json:"needsDbUpgrade"`
	Version        string `json:"version"`
	VersionString  string `json:"versionstring"`
	Edition        string `json:"edition"`
	ProductName    string `json:"productname"`
}

var nextcloudVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,4}$`)

const nextcloudMaxVersionLen = 32

func (f *NextcloudFingerprinter) Match(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "json")
}

func (f *NextcloudFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	var st nextcloudStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, nil
	}
	product := nextcloudProduct(st.ProductName)
	if product == "" {
		return nil, nil
	}
	version := sanitizeNextcloudVersion(st.VersionString)
	if version == "" {
		version = sanitizeNextcloudVersion(st.Version)
	}

	tech := "nextcloud"
	if product == "owncloud" {
		tech = "owncloud"
	}
	meta := map[string]any{
		"vendor":      productVendor(product),
		"product":     product,
		"installed":   st.Installed,
		"maintenance": st.Maintenance,
	}
	if st.Edition != "" {
		meta["edition"] = st.Edition
	}
	if st.Version != "" && sanitizeNextcloudVersion(st.Version) != "" {
		meta["version"] = sanitizeNextcloudVersion(st.Version)
	}

	return &FingerprintResult{
		Technology: tech,
		Version:    version,
		CPEs:       []string{buildNextcloudCPE(product, version)},
		Metadata:   meta,
	}, nil
}

func nextcloudProduct(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch {
	case n == "nextcloud" || strings.HasPrefix(n, "nextcloud "):
		return "nextcloud"
	case n == "owncloud" || strings.HasPrefix(n, "owncloud "):
		return "owncloud"
	default:
		return ""
	}
}

func productVendor(product string) string {
	if product == "owncloud" {
		return "ownCloud"
	}
	return "Nextcloud"
}

func sanitizeNextcloudVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > nextcloudMaxVersionLen {
		return ""
	}
	if strings.ContainsAny(v, ":*") {
		return ""
	}
	if !nextcloudVersionPattern.MatchString(v) {
		return ""
	}
	return v
}

func buildNextcloudCPE(product, version string) string {
	if version == "" {
		version = "*"
	}
	if product == "owncloud" {
		return fmt.Sprintf("cpe:2.3:a:owncloud:owncloud:%s:*:*:*:*:*:*:*", version)
	}
	return fmt.Sprintf("cpe:2.3:a:nextcloud:nextcloud:%s:*:*:*:*:*:*:*", version)
}
