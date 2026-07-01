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
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// adminPathUserAgent is the User-Agent sent for admin path probe requests.
// Kept in sync with the value used by the HTTP service plugin.
const adminPathUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

// AdminPathFingerprinter probes common admin and login paths when --deep is
// enabled. It implements DeepHTTPFingerprinter but never matches on the root
// response -- it only runs via DeepProbe.
type AdminPathFingerprinter struct{}

type adminPathEntry struct {
	path        string
	technology  string
	slug        string
	description string
}

var adminPaths = []adminPathEntry{
	{path: "/wp-admin/", technology: "wordpress", slug: "wp-admin", description: "WordPress admin panel"},
	{path: "/wp-login.php", technology: "wordpress", slug: "wp-login", description: "WordPress login page"},
	{path: "/phpmyadmin/", technology: "phpmyadmin", slug: "phpmyadmin", description: "phpMyAdmin database interface"},
	{path: "/administrator/", technology: "joomla", slug: "administrator", description: "Joomla administrator panel"},
	{path: "/users/sign_in", technology: "gitlab", slug: "gitlab-sign-in", description: "GitLab login page"},
	{path: "/adminer.php", technology: "adminer", slug: "adminer", description: "Adminer database management"},
	{path: "/admin/", technology: "generic", slug: "admin", description: "Admin panel"},
	{path: "/login", technology: "generic", slug: "login", description: "Login page"},
}

func init() {
	Register(&AdminPathFingerprinter{})
}

func (f *AdminPathFingerprinter) Name() string { return "adminpath" }

// Match always returns false: this fingerprinter never matches on the root
// response. It only runs via DeepProbe.
func (f *AdminPathFingerprinter) Match(_ *http.Response) bool { return false }

// Fingerprint returns nil for the same reason as Match.
func (f *AdminPathFingerprinter) Fingerprint(_ *http.Response, _ []byte) (*FingerprintResult, error) {
	return nil, nil
}

// DeepProbe probes each admin path and returns findings for paths that respond
// with 200 or 302.
func (f *AdminPathFingerprinter) DeepProbe(client *http.Client, baseURL, host string) []plugins.SecurityFinding {
	// Canary probe: if the server responds 200/302 to a nonsense path, it's a
	// catch-all and all admin path findings would be false positives.
	canary := adminPathEntry{path: "/nerva-fp-canary-404", technology: "canary", slug: "canary", description: "canary"}
	if finding := probeAdminPath(client, baseURL, host, canary); finding != nil {
		return nil
	}

	var findings []plugins.SecurityFinding

	for _, entry := range adminPaths {
		finding := probeAdminPath(client, baseURL, host, entry)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// probeAdminPath makes a single GET request to baseURL+entry.path and returns
// a SecurityFinding if the response status is 200 or 302. Returns nil for all
// other status codes (404, 403, 5xx, etc.).
func probeAdminPath(client *http.Client, baseURL, host string, entry adminPathEntry) *plugins.SecurityFinding {
	url := baseURL + entry.path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", adminPathUserAgent)
	if host != "" && !strings.ContainsAny(host, "\r\n") {
		req.Host = host
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	// Drain body to allow connection reuse without leaking resources.
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return nil
	}

	evidence := fmt.Sprintf("path: %s | status: %s", entry.path, resp.Status)
	if resp.StatusCode == http.StatusFound {
		if loc := resp.Header.Get("Location"); loc != "" {
			if len(loc) > 512 {
				loc = loc[:512]
			}
			evidence += fmt.Sprintf(" | location: %s", loc)
		}
	}

	return &plugins.SecurityFinding{
		ID:          "http-admin-path-" + entry.slug,
		Severity:    plugins.SeverityInfo,
		Description: fmt.Sprintf("%s accessible at %s", entry.description, entry.path),
		Evidence:    evidence,
	}
}
