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
Package fingerprinters provides HTTP fingerprinting via robots.txt analysis.

# Detection Strategy

Many CMS platforms and web frameworks leave distinctive path patterns in their
robots.txt files. By matching known path signatures against the Disallow and Allow
directives, this fingerprinter identifies the underlying technology.

Detection requires multiple corroborating signals per technology to minimize false
positives. Single-path technologies (Ghost, Umbraco) use highly specific paths
that are unambiguous on their own.

Signatures (all matches against lowercase body):

WordPress: /wp-admin/ + one of /wp-includes/, /wp-content/, /wp-json/ (≥2 total)
Joomla:    /administrator/ + one of /components/, /modules/, /templates/
Drupal:    ≥2 of /core/, /profiles/, /modules/, /sites/default/files/, /misc/, /includes/, install|update|cron.php
Ghost:     /ghost/ (highly specific path)
Umbraco:   /umbraco/ (highly specific path)
Magento:   ≥2 of /catalog/, /checkout/, /customer/, /admin/, /downloader/
Laravel:   ≥2 of /storage/, /vendor/, /nova/
Django:    /admin/ + /static/ + sitemap: ... /sitemap.xml

Fingerprint() returns the first matching technology as the primary result.
Additional matches are stored in Metadata["other_detections"].
*/
package fingerprinters

import (
	"net/http"
	"regexp"
	"strings"
)

// RobotsTxtFingerprinter detects CMS and web frameworks via /robots.txt path patterns.
type RobotsTxtFingerprinter struct{}

// robotsSignature holds a technology name and a set of path regexes.
// matchThreshold controls how many of the patterns must match.
type robotsSignature struct {
	technology     string
	patterns       []*regexp.Regexp
	matchThreshold int
}

// robotsSignatures is the ordered list of signatures to check.
// More specific signatures (single unique path) are listed first to fail fast.
var robotsSignatures = []robotsSignature{
	{
		// /umbraco/ is highly specific; one match suffices.
		technology: "umbraco",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/umbraco/`),
		},
		matchThreshold: 1,
	},
	{
		// /ghost/ is highly specific; one match suffices.
		technology: "ghost",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/ghost/`),
		},
		matchThreshold: 1,
	},
	{
		// WordPress: wp-admin plus at least one other wp- path.
		technology: "wordpress",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/wp-admin/`),
			regexp.MustCompile(`/wp-includes/`),
			regexp.MustCompile(`/wp-content/`),
			regexp.MustCompile(`/wp-json/`),
		},
		matchThreshold: 2,
	},
	{
		// Joomla: /administrator/ plus at least one structural path.
		technology: "joomla",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/administrator/`),
			regexp.MustCompile(`/components/`),
			regexp.MustCompile(`/modules/`),
			regexp.MustCompile(`/templates/`),
		},
		matchThreshold: 2,
	},
	{
		// Drupal: at least two of its distinctive paths.
		technology: "drupal",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/core/`),
			regexp.MustCompile(`/profiles/`),
			regexp.MustCompile(`/modules/`),
			regexp.MustCompile(`/sites/default/files/`),
			regexp.MustCompile(`/misc/`),
			regexp.MustCompile(`/includes/`),
			regexp.MustCompile(`(?:install|update|cron)\.php`),
		},
		matchThreshold: 2,
	},
	{
		// Magento: at least two commerce-specific paths.
		technology: "magento",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/catalog/`),
			regexp.MustCompile(`/checkout/`),
			regexp.MustCompile(`/customer/`),
			regexp.MustCompile(`/admin/`),
			regexp.MustCompile(`/downloader/`),
		},
		matchThreshold: 2,
	},
	{
		// Laravel: at least two framework-specific paths.
		technology: "laravel",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/storage/`),
			regexp.MustCompile(`/vendor/`),
			regexp.MustCompile(`/nova/`),
		},
		matchThreshold: 2,
	},
	{
		// Django: /admin/ + /static/ + a sitemap directive pointing to /sitemap.xml.
		technology: "django",
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`/admin/`),
			regexp.MustCompile(`/static/`),
			regexp.MustCompile(`sitemap:.*?/sitemap\.xml`),
		},
		matchThreshold: 3,
	},
}

func init() {
	Register(&RobotsTxtFingerprinter{})
}

func (f *RobotsTxtFingerprinter) Name() string { return "robotstxt" }

func (f *RobotsTxtFingerprinter) ProbeEndpoint() string { return "/robots.txt" }

func (f *RobotsTxtFingerprinter) ProbeAccept() string { return "text/plain" }

// Match returns true for 200 responses with a text/plain or text/html Content-Type.
// Servers occasionally return robots.txt with text/html; we accept both.
func (f *RobotsTxtFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != 200 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/plain") || strings.Contains(ct, "text/html")
}

// Fingerprint checks the robots.txt body against known CMS signatures.
// It returns the first matching technology as the primary result.
// Additional matches are stored in Metadata["other_detections"].
func (f *RobotsTxtFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) == 0 {
		return nil, nil
	}

	content := strings.ToLower(string(body))

	// Quick sanity check: must contain at least one standard robots.txt directive.
	if !strings.Contains(content, "user-agent") &&
		!strings.Contains(content, "disallow") &&
		!strings.Contains(content, "allow") {
		return nil, nil
	}

	var primary *FingerprintResult
	var others []string

	for _, sig := range robotsSignatures {
		if matchesRobotsSignature(content, sig) {
			if primary == nil {
				primary = &FingerprintResult{
					Technology: sig.technology,
				}
			} else {
				others = append(others, sig.technology)
			}
		}
	}

	if primary == nil {
		return nil, nil
	}

	if len(others) > 0 {
		primary.Metadata = map[string]any{
			"other_detections": others,
		}
	}

	return primary, nil
}

// matchesRobotsSignature returns true when the number of matched patterns meets
// the signature's threshold.
func matchesRobotsSignature(content string, sig robotsSignature) bool {
	matched := 0
	for _, re := range sig.patterns {
		if re.MatchString(content) {
			matched++
			if matched >= sig.matchThreshold {
				return true
			}
		}
	}
	return false
}
