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
Package fingerprinters provides HTTP fingerprinting for Doccano.

# Detection Strategy

DoccanoFingerprinter is a passive HTTP fingerprinter that detects Doccano
instances by matching HTML body content against four signals:
 1. HTML <title> tag containing "doccano" (case-insensitive)
 2. Meta description matching the canonical Doccano marketing string
 3. A div with id="__nuxt" (Nuxt.js SPA container)
 4. window.__NUXT__ runtime object (Nuxt.js hydration marker)

Detection fires when at least 2 of 4 signals match, reducing false positives
from generic Nuxt.js apps (which trigger signals 3 and/or 4 without 1 or 2).

# Why Passive

Doccano's login page at /auth/login and root / are publicly accessible.
The detection signals appear in the unauthenticated HTML response, so no
active probing of additional endpoints is required.

# Why No Version Extraction

Following the mlflow.go precedent for versionless fingerprinters: Doccano's
Nuxt.js SPA does not expose version information in unauthenticated HTTP
responses. Version strings appear only in authenticated API responses or
build artifacts, making reliable passive extraction impossible. The CPE uses
a wildcard version component ("*") per the mlflow.go pattern.

# Signal Gate (≥2 of 4)

Requiring at least two independent signals prevents false positives from:
  - Generic Nuxt.js apps (id="__nuxt" + window.__NUXT__ without doccano title/meta)
  - Pages that mention "doccano" in prose (title without Nuxt markers)
  - Non-Doccano annotation tools with similar meta descriptions
*/
package fingerprinters

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	doccanoTitlePattern           = regexp.MustCompile(`(?i)<title[^>]{0,200}>[^<]{0,200}doccano[^<]{0,200}</title>`)
	doccanoMetaDescriptionPattern = regexp.MustCompile(`(?i)doccano\s+is\s+an\s+open\s+source\s+annotation\s+tools?\s+for\s+machine\s+learning`)
	doccanoNuxtContainerPattern   = regexp.MustCompile(`id=["']__nuxt["']`)
	doccanoNuxtRuntimePattern     = regexp.MustCompile(`window\.__NUXT__`)
)

// DoccanoFingerprinter detects Doccano annotation tool instances via HTML body signals.
type DoccanoFingerprinter struct{}

func init() {
	Register(&DoccanoFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *DoccanoFingerprinter) Name() string { return "doccano" }

// Match returns true for HTML responses (or empty Content-Type) that may be Doccano.
// Returns false immediately if resp is nil.
func (f *DoccanoFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// Fingerprint detects Doccano by counting body signals. Returns nil if resp is nil,
// body is empty, or fewer than 2 of 4 signals match.
func (f *DoccanoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || len(body) == 0 {
		return nil, nil
	}

	signals := 0
	if doccanoTitlePattern.Match(body) {
		signals++
	}
	if doccanoMetaDescriptionPattern.Match(body) {
		signals++
	}
	if doccanoNuxtContainerPattern.Match(body) {
		signals++
	}
	if doccanoNuxtRuntimePattern.Match(body) {
		signals++
	}

	if signals < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "doccano",
		Version:    "",
		CPEs:       []string{"cpe:2.3:a:doccano:doccano:*:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"frontend":   "nuxt",
			"login_path": "/auth/login",
		},
	}, nil
}
