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
Package fingerprinters provides HTTP fingerprinting via inline JavaScript pattern matching.

# Detection Strategy

Many JS frameworks leave distinctive inline markers in the root HTML page:
global variable names, HTML attributes, data-* prefixes, and CDN URLs. This
fingerprinter scans the root "/" response body for these signals with zero
additional HTTP requests.

Byte signals are checked first via bytes.Contains (no regex overhead). Regex
signals are used only when a pattern requires structural matching (e.g.,
attribute prefixes or version extraction). All regexes are precompiled at
package initialization.

Signal definitions per framework:

  - Next.js:  __NEXT_DATA__, /_next/static
  - Nuxt.js:  __NUXT__, /_nuxt/
  - React:    data-reactroot, data-reactid, __REACT_DEVTOOLS_GLOBAL_HOOK__
  - Vue.js:   __VUE__, data-v-[a-f0-9]{7,8} attribute
  - Angular:  ng-version=" attribute, ng-version value extraction
  - Svelte:   __svelte global, class="...svelte-<hash> pattern
  - Shopify:  cdn.shopify.com, Shopify.shop
  - GTM:      googletagmanager.com/gtm.js

Fingerprint() returns nil when no signals match (not an error — the framework
is simply absent).
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Precompiled regexes for frameworks that require structural matching.
// Defined at package level to avoid per-call compilation overhead.
var (
	// angularVersionRegex extracts the version from ng-version="X.Y.Z".
	angularVersionRegex = regexp.MustCompile(`ng-version="(\d+\.\d+\.\d+)"`)

	// vueDataAttrRegex matches Vue's scoped CSS hash attributes (data-v-XXXXXXX).
	// The trailing non-hex lookahead prevents partial matches on longer hex runs
	// (e.g., 9-char hex strings must not match as 7 or 8 char substrings).
	vueDataAttrRegex = regexp.MustCompile(`data-v-[a-f0-9]{7,8}(?:[^a-f0-9]|$)`)

	// svelteClassRegex matches Svelte's generated scoped class names (svelte-XXXXX).
	// The lookahead requires the hash is immediately followed by a space, quote, or
	// end-of-string to avoid matching hyphenated English words like svelte-framework.
	svelteClassRegex = regexp.MustCompile(`class="[^"]*\bsvelte-[a-z0-9]+(?:["' ]|$)`)
)

// jsFrameworkSignature describes detection signals for a single JS framework.
type jsFrameworkSignature struct {
	// techName is the Technology field in FingerprintResult.
	techName string

	// vendor and product are used to build the CPE string.
	// If both are empty, no CPE is emitted (e.g., GTM has no NVD entry).
	vendor  string
	product string

	// byteSignals are literal byte strings checked via bytes.Contains.
	// Any match is sufficient.
	byteSignals [][]byte

	// regexSignals are compiled patterns checked against the full body string.
	// Any match is sufficient.
	regexSignals []*regexp.Regexp

	// versionRegex, when non-nil, is applied to extract a version string.
	// Group 1 is used as the version.
	versionRegex *regexp.Regexp
}

// jsFrameworkSignatures lists all frameworks to detect. The order does not
// affect correctness — each instance is an independent fingerprinter.
var jsFrameworkSignatures = []jsFrameworkSignature{
	{
		techName:    "nextjs",
		vendor:      "vercel",
		product:     "next.js",
		byteSignals: [][]byte{[]byte("__NEXT_DATA__"), []byte("/_next/static")},
	},
	{
		techName:    "nuxtjs",
		vendor:      "nuxtjs",
		product:     "nuxt.js",
		byteSignals: [][]byte{[]byte("__NUXT__"), []byte("/_nuxt/")},
	},
	{
		techName: "react",
		vendor:   "facebook",
		product:  "react",
		byteSignals: [][]byte{
			[]byte("data-reactroot"),
			[]byte("data-reactid"),
			[]byte("__REACT_DEVTOOLS_GLOBAL_HOOK__"),
		},
	},
	{
		techName:     "vuejs",
		vendor:       "vuejs",
		product:      "vue",
		byteSignals:  [][]byte{[]byte("__VUE__")},
		regexSignals: []*regexp.Regexp{vueDataAttrRegex},
	},
	{
		techName:     "angular",
		vendor:       "angular",
		product:      "angular",
		byteSignals:  [][]byte{[]byte(`ng-version="`)},
		versionRegex: angularVersionRegex,
	},
	{
		techName:     "svelte",
		vendor:       "svelte",
		product:      "svelte",
		byteSignals:  [][]byte{[]byte("__svelte")},
		regexSignals: []*regexp.Regexp{svelteClassRegex},
	},
	{
		techName:    "shopify",
		byteSignals: [][]byte{[]byte("cdn.shopify.com"), []byte("Shopify.shop")},
	},
	{
		// Google Tag Manager has no NVD CPE entry; vendor and product are left empty.
		// Only googletagmanager.com/gtm.js is used as the signal; dataLayer.push is
		// intentionally excluded because it is also emitted by GA4 (gtag.js) on pages
		// that do not load GTM at all, which would produce false positives.
		techName:    "google-tag-manager",
		byteSignals: [][]byte{[]byte("googletagmanager.com/gtm.js")},
	},
}

func init() {
	for i := range jsFrameworkSignatures {
		Register(&jsFrameworkFingerprinter{sig: jsFrameworkSignatures[i]})
	}
}

// jsFrameworkFingerprinter is a single-framework passive fingerprinter.
// One instance is registered per framework via init().
type jsFrameworkFingerprinter struct {
	sig jsFrameworkSignature
}

// Name returns a stable identifier for this fingerprinter.
func (f *jsFrameworkFingerprinter) Name() string {
	return "jsframework-" + f.sig.techName
}

// Match returns true when the response Content-Type contains "text/html".
// JS framework markers only appear in HTML pages; non-HTML responses (JSON,
// images, etc.) are skipped without reading the body.
func (f *jsFrameworkFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint scans the HTML body for framework-specific signals.
// Returns nil (no error) when the framework is not detected — the body does
// not contain the expected markers.
func (f *jsFrameworkFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) == 0 {
		return nil, nil
	}

	// Check byte signals first (faster than regex).
	detected := false
	for _, signal := range f.sig.byteSignals {
		if bytes.Contains(body, signal) {
			detected = true
			break
		}
	}

	// Check regex signals if not already confirmed by a byte hit.
	if !detected {
		for _, re := range f.sig.regexSignals {
			if re.Match(body) {
				detected = true
				break
			}
		}
	}

	if !detected {
		return nil, nil
	}

	version := ""
	if f.sig.versionRegex != nil {
		if m := f.sig.versionRegex.FindSubmatch(body); len(m) >= 2 {
			version = string(m[1])
		}
	}

	result := &FingerprintResult{
		Technology: f.sig.techName,
		Version:    version,
	}

	if f.sig.vendor != "" && f.sig.product != "" {
		result.CPEs = []string{buildJSFrameworkCPE(f.sig.vendor, f.sig.product, version)}
	}

	return result, nil
}

// buildJSFrameworkCPE formats a CPE 2.3 string for a JS framework.
// Version defaults to "*" when not extracted.
func buildJSFrameworkCPE(vendor, product, version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}
