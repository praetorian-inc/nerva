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
Package fingerprinters includes detection for Oracle Transportation Management (OTM / G-Log).

# What We Detect

Oracle Transportation Management is an enterprise logistics platform, historically
known as G-Log (the company Oracle acquired). It is hosted on Oracle WebLogic and
exposes a web UI via the "GC3" context root. The "glog" namespace in servlet class
names derives from the G-Log acquisition.

Instances are identified via the unauthenticated login page at:

	/GC3/glog.webserver.servlet.umt.Login

# Detection Strategy

Multiple corroborating signals are checked to avoid false positives. Detection
requires at least one "distinctive" signal — markers that are specific enough to
the OTM web tier that coincidental appearance is implausible:

  - glog.webserver.util.FrameGC3Servlet — Java class name unique to the OTM web tier
  - glog.integration.servlet — Java servlet namespace unique to OTM integration layer
  - <title> "Oracle Logistics" — page title specific to OTM login pages
  - "ORACLE TRANSPORTATION" and "GLOBAL TRADE MANAGEMENT" — the login heading
  - glogUrlContext / glogRawUrlContext — JavaScript variables emitted by the OTM web tier

The "glog.webserver.servlet.umt.Login" substring is the probe URL path itself and is
therefore reflection-prone: a server that echoes the request path will contain it.
It is intentionally NOT used as a detection signal at all — detection relies solely
on the distinctive body markers listed above.

# Version

OTM exposes no exact build number unauthenticated. A coarse era hint may be
extracted from the footer copyright year (e.g., "Copyright © 2001, 2016, Oracle
and/or its affiliates.") and stored in metadata["copyright_year"] alongside a
"version_note" key explaining the limitation. The CPE version field is always
left as the wildcard "*" since no reliable version can be confirmed.

# CPE

cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// otmTitleRegex matches the OTM login page <title> element, tolerant of
// attributes and surrounding whitespace.
var otmTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*Oracle Logistics\s*</title>`)

// otmCopyrightYearRegex extracts the last (end) year from an OTM footer
// copyright notice. Live raw HTML uses HTML entities:
//
//	Copyright &#169 2001&#44; 2016&#44; Oracle and/or its affiliates.
//
// The regex skips the copyright symbol (©, &#169;?, &copy;, (c)) then captures
// the trailing 4-digit year in a range like "2001, 2016".
var otmCopyrightYearRegex = regexp.MustCompile(
	`(?i)Copyright\s*(?:&#169;?|&copy;|©|\(c\))?\s*(?:\d{4}\s*(?:&#44;|,)\s*)*(\d{4})`,
)

// OracleOTMFingerprinter detects Oracle Transportation Management (OTM / G-Log)
// instances via the unauthenticated login page served at the GC3 context root.
type OracleOTMFingerprinter struct{}

func init() {
	Register(&OracleOTMFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OracleOTMFingerprinter) Name() string {
	return "oracle-otm"
}

// ProbeEndpoint returns the OTM login servlet path. This endpoint is
// unauthenticated and returns 200 text/html on live instances.
func (f *OracleOTMFingerprinter) ProbeEndpoint() string {
	return "/GC3/glog.webserver.servlet.umt.Login"
}

// ProbeAccept requests text/html explicitly to match what a browser would send
// to the OTM login page.
func (f *OracleOTMFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response status is in the 200–499 range and the
// Content-Type is text/html. Live OTM instances return 200 text/html.
func (f *OracleOTMFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full OTM detection against the login page body and
// extracts a coarse era hint from the footer copyright when available.
func (f *OracleOTMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	bodyStr := string(body)

	// Distinctive signals: each is specific enough to the OTM web tier that
	// coincidental appearance in a non-OTM page is implausible.
	hasFrameServlet := strings.Contains(bodyStr, "glog.webserver.util.FrameGC3Servlet")
	hasIntegrationServlet := strings.Contains(bodyStr, "glog.integration.servlet")
	hasOTMTitle := otmTitleRegex.MatchString(bodyStr)
	hasOTMHeading := strings.Contains(bodyStr, "ORACLE TRANSPORTATION") &&
		strings.Contains(bodyStr, "GLOBAL TRADE MANAGEMENT")
	hasGC3Context := strings.Contains(bodyStr, "glogUrlContext") ||
		strings.Contains(bodyStr, "glogRawUrlContext")

	detected := hasFrameServlet || hasIntegrationServlet || hasOTMTitle || hasOTMHeading || hasGC3Context
	if !detected {
		return nil, nil
	}

	// Version: OTM exposes no exact build number unauthenticated. Version is
	// always left empty; the CPE emits the wildcard form.
	version := ""

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Oracle Transportation Management",
		"detection_method": otmDetectionMethod(hasFrameServlet, hasIntegrationServlet, hasOTMHeading, hasGC3Context),
		"namespace":        "GC3",
	}

	// Best-effort era hint from the footer copyright end year.
	if matches := otmCopyrightYearRegex.FindStringSubmatch(bodyStr); matches != nil {
		yearStr := matches[1]
		if year, err := strconv.Atoi(yearStr); err == nil && year >= 1990 && year <= 2100 {
			metadata["copyright_year"] = yearStr
			metadata["version_note"] = "best-effort era hint from footer copyright; no exact build exposed unauthenticated"
		}
	}

	return &FingerprintResult{
		Technology: "oracle_otm",
		Version:    version,
		CPEs:       []string{buildOracleOTMCPE(version)},
		Metadata:   metadata,
	}, nil
}

// otmDetectionMethod returns the strongest matched signal name in priority order.
// The default (Oracle Logistics <title>) is the only distinctive signal that can
// remain once the others are ruled out, so no unreachable fallback is needed.
func otmDetectionMethod(hasFrameServlet, hasIntegrationServlet, hasOTMHeading, hasGC3Context bool) string {
	switch {
	case hasFrameServlet:
		return "frame_servlet"
	case hasIntegrationServlet:
		return "integration_servlet"
	case hasOTMHeading:
		return "otm_heading"
	case hasGC3Context:
		return "gc3_context"
	default:
		return "oracle_logistics_title"
	}
}

// buildOracleOTMCPE constructs a CPE 2.3 string for Oracle Transportation Management.
// NVD-verified tokens: vendor=oracle, product=transportation_management.
// When version is empty (always here), the wildcard form is emitted.
func buildOracleOTMCPE(version string) string {
	// Belt-and-suspenders: reject any version containing CPE special characters.
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}
	if version == "" {
		return "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:transportation_management:%s:*:*:*:*:*:*:*", version)
}
