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
Package fingerprinters provides HTTP fingerprinting for Express.js applications.

# Detection Strategy

Express.js is the most popular Node.js web framework. Exposed applications
may represent a security concern due to:
  - Default error pages leaking internal paths in dev mode
  - Stack traces exposing application structure and dependencies
  - Misconfigured security headers

Detection uses a two-signal approach:

Signal 1 (passive): X-Powered-By header on any HTTP response
  - Header value "Express" (case-sensitive) indicates Express.js
  - Many production apps disable this header via app.disable("x-powered-by")

Signal 2 (active): Default error page pattern on probed non-existent path
  - GET /nerva-fp-nonexistent-path triggers Express's default 404 handler
  - Response body contains "Cannot GET /" — unique to Express's finalhandler
  - Status code 404, Content-Type: text/html

Signal 3 (enrichment): Dev mode detection via stack traces
  - Development mode (NODE_ENV=development) returns full stack traces
  - Patterns: "at " followed by file paths or "Error:" with stack frames
  - Stored as devMode: true in metadata — indicates a security concern

# Response Headers

Express production mode:

	X-Powered-By: Express
	Content-Type: text/html; charset=utf-8

Express default 404 body:

	<!DOCTYPE html>
	<html lang="en">
	<head>
	<meta charset="utf-8">
	<title>Error</title>
	</head>
	<body>
	<pre>Cannot GET /nerva-fp-nonexistent-path</pre>
	</body>
	</html>

Express dev mode 404 body (includes stack trace):

	<pre>NotFoundError: Not Found<br>    at /app/node_modules/express/lib/router/index.js:12:15</pre>

# Port Configuration

Express.js typically runs on:
  - 3000: Default development port
  - 8080: Common alternative
  - 80:   HTTP production
  - 443:  HTTPS production

# Example Usage

	fp := &ExpressFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s devMode: %v\n",
				result.Technology, result.Version, result.Metadata["devMode"])
		}
	}
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// expressVersionRegex matches Express version in stack traces.
// Patterns: express@4.21.0, express@5.0.0
var expressVersionRegex = regexp.MustCompile(`express@(\d+\.\d+\.\d+)`)

// expressStackTraceRegex detects stack trace lines in dev mode error responses.
// Matches patterns like "at /path/to/file.js:12:15" or "at Function.handle (/path/)"
var expressStackTraceRegex = regexp.MustCompile(`\bat\s+(?:\S+\s+)?\(?\S+\.js:\d+`)

// ExpressFingerprinter detects Express.js applications via X-Powered-By header
// and default error page body patterns.
type ExpressFingerprinter struct{}

func init() {
	Register(&ExpressFingerprinter{})
}

func (f *ExpressFingerprinter) Name() string {
	return "expressjs"
}

// ProbeEndpoint returns the path used for active detection.
// Express's default 404 handler produces a distinctive HTML error page
// with "Cannot GET /<path>" that is unique to Express.
func (f *ExpressFingerprinter) ProbeEndpoint() string {
	return "/nerva-fp-nonexistent-path"
}

// Match returns true if this fingerprinter should attempt detection.
// Called once for the root "/" response (passive) and once for the
// probe "/nerva-fp-nonexistent-path" response (active).
//
// Returns true if:
//  1. X-Powered-By header contains "Express" (case-sensitive), OR
//  2. Status is 404 AND Content-Type is text/html (allows Fingerprint to
//     validate the Express error page body)
func (f *ExpressFingerprinter) Match(resp *http.Response) bool {
	// Signal 1: X-Powered-By header (passive, immediate confirmation)
	if strings.Contains(resp.Header.Get("X-Powered-By"), "Express") {
		return true
	}

	// Signal 2: 404 with text/html — may be Express default error page.
	// Fingerprint() will validate the body contains "Cannot GET /"
	if resp.StatusCode == 404 && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts Express.js metadata.
// Must validate the actual Express signature before returning a result,
// since Match() may produce false positives (e.g., any 404 text/html page).
func (f *ExpressFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)

	hasPoweredByHeader := strings.Contains(resp.Header.Get("X-Powered-By"), "Express")
	hasErrorPageBody := bytes.Contains(body, []byte("Cannot GET /"))

	// Must have at least one confirmed Express signal
	if !hasPoweredByHeader && !hasErrorPageBody {
		return nil, nil
	}

	// Store X-Powered-By value in metadata if present
	if hasPoweredByHeader {
		metadata["poweredBy"] = resp.Header.Get("X-Powered-By")
	}

	// Signal 3: Dev mode detection via stack traces
	bodyStr := string(body)
	if expressStackTraceRegex.MatchString(bodyStr) {
		metadata["devMode"] = true
	}

	// Version extraction from stack traces (e.g., express@4.21.0)
	version := ""
	if matches := expressVersionRegex.FindStringSubmatch(bodyStr); len(matches) == 2 {
		version = matches[1]
	}

	return &FingerprintResult{
		Technology: "expressjs",
		Version:    version,
		CPEs:       []string{buildExpressCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildExpressCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:expressjs:express:%s:*:*:*:*:*:*:*", version)
}
