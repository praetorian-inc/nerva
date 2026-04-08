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
Package fingerprinters provides HTTP fingerprinting for pgAdmin.

# Detection Strategy

pgAdmin is the most popular open-source PostgreSQL management UI. Exposed
instances represent a security concern due to:
  - Direct database management access
  - SQL query execution capabilities
  - Credential storage for database connections
  - Often exposed without authentication or with weak credentials

Two fingerprinters are provided:

PgAdminFingerprinter: Probes /misc/ping for definitive detection.
  - Body (trimmed) must be exactly "PING"
  - Response must contain a Set-Cookie header with "pga4_session"
  - Works in server mode only; does not extract version.

PgAdminLoginFingerprinter: Probes /login for version extraction.
  - Detects pgAdmin via "pgAdmin" string in HTML body
  - Extracts version from JS cache-busting parameter: ver=NNNNN
  - Version integer format: MAJOR*10000 + MINOR*100 + PATCH
  - Tested across pgAdmin 4.30, 5.7, 6.21, 7.8, 8.6, 9.14

# Response Format

The /misc/ping endpoint returns:

	HTTP/1.1 200 OK
	Content-Type: text/html; charset=utf-8
	Set-Cookie: pga4_session=UUID!hash; Expires=...; HttpOnly; Path=/; SameSite=Lax
	Server: gunicorn

	PING

The /login page contains version info in JS cache-busting parameters:

	<script src="/static/js/generated/pgadmin_commons.js?ver=91400"></script>

Where 91400 maps to version 9.14.0 (patch 0 is omitted: "9.14").

# Port Configuration

pgAdmin typically runs on:
  - 5050: Default pgAdmin HTTP port
  - 80:   HTTP in containerized deployments
  - 443:  HTTPS in production

# Auth Mode

The /misc/ping endpoint is only available in server mode (not desktop mode),
so detection via this endpoint always indicates server mode.

# Example Usage

	fp := &PgAdminFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s mode=%v\n", result.Technology, result.Metadata["mode"])
		}
	}

	lfp := &PgAdminLoginFingerprinter{}
	if lfp.Match(resp) {
		result, err := lfp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version=%s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// pgadminVersionRegex validates that a version string is safe to embed in a CPE.
// Accepts: "9.14", "8.6.1", "4.30"
var pgadminVersionRegex = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

// pgadminVerIntRegex extracts the version integer from JS cache-busting parameters.
// Matches patterns like: ver=91400, ver=62100, ver=80601
var pgadminVerIntRegex = regexp.MustCompile(`ver=(\d{5,6})`)

// PgAdminFingerprinter detects pgAdmin instances via /misc/ping endpoint
type PgAdminFingerprinter struct{}

func init() {
	Register(&PgAdminFingerprinter{})
	Register(&PgAdminLoginFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *PgAdminFingerprinter) Name() string { return "pgadmin" }

// ProbeEndpoint returns the endpoint to probe for pgAdmin detection.
func (f *PgAdminFingerprinter) ProbeEndpoint() string { return "/misc/ping" }

// Match returns true if the response Content-Type contains text/html.
// This is a fast pre-filter before the more expensive body check.
func (f *PgAdminFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// Fingerprint performs full pgAdmin detection.
// Both conditions must be met for a positive identification:
//  1. Body (trimmed) must be exactly "PING"
//  2. Response must have a Set-Cookie header containing "pga4_session"
func (f *PgAdminFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Body must be exactly "PING" after whitespace trimming
	if strings.TrimSpace(string(body)) != "PING" {
		return nil, nil
	}

	// Must have pgAdmin-specific session cookie.
	// Iterate over resp.Header["Set-Cookie"] (case-sensitive raw header access)
	// rather than resp.Header.Get("Set-Cookie") which only returns the first value.
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "pga4_session") {
			return &FingerprintResult{
				Technology: "pgadmin",
				CPEs:       []string{buildPgAdminCPE("")},
				Metadata: map[string]any{
					"mode": "server",
				},
			}, nil
		}
	}

	return nil, nil
}

func buildPgAdminCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:pgadmin:pgadmin:%s:*:*:*:*:*:*:*", version)
}

// PgAdminLoginFingerprinter detects pgAdmin instances via /login page and extracts version.
// The login page contains version information in JS cache-busting parameters of the form
// ver=NNNNN where the integer encodes: MAJOR*10000 + MINOR*100 + PATCH.
type PgAdminLoginFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *PgAdminLoginFingerprinter) Name() string { return "pgadmin-login" }

// ProbeEndpoint returns the login page endpoint.
func (f *PgAdminLoginFingerprinter) ProbeEndpoint() string { return "/login" }

// Match returns true if the response Content-Type contains text/html.
func (f *PgAdminLoginFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// Fingerprint detects pgAdmin via the login page and extracts the version.
// It requires both:
//  1. The body contains "pgAdmin" (present in the HTML title "pgAdmin 4")
//  2. The body contains a ver=NNNNN cache-busting parameter in a script tag
//
// The version integer is decoded as MAJOR*10000 + MINOR*100 + PATCH.
// Patch 0 is omitted: 91400 -> "9.14", 80601 -> "8.6.1".
func (f *PgAdminLoginFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Require pgAdmin marker to avoid false positives from pages with generic ver= params.
	if !strings.Contains(bodyStr, "pgAdmin") {
		return nil, nil
	}

	// Extract version integer from JS cache-busting parameter.
	matches := pgadminVerIntRegex.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return nil, nil
	}

	versionInt, err := strconv.Atoi(matches[1])
	if err != nil {
		return nil, nil
	}

	version := pgadminVersionFromInt(versionInt)

	// Validate version string before embedding in CPE.
	if !pgadminVersionRegex.MatchString(version) {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "pgadmin",
		Version:    version,
		CPEs:       []string{buildPgAdminCPE(version)},
	}, nil
}

// pgadminVersionFromInt converts a pgAdmin version integer to a version string.
// Format: MAJOR*10000 + MINOR*100 + PATCH
// Examples: 91400 -> "9.14", 80601 -> "8.6.1", 43000 -> "4.30"
func pgadminVersionFromInt(versionInt int) string {
	major := versionInt / 10000
	minor := (versionInt % 10000) / 100
	patch := versionInt % 100
	if patch == 0 {
		return fmt.Sprintf("%d.%d", major, minor)
	}
	return fmt.Sprintf("%d.%d.%d", major, minor, patch)
}
