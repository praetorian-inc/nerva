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
Telerik Report Server HTTP fingerprinter.

Detection model: active probe of the login page:
  - /Account/Login — renders <title>Telerik Report Server</title> unauthenticated

Closed-source product. Version is rarely exposed unauthenticated; opportunistic
regex captures build numbers from ASP.NET stack traces when customErrors=Off.

# CVE Context

Detection signals presence, not vulnerability. Version-to-CVE correlation is
performed by downstream tooling. The fingerprinter never sends an exploit payload.

  - CVE-2024-4358 (CVSS 9.8, CISA KEV): auth bypass via /Startup/Register
  - CVE-2024-1800: deserialization RCE (chain target for CVE-2024-4358)
  - CVE-2024-6327: additional deserialization RCE

/Startup/Register is explicitly OUT OF SCOPE for v1 per Phase 7 design decision.
Detection of Report Server presence via /Account/Login is the sole v1 signal.

Future work (unverified, not detected by this fingerprinter):
  - CVE-2025-3600, CVE-2026-2878 — signature unverified; excluded from v1.

# Active Probe Safety

GET /Account/Login is a static MVC login-page render. CVE-2024-4358 exploitation
requires GET /Startup/Register followed by POST with admin-creation fields. Our
probe differs on both path and method; it does not approach the exploit surface.
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	reportServerTitleMarker  = "<title>Telerik Report Server</title>"
	reportServerSSRSExclusion = "Microsoft SQL Server Reporting Services"
	reportServerBodyCap      = 2 * 1024 * 1024

	// maxTelerikVersionFieldLen is the maximum number of bytes accepted from an extracted version field.
	maxTelerikVersionFieldLen = 256
)

// telerikReportServerVersionRegex validates extracted version candidates.
// Anchored, requires at least 3 dotted components — matches both
// YYYY.Q.MMDD[.build] (modern) and MAJOR.MINOR.YY.MMDD (legacy) Report Server schemes.
var telerikReportServerVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?$`)

// telerikReportServerStackVersionRegex extracts build numbers from ASP.NET stack traces.
// Two alternating schemes: modern YYYY.Q.DDD[.N] and legacy MAJOR.MINOR.YY.MMDD.
// Longest alternative first to prevent short-circuit on overlapping inputs.
var telerikReportServerStackVersionRegex = regexp.MustCompile(
	`(\d{4}\.\d+\.\d{3,4}(?:\.\d+)?|\d+\.\d+\.\d{2}\.\d{3,4})`,
)

// TelerikReportServerFingerprinter detects Progress Telerik Report Server instances.
type TelerikReportServerFingerprinter struct{}

func init() {
	Register(&TelerikReportServerFingerprinter{})
}

func (f *TelerikReportServerFingerprinter) Name() string {
	return "telerik-report-server"
}

func (f *TelerikReportServerFingerprinter) ProbeEndpoint() string {
	return "/Account/Login"
}

// Match is a cheap pre-filter. It accepts 2xx-4xx responses with a text/html Content-Type.
func (f *TelerikReportServerFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// Fingerprint performs full detection. Returns (nil, nil) for every false-negative path.
func (f *TelerikReportServerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter (defense-in-depth; Fingerprint may be invoked without Match).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap.
	if len(body) > reportServerBodyCap {
		return nil, nil
	}

	// Gate 3: CPE-injection body guard.
	if bytes.Contains(body, []byte(":*:")) {
		return nil, nil
	}

	// Gate 4: require title marker (case-sensitive on product name, avoids SSRS).
	if !bytes.Contains(body, []byte(reportServerTitleMarker)) {
		return nil, nil
	}

	// Gate 5: defense-in-depth SSRS exclusion.
	if bytes.Contains(body, []byte(reportServerSSRSExclusion)) {
		return nil, nil
	}

	// Gate 6: defense-in-depth content-type check (Match also enforces this).
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil, nil
	}

	version := extractTelerikReportServerVersion(body)

	metadata := map[string]any{
		"vendor":         "Progress",
		"product":        "Telerik Report Server",
		"probe_endpoint": f.ProbeEndpoint(),
	}
	if version != "" {
		metadata["version_source"] = "stack_trace"
	}

	return &FingerprintResult{
		Technology: "telerik-report-server",
		Version:    version,
		CPEs:       []string{buildTelerikReportServerCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityInfo,
	}, nil
}

// extractTelerikReportServerVersion runs the opportunistic stack-trace extractor and
// re-validates the candidate against the anchored validator. Returns "" on no/invalid match.
func extractTelerikReportServerVersion(body []byte) string {
	m := telerikReportServerStackVersionRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if len(v) > maxTelerikVersionFieldLen {
		return ""
	}
	if !telerikReportServerVersionRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildTelerikReportServerCPE constructs a CPE 2.3 identifier for Progress Telerik Report Server.
// Vendor namespace is "progress" per NVD CVE-2024-4358. Empty or invalid version → wildcard.
func buildTelerikReportServerCPE(version string) string {
	if version == "" || !telerikReportServerVersionRegex.MatchString(version) {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:progress:telerik_report_server:%s:*:*:*:*:*:*:*", version)
}
