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
Telerik UI for ASP.NET AJAX HTTP fingerprinter.

Detection model: active probe of two distinctive resource handlers:
  - /Telerik.Web.UI.WebResource.axd?type=rau (RadAsyncUpload) — primary
  - /Telerik.Web.UI.DialogHandler.aspx (DialogHandler)        — fallback

Closed-source product. Version typically not extractable unauthenticated;
opportunistic regex captures Telerik.Web.UI Version=N from ASP.NET stack
traces when customErrors=Off (rare in production).

# CVE Context

Detection signals presence, not vulnerability. Version-to-CVE correlation is
performed by downstream tooling. The fingerprinter never sends an exploit payload.

  - CVE-2019-18935 (RadAsyncUpload deserialization, CVSS 9.8, CISA KEV)
  - CVE-2017-9248 (cryptographic weakness, CVSS 9.8, CISA KEV)

# Probe Safety

The rau probe is a plain GET /Telerik.Web.UI.WebResource.axd?type=rau with no
request body. CVE-2019-18935 deserialization is reached only when rauPostData and
supporting form fields are present in a POST body. The GET-only probe short-circuits
to the static JSON response before any JavaScriptSerializer.Deserialize call.

The DialogHandler probe is a plain GET /Telerik.Web.UI.DialogHandler.aspx with no
parameters. CVE-2017-9248 exploitation requires POST with a forged dp parameter;
our probe differs on both method and parameters.
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

// radAsyncUploadMarker is the exact body string returned by the rau handler since 2010.
// The misspelling of "successfully" is vendor-canonical and load-bearing — do not correct it.
const radAsyncUploadMarker = "RadAsyncUpload handler is registered succesfully"

const (
	dialogHandlerMarker1 = "Telerik.Web.UI.DialogHandler"
	dialogHandlerMarker2 = "dialogParametersHolder"
	telerikUIBodyCap     = 2 * 1024 * 1024
)

// telerikAJAXVersionRegex anchored validator: YYYY.Q.MMDD[.build], e.g. 2019.3.1023.
var telerikAJAXVersionRegex = regexp.MustCompile(`^\d{4}\.\d+\.\d+(\.\d+)?$`)

// telerikAJAXStackVersionRegex extracts a version from an ASP.NET stack trace when
// customErrors=Off surfaces the Telerik.Web.UI assembly version.
var telerikAJAXStackVersionRegex = regexp.MustCompile(`Telerik\.Web\.UI[, ]+Version=(\d{4}\.\d+\.\d+(?:\.\d+)?)`)

// TelerikRadAsyncUploadFingerprinter detects Telerik UI for ASP.NET AJAX via the
// RadAsyncUpload handler endpoint.
type TelerikRadAsyncUploadFingerprinter struct{}

// TelerikDialogHandlerFingerprinter detects Telerik UI for ASP.NET AJAX via the
// DialogHandler endpoint (fallback probe).
type TelerikDialogHandlerFingerprinter struct{}

func init() {
	Register(&TelerikRadAsyncUploadFingerprinter{})
	Register(&TelerikDialogHandlerFingerprinter{})
}

// --- TelerikRadAsyncUploadFingerprinter ---

func (f *TelerikRadAsyncUploadFingerprinter) Name() string {
	return "telerik-ui-aspnet-ajax-rau"
}

func (f *TelerikRadAsyncUploadFingerprinter) ProbeEndpoint() string {
	return "/Telerik.Web.UI.WebResource.axd?type=rau"
}

func (f *TelerikRadAsyncUploadFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func (f *TelerikRadAsyncUploadFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > telerikUIBodyCap {
		return nil, nil
	}
	if bytes.Contains(body, []byte(":*:")) {
		return nil, nil
	}
	if !bytes.Contains(body, []byte(radAsyncUploadMarker)) {
		return nil, nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	trimmed := strings.TrimSpace(string(body))
	if !strings.Contains(ct, "application/json") && !strings.HasPrefix(trimmed, "{") {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":         "Telerik",
		"product":        "Telerik UI for ASP.NET AJAX",
		"probe_endpoint": f.ProbeEndpoint(),
	}

	version := extractTelerikAJAXVersion(body)
	if version != "" {
		metadata["version_source"] = "stack_trace"
	}

	return &FingerprintResult{
		Technology: "telerik-ui-aspnet-ajax",
		Version:    version,
		CPEs:       []string{buildTelerikUICPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityInfo,
	}, nil
}

// --- TelerikDialogHandlerFingerprinter ---

func (f *TelerikDialogHandlerFingerprinter) Name() string {
	return "telerik-ui-aspnet-ajax-dialog"
}

func (f *TelerikDialogHandlerFingerprinter) ProbeEndpoint() string {
	return "/Telerik.Web.UI.DialogHandler.aspx"
}

func (f *TelerikDialogHandlerFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func (f *TelerikDialogHandlerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > telerikUIBodyCap {
		return nil, nil
	}
	if bytes.Contains(body, []byte(":*:")) {
		return nil, nil
	}
	if !bytes.Contains(body, []byte(dialogHandlerMarker1)) {
		return nil, nil
	}
	if !bytes.Contains(body, []byte(dialogHandlerMarker2)) {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":         "Telerik",
		"product":        "Telerik UI for ASP.NET AJAX",
		"probe_endpoint": f.ProbeEndpoint(),
	}

	version := extractTelerikAJAXVersion(body)
	if version != "" {
		metadata["version_source"] = "stack_trace"
	}

	return &FingerprintResult{
		Technology: "telerik-ui-aspnet-ajax",
		Version:    version,
		CPEs:       []string{buildTelerikUICPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityInfo,
	}, nil
}

// --- Shared helpers ---

// extractTelerikAJAXVersion extracts an assembly version from an ASP.NET stack trace
// body (only present when customErrors=Off). Returns empty string when absent or invalid.
func extractTelerikAJAXVersion(body []byte) string {
	m := telerikAJAXStackVersionRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if len(v) > maxTelerikVersionFieldLen {
		return ""
	}
	if !telerikAJAXVersionRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildTelerikUICPE constructs a CPE 2.3 identifier for Telerik UI for ASP.NET AJAX.
// NVD vendor namespace: telerik (per CVE-2019-18935). When version is empty or fails
// the anchored validator, the wildcard "*" is substituted.
func buildTelerikUICPE(version string) string {
	if version == "" || !telerikAJAXVersionRegex.MatchString(version) {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:telerik:ui_for_asp.net_ajax:%s:*:*:*:*:*:*:*", version)
}
