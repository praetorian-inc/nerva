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

// This probe is called SCCM despite Microsoft having
// renamed SCCM now three times.
// SCCM itself has more parts than the management point, however I have not found a quick way of verifying those components without authentication.

package fingerprinters

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func init() {
	Register(&SCCMManagementPointFingerprinter{})
}

func buildSCCMCPEs(rel, site string) []string {
	v := rel
	if v == "" {
		v = "*"
	}

	out := []string{
		// The old ones use just the release version
		fmt.Sprintf("cpe:2.3:a:microsoft:system_center_configuration_manager:%s:*:*:*:*:*:*:*", v),
		fmt.Sprintf("cpe:2.3:a:microsoft:endpoint_configuration_manager:%s:*:*:*:*:*:*:*", v),
	}

	// The new one uses both the release version
	// and site version
	if rel != "" && site != "" {
		out = append(out, fmt.Sprintf("cpe:2.3:a:microsoft:configuration_manager_%s:%s:*:*:*:*:*:*:*", rel, site))
	}

	return out
}

// sccmReleaseFromBuild maps the 4-digit site build (the <Version> value in an
// mplist response, e.g. "9128") to its marketing release.
//
// Based on
// https://learn.microsoft.com/en-us/intune/configmgr/core/servers/manage/updates
// https://www.prajwaldesai.com/sccm-versions-build-numbers-console-client/
func sccmReleaseFromBuild(build string) string {
	switch build {
	case "7711":
		return "2012"
	case "7804":
		return "2012 SP1"
	case "7958":
		return "2012 R2"
	case "8239":
		return "2012 R2 SP1"
	case "8325":
		return "1511"
	case "8355":
		return "1602"
	case "8412":
		return "1606"
	case "8458":
		return "1610"
	case "8498":
		return "1702"
	case "8540":
		return "1706"
	case "8577":
		return "1710"
	case "8634":
		return "1802"
	case "8692":
		return "1806"
	case "8740":
		return "1810"
	case "8790":
		return "1902"
	case "8853":
		return "1906"
	case "8913":
		return "1910"
	case "8968":
		return "2002"
	case "9012":
		return "2006"
	case "9040":
		return "2010"
	case "9049":
		return "2103"
	case "9058":
		return "2107"
	case "9068":
		return "2111"
	case "9078":
		return "2203"
	case "9088":
		return "2207"
	case "9096":
		return "2211"
	case "9106":
		return "2303"
	case "9122":
		return "2309"
	case "9128":
		return "2403"
	case "9132":
		return "2409"
	default:
		return ""
	}
}

// versionFromBuild resolves the build
// to the release version and the site version
func versionFromBuild(build string) (string, string) {
	if build == "" {
		return "", "*"
	}

	rel := sccmReleaseFromBuild(build)
	if rel == "" {
		return "", "*"
	}

	return rel, "5.00." + build // Always starts with 5.00
}

// --- Management Point ---------------------------------------------------------

// SCCMManagementPointFingerprinter detects an SCCM/MEMCM management point via the
// anonymous mplist endpoint.
type SCCMManagementPointFingerprinter struct{}

func (f *SCCMManagementPointFingerprinter) Name() string { return "sccm-mp" }

func (f *SCCMManagementPointFingerprinter) ProbeEndpoint() string {
	return "/sms_mp/.sms_aut?mplist"
}

func (f *SCCMManagementPointFingerprinter) ProbeAccept() string {
	return "*/*"
}

func (f *SCCMManagementPointFingerprinter) Match(resp *http.Response) bool {
	// Trigger on IIS
	return strings.Contains(resp.Header.Get("Server"), "Microsoft-IIS")
}

type sccmMPList struct {
	XMLName xml.Name `xml:"MPList"`
	MPs     []struct {
		Name         string `xml:"Name,attr"`
		FQDN         string `xml:"FQDN,attr"`
		SiteCode     string `xml:"SiteCode,attr"`
		Version      string `xml:"Version"`
		Capabilities struct {
			Properties []struct {
				Name  string `xml:"Name,attr"`
				Value string `xml:"Value,attr"`
			} `xml:"Property"`
		} `xml:"Capabilities"`
	} `xml:"MP"`
}

var mpVersionRe = regexp.MustCompile(`<Version>\s*(\d+)\s*</Version>`)

func (f *SCCMManagementPointFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "<MPList") {
		return nil, nil
	}

	build := ""
	names := []string{}
	siteCode := ""

	var list sccmMPList
	if err := xml.Unmarshal(body, &list); err == nil && len(list.MPs) > 0 {
		for _, mp := range list.MPs {
			if build == "" && mp.Version != "" {
				build = strings.TrimSpace(mp.Version)
			}

			if siteCode == "" && mp.SiteCode != "" {
				siteCode = mp.SiteCode
			}

			if mp.FQDN != "" {
				names = append(names, mp.FQDN)
			} else if mp.Name != "" {
				names = append(names, mp.Name)
			}
		}
	}

	// Fallback when the document is technically malformed but recognizable.
	// exp: build == 9106
	if build == "" {
		if m := mpVersionRe.FindStringSubmatch(bodyStr); m != nil {
			build = m[1]
		}
	}

	rel, siteVersion := versionFromBuild(build)

	meta := map[string]any{
		"vendor":  "Microsoft",
		"product": "System Center Configuration Manager (SCCM) - Management Point",
	}

	if build != "" {
		meta["build_number"] = build
		meta["site_version"] = siteVersion
	}

	if rel != "" {
		meta["release"] = rel
	}

	if siteCode != "" {
		meta["site_code"] = siteCode
	}

	if len(names) > 0 {
		meta["management_points"] = names
	}

	return &FingerprintResult{
		Technology: "sccm-mp",
		Version:    siteVersion,
		CPEs:       buildSCCMCPEs(rel, siteVersion),
		Metadata:   meta,
	}, nil
}
