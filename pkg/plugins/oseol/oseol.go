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

// Package oseol detects vendor-unsupported Ubuntu, Debian, RHEL, and CentOS
// versions from banners and CPE strings Nerva already collects. Ubuntu HTTP
// Server headers of the form Apache/x.y.z (Ubuntu) map to the shipping LTS
// the same way OpenSSH_X.YpZ Ubuntu banners already do. Debian Apache patch
// versions are not a release id (DSAs rewrite them); Debian needs +debN.
//
// End-of-life dates are the end of vendor standard/LTS security maintenance,
// not paid extras (Ubuntu Pro/ESM, Debian ELTS, RHEL ELS). Dates and sources
// come from the embedded, automatically refreshed snapshot. Do not invent dates.
package oseol

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// FindingID is the stable Nerva finding ID for non-RDP OS end-of-life.
// Windows via RDP continues to use rdp-eol-os.
const FindingID = "os-eol"

// now is the clock used to decide whether a release is past vendor EOL.
// Tests replace it; production uses time.Now.
var now = time.Now

type family string

const (
	familyUbuntu family = "ubuntu"
	familyDebian family = "debian"
	familyRHEL   family = "rhel"
	familyCentOS family = "centos"
)

type release struct {
	family  family
	version string
	name    string
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ubuntuOpenSSH maps OpenSSH_X.YpZ in an Ubuntu-tagged SSH banner to the LTS
// that shipped that OpenSSH (packages.ubuntu.com openssh source, one per LTS).
var ubuntuOpenSSH = map[string]string{
	"6.6": "14.04",
	"7.2": "16.04",
	"7.6": "18.04",
	"8.2": "20.04",
	"8.9": "22.04",
	"9.6": "24.04",
}

// ubuntuApache maps Apache/x.y.z in an Ubuntu-tagged HTTP Server header to the
// LTS that shipped that httpd (packages.ubuntu.com apache2, one per LTS).
// Ubuntu keeps the upstream Server version stable across security updates, so
// the three-digit version is a release id, unlike Debian where DSAs rewrite it.
var ubuntuApache = map[string]string{
	"2.4.7":  "14.04",
	"2.4.18": "16.04",
	"2.4.29": "18.04",
	"2.4.41": "20.04",
	"2.4.52": "22.04",
	"2.4.58": "24.04",
}

var (
	debVer       = regexp.MustCompile(`(?i)\+deb(\d+)`)
	elVer        = regexp.MustCompile(`(?i)\.el(\d+)(?:_\d+)?`)
	ubuntuY      = regexp.MustCompile(`(?i)ubuntu(?:0\.)?(?:[ /])?(\d{2}\.\d{2})`)
	sshOpen      = regexp.MustCompile(`(?i)OpenSSH_(\d+\.\d+)p`)
	centosH      = regexp.MustCompile(`(?i)\(CentOS(?: Linux)?(?:[ /](\d+))?\)`)
	rhelH        = regexp.MustCompile(`(?i)\(Red Hat(?: Enterprise Linux)?(?:[ /](\d+))?\)`)
	apache       = regexp.MustCompile(`(?i)Apache/(\d+\.\d+\.\d+)`)
	apacheUbuntu = regexp.MustCompile(`(?i)Apache/(\d+\.\d+\.\d+)\s*\(Ubuntu\)`)
)

// Check returns an os-eol finding when any of the texts identifies a
// vendor-unsupported Ubuntu, Debian, RHEL, or CentOS version. Unidentified
// or still-supported releases return nil.
func Check(texts ...string) *plugins.SecurityFinding {
	for _, text := range texts {
		if text == "" {
			continue
		}
		if len(text) > maxEvidenceBytes {
			text = text[:maxEvidenceBytes]
		}
		if rel, evidence := identify(text); rel != nil {
			identified := osEvidence{name: rel.name, method: "banner/CPE inference", text: evidence,
				candidates: []string{string(rel.family) + "/" + rel.version}}
			if finding := identified.finding(); finding != nil {
				return finding
			}
		}
	}
	return nil
}

// WindowsVersionUnsupported is the legacy RDP adapter. Windows evidence uses
// the same all-candidates assessment as every other OS; there is no Windows EOL engine.
func WindowsVersionUnsupported(version string) bool {
	evidence := windowsVersionEvidence(version, "")
	if evidence == nil {
		return false
	}
	_, unsupported := assessLifecycle(evidence.candidates)
	return unsupported
}

func identify(text string) (*release, string) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "cpe:") {
		return fromCPE(text)
	}
	if rel, ev := fromDebianDeb(text); rel != nil {
		return rel, ev
	}
	if rel, ev := fromUbuntuVersion(text); rel != nil {
		return rel, ev
	}
	if rel, ev := fromUbuntuSSH(text); rel != nil {
		return rel, ev
	}
	if rel, ev := fromUbuntuApache(text); rel != nil {
		return rel, ev
	}
	if rel, ev := fromHTTPDistro(text); rel != nil {
		return rel, ev
	}
	if rel, ev := fromELSuffix(text); rel != nil {
		return rel, ev
	}
	return nil, ""
}

func lookup(f family, version string) *release {
	vendor, product := linuxProduct(f)
	if vendor == "" || !versionToken.MatchString(version) {
		return nil
	}
	return &release{f, version, productName(vendor, product) + " " + version}
}

func fromCPE(text string) (*release, string) {
	part, vendor, product, version, valid := parseCPE(strings.TrimSpace(text))
	if !valid || part != "o" {
		return nil, ""
	}
	definition := findProduct(vendor, product)
	if definition == nil || definition.legacyFamily == "" {
		return nil, ""
	}
	if rel := lookup(definition.legacyFamily, definition.release(product, version)); rel != nil {
		return rel, text
	}
	return nil, ""
}

func ubuntuVersion(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) >= 2 && len(parts[0]) == 2 && len(parts[1]) == 2 {
		return parts[0] + "." + parts[1]
	}
	return ""
}

func major(v string) string {
	if i := strings.IndexAny(v, ".-"); i > 0 {
		v = v[:i]
	}
	if _, err := strconv.Atoi(v); err != nil {
		return ""
	}
	return v
}

func fromDebianDeb(text string) (*release, string) {
	m := debVer.FindStringSubmatch(text)
	if m == nil {
		return nil, ""
	}
	rel := lookup(familyDebian, m[1])
	if rel == nil {
		return nil, ""
	}
	return rel, m[0]
}

func fromUbuntuVersion(text string) (*release, string) {
	m := ubuntuY.FindStringSubmatch(text)
	if m == nil {
		return nil, ""
	}
	rel := lookup(familyUbuntu, m[1])
	if rel == nil {
		return nil, ""
	}
	return rel, m[0]
}

func fromUbuntuSSH(text string) (*release, string) {
	if !strings.Contains(strings.ToLower(text), "ubuntu") {
		return nil, ""
	}
	m := sshOpen.FindStringSubmatch(text)
	if m == nil {
		return nil, ""
	}
	ver, ok := ubuntuOpenSSH[m[1]]
	if !ok {
		return nil, ""
	}
	rel := lookup(familyUbuntu, ver)
	if rel == nil {
		return nil, ""
	}
	return rel, strings.TrimSpace(text)
}

func fromUbuntuApache(text string) (*release, string) {
	m := apacheUbuntu.FindStringSubmatch(text)
	if m == nil {
		return nil, ""
	}
	ver, ok := ubuntuApache[m[1]]
	if !ok {
		return nil, ""
	}
	rel := lookup(familyUbuntu, ver)
	if rel == nil {
		return nil, ""
	}
	return rel, m[0]
}

func fromHTTPDistro(text string) (*release, string) {
	if m := centosH.FindStringSubmatch(text); m != nil {
		ver := m[1]
		if ver == "" && apacheVersion(text) == "2.4.6" {
			ver = "7" // CentOS 7 shipped Apache 2.4.6
		}
		if ver == "" {
			return nil, ""
		}
		rel := lookup(familyCentOS, ver)
		if rel == nil {
			return nil, ""
		}
		return rel, m[0]
	}
	if m := rhelH.FindStringSubmatch(text); m != nil {
		ver := m[1]
		if ver == "" && apacheVersion(text) == "2.4.6" {
			ver = "7" // RHEL 7 shipped Apache 2.4.6
		}
		if ver == "" {
			return nil, ""
		}
		rel := lookup(familyRHEL, ver)
		if rel == nil {
			return nil, ""
		}
		return rel, m[0]
	}
	return nil, ""
}

func apacheVersion(text string) string {
	m := apache.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

func fromELSuffix(text string) (*release, string) {
	m := elVer.FindStringSubmatch(text)
	if m == nil {
		return nil, ""
	}
	// .elN is shared by RHEL rebuilds (Oracle, Rocky, Alma). Only emit when
	// the same text also names RHEL or CentOS; otherwise the family is unidentified.
	lower := strings.ToLower(text)
	var f family
	switch {
	case centosH.MatchString(text) || strings.Contains(lower, "centos"):
		f = familyCentOS
	case rhelH.MatchString(text) || strings.Contains(lower, "red hat") || strings.Contains(lower, "redhat"):
		f = familyRHEL
	default:
		return nil, ""
	}
	rel := lookup(f, m[1])
	if rel == nil {
		return nil, ""
	}
	return rel, m[0]
}
