package oseol

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// IIS and NTLM identify candidate OS families, not a guaranteed edition/SKU.
// This file only decodes that evidence; assessment.go owns every EOL decision.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
var legacyWindows = map[string]struct {
	name       string
	candidates []string
}{
	"5.0": {"Windows 2000", []string{"windows-server/2000"}},
	"5.1": {"Windows XP", []string{"windows/5"}},
	"5.2": {"Windows Server 2003 / 2003 R2 or Windows XP x64", []string{"windows-server/2003", "windows-server/2003-r2", "windows/5"}},
	"6.0": {"Windows Server 2008 or Windows Vista", []string{"windows-server/2008", "windows/6"}},
	"6.1": {"Windows Server 2008 R2 or Windows 7", []string{"windows-server/2008-r2", "windows/7"}},
	"6.2": {"Windows Server 2012 or Windows 8", []string{"windows-server/2012", "windows/8"}},
	"6.3": {"Windows Server 2012 R2 or Windows 8.1", []string{"windows-server/2012-r2", "windows/8.1"}},
}

var iisWindows = map[string]string{"6.0": "5.2", "7.0": "6.0", "7.5": "6.1", "8.0": "6.2", "8.5": "6.3"}
var iisVersion = regexp.MustCompile(`(?i)\bMicrosoft-IIS/(\d+\.\d+)\b`)
var ntlmVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func identifyWindowsEvidence(protocol string, metadata map[string]json.RawMessage, texts []string) *osEvidence {
	var version, evidence string
	switch protocol {
	case plugins.ProtoHTTP, plugins.ProtoHTTPS:
		version, evidence = identifyIIS(texts)
	case plugins.ProtoSMB, plugins.ProtoRDP:
		var reported string
		if json.Unmarshal(metadata["os_version"], &reported) == nil && len(reported) <= maxEvidenceBytes && strings.Count(reported, ".") == 2 {
			version, evidence = reported, "NTLM version "+reported
		}
	}
	return windowsVersionEvidence(version, evidence)
}

func identifyIIS(texts []string) (version, evidence string) {
	for _, text := range texts {
		if len(text) > maxEvidenceBytes {
			text = text[:maxEvidenceBytes]
		}
		for _, match := range iisVersion.FindAllStringSubmatch(text, -1) {
			candidate, known := iisWindows[match[1]]
			if !known || (version != "" && version != candidate) {
				return "", "" // Conflicting/unknown versions must not be last-wins.
			}
			version, evidence = candidate, match[0]
		}
	}
	return
}

func windowsVersionEvidence(version, evidence string) *osEvidence {
	if len(version) > maxEvidenceBytes {
		return nil
	}
	if strings.Count(version, ".") == 2 {
		if !ntlmVersion.MatchString(version) {
			return nil
		}
		version = minorRelease(version)
	}
	candidate, ok := legacyWindows[version]
	if !ok {
		return nil // In particular, IIS 10 / NT 10 identifies too many releases.
	}
	return &osEvidence{
		name: candidate.name, method: "service-version inference", text: evidence,
		candidates: candidate.candidates, ambiguous: true,
	}
}
