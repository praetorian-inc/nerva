package oseol

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// IIS versions and NTLM versions identify sets of Windows releases, not always
// one SKU. Only report EOL when every candidate is past ordinary security support.
// Do not turn those sets into a fabricated single-product OS CPE.
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

func windowsFinding(service *plugins.Service, metadata map[string]json.RawMessage, texts []string) *plugins.SecurityFinding {
	var version, evidence string
	switch service.Protocol {
	case plugins.ProtoHTTP, plugins.ProtoHTTPS:
		for _, text := range texts {
			if match := iisVersion.FindStringSubmatch(text); match != nil {
				version, evidence = iisWindows[match[1]], match[0]
			}
		}
	case plugins.ProtoSMB, plugins.ProtoRDP:
		var reported string
		if json.Unmarshal(metadata["os_version"], &reported) == nil && versionToken.MatchString(reported) {
			parts := strings.Split(reported, ".")
			if len(parts) == 3 {
				version = strings.Join(parts[:2], ".")
				evidence = "NTLM version " + reported
			}
		}
	}
	candidate, ok := legacyWindows[version]
	if !ok {
		return nil // In particular, IIS 10.0 / NT 10.0 is not an EOL verdict.
	}
	end := latestWindowsSupportEnd(candidate.candidates)
	if end.IsZero() || now().Before(end) {
		return nil
	}
	id := FindingID
	if service.Protocol == plugins.ProtoRDP {
		id = "rdp-eol-os"
	}
	return &plugins.SecurityFinding{
		ID: id, Severity: plugins.SeverityLow,
		Description: fmt.Sprintf("Service indicates an end-of-life Windows release: %s. This is an inference, not an authenticated OS identification; the exact edition is unresolved. All listed candidates ended ordinary security support by %s; paid extended support is not determined. Evidence: %s. Lifecycle: https://learn.microsoft.com/en-us/lifecycle/products/", candidate.name, end.AddDate(0, 0, -1).Format(time.DateOnly), evidence),
		Evidence:    evidence,
	}
}

// WindowsVersionUnsupported checks an identified NT version against the refreshed
// support dates for every candidate OS. It does not identify an edition or SKU.
func WindowsVersionUnsupported(version string) bool {
	candidate, ok := legacyWindows[version]
	if !ok {
		return false
	}
	end := latestWindowsSupportEnd(candidate.candidates)
	return !end.IsZero() && !now().Before(end)
}

func latestWindowsSupportEnd(candidates []string) time.Time {
	var latest time.Time
	for _, candidate := range candidates {
		product, version, _ := strings.Cut(candidate, "/")
		end, _ := lifecycleEnd(product, version)
		if end.IsZero() {
			return time.Time{} // Every possible release must have a known cutoff.
		}
		if end.After(latest) {
			latest = end
		}
	}
	return latest
}
