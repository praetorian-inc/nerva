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
	name, end string
}{
	"5.0": {"Windows 2000", "2010-07-13"},
	"5.1": {"Windows XP", "2014-04-08"},
	"5.2": {"Windows Server 2003 / 2003 R2 or Windows XP x64", "2015-07-14"},
	"6.0": {"Windows Server 2008 or Windows Vista", "2020-01-14"},
	"6.1": {"Windows Server 2008 R2 or Windows 7", "2020-01-14"},
	"6.2": {"Windows Server 2012 or Windows 8", "2023-10-10"},
	"6.3": {"Windows Server 2012 R2 or Windows 8.1", "2023-10-10"},
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
	end, _ := time.Parse("2006-01-02", candidate.end)
	if now().Before(end.AddDate(0, 0, 1)) {
		return nil
	}
	id := FindingID
	if service.Protocol == plugins.ProtoRDP {
		id = "rdp-eol-os"
	}
	return &plugins.SecurityFinding{
		ID: id, Severity: plugins.SeverityLow,
		Description: fmt.Sprintf("Service indicates an end-of-life Windows release: %s. This is an inference, not an authenticated OS identification; the exact edition is unresolved. All listed candidates ended ordinary security support by %s; paid extended support is not determined. Evidence: %s. Lifecycle: https://learn.microsoft.com/en-us/lifecycle/products/", candidate.name, candidate.end, evidence),
		Evidence:    evidence,
	}
}
