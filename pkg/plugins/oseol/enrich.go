package oseol

import (
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// Enrich preserves the plugin result, adding OS inventory and (when requested)
// lifecycle findings. Only documented protocol fields are considered evidence.
// It is idempotent so direct plugin and scan-engine callers can both use it.
func Enrich(service *plugins.Service, misconfigs bool) {
	if service == nil {
		return
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(service.Raw, &metadata) != nil || metadata == nil {
		return
	}
	var cpes []string
	_ = json.Unmarshal(metadata["cpes"], &cpes)
	texts := serviceOSTexts(service, metadata)
	observations, hasOSIdentification := identifyService(cpes, texts, service.Protocol)
	observations = consistentObservations(observations)

	for _, identified := range observations {
		cpe := identified.cpe()
		if !slices.Contains(cpes, cpe) {
			cpes = append(cpes, cpe)
		}
		if misconfigs {
			if finding := identified.finding(texts); finding != nil {
				addFinding(service, *finding)
			}
		}
	}
	if len(cpes) > 0 {
		metadata["cpes"], _ = json.Marshal(cpes)
		service.Raw, _ = json.Marshal(metadata)
	}
	if misconfigs && !hasOSIdentification {
		if evidence := identifyWindowsEvidence(service.Protocol, metadata, texts); evidence != nil {
			if finding := evidence.finding(); finding != nil {
				addFinding(service, *finding)
			}
		}
	}
}

func serviceOSTexts(service *plugins.Service, metadata map[string]json.RawMessage) []string {
	var texts []string
	read := func(key string) {
		var value string
		if json.Unmarshal(metadata[key], &value) == nil && value != "" {
			texts = append(texts, value)
		}
	}
	switch service.Protocol {
	case plugins.ProtoHTTP, plugins.ProtoHTTPS:
		var headers map[string][]string
		_ = json.Unmarshal(metadata["response_headers"], &headers)
		for name, values := range headers {
			if strings.EqualFold(name, "Server") {
				texts = append(texts, values...)
			}
		}
		var fingerprints map[string]map[string]json.RawMessage
		_ = json.Unmarshal(metadata["fingerprint_metadata"], &fingerprints)
		if php, ok := fingerprints["php"]; ok {
			var system string
			if json.Unmarshal(php["system"], &system) == nil {
				texts = append(texts, system)
			}
		}
	case plugins.ProtoSSH, plugins.ProtoFTP:
		read("banner")
	case plugins.ProtoRDP:
		read("fingerprint")
	case plugins.ProtoSNMP:
		read("description")
	case plugins.ProtoTelnet:
		var encoded string
		if json.Unmarshal(metadata["server_data"], &encoded) == nil {
			if decoded, err := hex.DecodeString(encoded); err == nil {
				texts = append(texts, string(decoded))
			}
		}
	}
	return texts
}

func consistentObservations(observations []observation) []observation {
	byProduct := make(map[string]observation)
	conflicts := make(map[string]bool)
	var order []string
	for _, identified := range observations {
		key := identified.vendor + ":" + identified.product
		if existing, ok := byProduct[key]; ok {
			if existing.version != identified.version {
				conflicts[key] = true
			} else if existing.method == "scanner CPE" && identified.method != "scanner CPE" {
				byProduct[key] = identified
			}
			continue
		}
		byProduct[key] = identified
		order = append(order, key)
	}
	// Different OS products on one service are conflicting host evidence too.
	if len(order) > 1 {
		return nil
	}
	var result []observation
	for _, key := range order {
		if !conflicts[key] {
			result = append(result, byProduct[key])
		}
	}
	return result
}

func ciscoRouterOrSwitch(texts []string) bool {
	text := strings.ToLower(strings.Join(texts, "\n"))
	if strings.Contains(text, "aironet") || strings.Contains(text, "access point") {
		return false
	}
	return strings.Contains(text, "router") || strings.Contains(text, "switch") || strings.Contains(text, "catalyst 9") || strings.Contains(text, "c9300") || strings.Contains(text, "c9500")
}

func addFinding(service *plugins.Service, finding plugins.SecurityFinding) {
	if service.Protocol == plugins.ProtoRDP {
		finding.ID = "rdp-eol-os"
	}
	for i, existing := range service.SecurityFindings {
		if existing.ID == finding.ID {
			// Prefer the lifecycle explanation, including its evidence and source,
			// over a legacy finding that Guard cannot preserve in full.
			if len(finding.Description) > len(existing.Description) {
				service.SecurityFindings[i] = finding
			}
			return
		}
	}
	service.SecurityFindings = append(service.SecurityFindings, finding)
}
