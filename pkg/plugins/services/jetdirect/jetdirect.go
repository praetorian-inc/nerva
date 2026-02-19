// Package jetdirect implements JetDirect/PJL printer detection.
//
// Detection Strategy:
// Phase 1: Send UEL + PJL INFO ID probe to identify PJL-aware printers.
//   - The UEL escape sequence (\x1b%-12345X) resets the printer to PJL mode.
//   - @PJL INFO ID requests the printer's identification string.
//   - Valid responses contain @PJL INFO ID followed by a quoted model string.
//
// Phase 2: Enrichment (best-effort, failures do not affect detection):
//   - @PJL INFO STATUS for printer status code
//   - @PJL FSDIRLIST to detect filesystem access (security finding)
//
// Default port: 9100 (also 9101, 9102 for additional print channels)
//
// Wire Protocol Reference:
//   - HP PJL Technical Reference Manual
//   - UEL: ESC%-12345X (hex: 1B 25 2D 31 32 33 34 35 58)
package jetdirect

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	JETDIRECT = "jetdirect"
)

// UEL (Universal Exit Language) escape sequence
var uel = []byte("\x1b%-12345X")

// PJL probe: UEL + INFO ID + UEL
var pjlInfoIDProbe = append(append(append([]byte{}, uel...), []byte("@PJL INFO ID\r\n")...), uel...)

// pjlInfoIDQuoted matches @PJL INFO ID response with quoted ID (e.g., "HP LaserJet 4250")
var pjlInfoIDQuoted = regexp.MustCompile(`@PJL INFO ID\r?\n"([^"]+)"`)

// pjlInfoIDUnquoted matches @PJL INFO ID response with unquoted ID (e.g., hp LaserJet 4200)
var pjlInfoIDUnquoted = regexp.MustCompile(`@PJL INFO ID\r?\n([^\r\n]+)`)

// Vendor extraction patterns (ordered by specificity)
var vendorPatterns = []struct {
	vendor  string
	pattern *regexp.Regexp
}{
	{"hp", regexp.MustCompile(`(?i)^HP\s+(.+)`)},
	{"brother", regexp.MustCompile(`(?i)^Brother\s+(.+)`)},
	{"ricoh", regexp.MustCompile(`(?i)^RICOH\s+(.+)`)},
	{"canon", regexp.MustCompile(`(?i)^Canon\s+(.+)`)},
	{"xerox", regexp.MustCompile(`(?i)^Xerox\s+(.+)`)},
	{"lexmark", regexp.MustCompile(`(?i)^Lexmark\s+(.+)`)},
	{"epson", regexp.MustCompile(`(?i)^EPSON\s+(.+)`)},
	{"samsung", regexp.MustCompile(`(?i)^Samsung\s+(.+)`)},
	{"konica_minolta", regexp.MustCompile(`(?i)^KONICA MINOLTA\s+(.+)`)},
	{"kyocera", regexp.MustCompile(`(?i)^KYOCERA\s+(.+)`)},
	{"sharp", regexp.MustCompile(`(?i)^SHARP\s+(.+)`)},
	{"oki", regexp.MustCompile(`(?i)^OKI\s+(.+)`)},
	{"dell", regexp.MustCompile(`(?i)^Dell\s+(.+)`)},
	{"toshiba", regexp.MustCompile(`(?i)^TOSHIBA\s+(.+)`)},
	{"zebra", regexp.MustCompile(`(?i)^Zebra\s+(.+)`)},
	{"pantum", regexp.MustCompile(`(?i)^Pantum\s+(.+)`)},
}

// firmwarePattern extracts firmware version from Brother-style IDs (e.g., "Ver.b.26")
var firmwarePattern = regexp.MustCompile(`Ver\.([a-zA-Z0-9.]+)`)

// pjlStatusPattern extracts DISPLAY value from PJL INFO STATUS response
var pjlStatusPattern = regexp.MustCompile(`DISPLAY="([^"]*)"`)


// JetDirectPlugin implements the fingerprintx Plugin interface for JetDirect/PJL detection.
type JetDirectPlugin struct{}

func init() {
	plugins.RegisterPlugin(&JetDirectPlugin{})
}

// detectPJL checks if the response contains a valid PJL INFO ID response.
// Returns true and the extracted ID string if detected, false and empty string otherwise.
func detectPJL(response []byte) (bool, string) {
	if len(response) == 0 {
		return false, ""
	}
	// Try quoted format first (more specific)
	matches := pjlInfoIDQuoted.FindSubmatch(response)
	if len(matches) >= 2 {
		return true, string(matches[1])
	}
	// Fall back to unquoted format
	matches = pjlInfoIDUnquoted.FindSubmatch(response)
	if len(matches) >= 2 {
		return true, strings.TrimSpace(string(matches[1]))
	}
	return false, ""
}

// extractVendorModel parses the INFO ID string to extract vendor and model.
func extractVendorModel(id string) (vendor, model string) {
	// Strip colon-delimited suffixes (Brother format: "Model:Serial:Ver.x.y")
	parts := strings.SplitN(id, ":", 2)
	cleanID := strings.TrimSpace(parts[0])

	for _, vp := range vendorPatterns {
		matches := vp.pattern.FindStringSubmatch(cleanID)
		if len(matches) >= 2 {
			return vp.vendor, strings.TrimSpace(matches[1])
		}
	}
	return "", cleanID
}

// extractFirmware extracts firmware version from the full INFO ID string.
func extractFirmware(id string) string {
	matches := firmwarePattern.FindStringSubmatch(id)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// normalizeModel converts a model string to CPE-safe format.
// Example: "LaserJet 4250" -> "laserjet_4250"
func normalizeModel(model string) string {
	m := strings.ToLower(model)
	m = strings.TrimSuffix(m, " series")
	m = strings.ReplaceAll(m, " ", "_")
	m = strings.ReplaceAll(m, "-", "_")
	return m
}

// buildJetDirectCPE generates a hardware CPE for the printer.
// Format: cpe:2.3:h:{vendor}:{model}:{firmware}:*:*:*:*:*:*:*
func buildJetDirectCPE(vendor, model, firmware string) string {
	if vendor == "" || model == "" {
		return ""
	}
	normModel := normalizeModel(model)
	ver := firmware
	if ver == "" {
		ver = "*"
	}
	return fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendor, normModel, ver)
}

// enrichStatus sends PJL INFO STATUS and extracts status string.
func enrichStatus(conn net.Conn, timeout time.Duration) string {
	probe := append(append(append([]byte{}, uel...), []byte("@PJL INFO STATUS\r\n")...), uel...)
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil || len(response) == 0 {
		return ""
	}
	// Look for DISPLAY="..." in response
	matches := pjlStatusPattern.FindSubmatch(response)
	if len(matches) >= 2 {
		return string(matches[1])
	}
	return ""
}

// pjlFirmwareConfigPattern extracts firmware version from PJL INFO CONFIG response
// Matches patterns like: FIRMWARE DATECODE=20150327 or FIRMWARE=V4.2.1
var pjlFirmwareConfigPattern = regexp.MustCompile(`(?i)FIRMWARE(?:\s+DATECODE)?[=\s]+([^\r\n]+)`)

// enrichFirmwareFromConfig sends PJL INFO CONFIG and extracts firmware version.
// This is useful for HP printers that don't include firmware in INFO ID.
func enrichFirmwareFromConfig(conn net.Conn, timeout time.Duration) string {
	probe := append(append(append([]byte{}, uel...), []byte("@PJL INFO CONFIG\r\n")...), uel...)
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil || len(response) == 0 {
		return ""
	}
	matches := pjlFirmwareConfigPattern.FindSubmatch(response)
	if len(matches) >= 2 {
		return strings.TrimSpace(string(matches[1]))
	}
	return ""
}

// enrichFilesystemAccess sends PJL FSDIRLIST and returns true if filesystem is accessible.
func enrichFilesystemAccess(conn net.Conn, timeout time.Duration) bool {
	probe := append(append(append([]byte{}, uel...), []byte("@PJL FSDIRLIST NAME=\"0:\\\" COUNT=1\r\n")...), uel...)
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil || len(response) == 0 {
		return false
	}
	respStr := string(response)
	// Successful directory listing contains ENTRY or TYPE= markers
	return strings.Contains(respStr, "ENTRY") || strings.Contains(respStr, "TYPE=")
}

// Run implements the Plugin interface. Sends PJL INFO ID probe and returns service if detected.
func (p *JetDirectPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Detection - Send PJL INFO ID probe
	response, err := utils.SendRecv(conn, pjlInfoIDProbe, timeout)
	if err != nil {
		return nil, err
	}

	detected, rawID := detectPJL(response)
	if !detected {
		return nil, nil
	}

	// Phase 2: Enrichment
	vendor, model := extractVendorModel(rawID)
	firmware := extractFirmware(rawID)
	// If firmware not in ID string, try INFO CONFIG (common for HP)
	if firmware == "" {
		firmware = enrichFirmwareFromConfig(conn, timeout)
	}
	cpe := buildJetDirectCPE(vendor, model, firmware)

	status := enrichStatus(conn, timeout)
	fsAccess := enrichFilesystemAccess(conn, timeout)

	payload := plugins.ServiceJetDirect{
		Manufacturer:     vendor,
		Model:            model,
		Firmware:         firmware,
		RawID:            rawID,
		Status:           status,
		FilesystemAccess: fsAccess,
	}

	if cpe != "" {
		payload.CPEs = []string{cpe}
	}

	version := firmware
	if version == "" && model != "" {
		version = model
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

// PortPriority returns true for the standard JetDirect ports.
func (p *JetDirectPlugin) PortPriority(port uint16) bool {
	return port == 9100 || port == 9101 || port == 9102
}

// Name returns the protocol name.
func (p *JetDirectPlugin) Name() string {
	return JETDIRECT
}

// Type returns TCP as the transport protocol.
func (p *JetDirectPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin priority. Port 9100 is exclusive to JetDirect.
func (p *JetDirectPlugin) Priority() int {
	return 100
}
