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

// Package managesieve provides fingerprinting for the ManageSieve (RFC 5804)
// protocol used to remotely manage Sieve mail filtering scripts.
//
// ManageSieve servers send a multi-line greeting immediately upon connection
// (typically on TCP port 4190). Each capability line is a quoted keyword,
// optionally followed by a quoted value, terminated by CRLF. The greeting
// ends with an untagged OK response. Detection is passive — no probe is sent.
//
// Protocol reference: https://www.rfc-editor.org/rfc/rfc5804
package managesieve

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// MANAGESIEVE is the protocol identifier for ManageSieve.
const MANAGESIEVE = "managesieve"

const (
	manageSieveDefaultPort = 4190
	manageSievePriority    = 150
)

// ManageSievePlugin implements the plugins.Plugin interface for ManageSieve fingerprinting.
type ManageSievePlugin struct{}

func init() {
	plugins.RegisterPlugin(&ManageSievePlugin{})
}

// cyrusVersionPattern extracts the version from Cyrus timsieved implementation
// strings, e.g. "Cyrus timsieved v3.8.3" -> "3.8.3". Dovecot Pigeonhole does
// not include a version number in its IMPLEMENTATION string.
var cyrusVersionPattern = regexp.MustCompile(`(?i)timsieved\s+v(\d+\.\d+(?:\.\d+)?)`)

// versionValidPattern validates that an extracted version string contains
// only digits and dots (defense-in-depth guard prior to CPE construction).
var versionValidPattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// Name returns the protocol identifier for this plugin.
func (p *ManageSievePlugin) Name() string {
	return MANAGESIEVE
}

// Type returns the transport protocol used by ManageSieve.
func (p *ManageSievePlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority for this plugin.
func (p *ManageSievePlugin) Priority() int {
	return manageSievePriority
}

// PortPriority returns true if port 4190 is the default ManageSieve port.
func (p *ManageSievePlugin) PortPriority(port uint16) bool {
	return port == manageSieveDefaultPort
}

// parseCapabilityLine parses a single ManageSieve capability line of the form
// `"KEYWORD"` or `"KEYWORD" "value"`. Returns ok=false if line is not a
// quoted capability line (e.g. the terminating OK response, or an empty line).
//
// Per RFC 5804, capability keywords are matched case-insensitively; the
// returned keyword is normalized to uppercase for switch-based comparison.
func parseCapabilityLine(line string) (keyword, value string, ok bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, `"`) {
		return "", "", false
	}

	rest := line[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", "", false
	}
	keyword = strings.ToUpper(rest[:end])

	after := strings.TrimSpace(rest[end+1:])
	if after == "" {
		return keyword, "", true
	}
	if !strings.HasPrefix(after, `"`) {
		// Trailing content that isn't a quoted value - treat as no value.
		return keyword, "", true
	}

	valRest := after[1:]
	valEnd := strings.LastIndexByte(valRest, '"')
	if valEnd < 0 {
		return keyword, "", true
	}
	value = valRest[:valEnd]

	return keyword, value, true
}

// extractVersion extracts a version number from a ManageSieve IMPLEMENTATION
// string. Cyrus timsieved includes a version (e.g. "Cyrus timsieved v3.8.3");
// Dovecot Pigeonhole does not, and returns an empty string.
func extractVersion(implementation string) string {
	matches := cyrusVersionPattern.FindStringSubmatch(implementation)
	if len(matches) != 2 {
		return ""
	}
	version := matches[1]
	if !versionValidPattern.MatchString(version) {
		return ""
	}
	return version
}

// buildCPEs generates CPE 2.3 identifiers for known ManageSieve implementations.
// Returns nil if the implementation is unrecognized, empty, or the version
// contains CPE metacharacters (defense-in-depth guard against injection into
// the colon-delimited CPE format).
func buildCPEs(implementation, version string) []string {
	if implementation == "" {
		return nil
	}
	if strings.ContainsAny(version, ":*?") {
		return nil
	}

	cpeVersion := "*"
	if version != "" {
		cpeVersion = version
	}

	lower := strings.ToLower(implementation)
	switch {
	case strings.Contains(lower, "cyrus timsieved"):
		return []string{fmt.Sprintf("cpe:2.3:a:cyrusimap:cyrus_imap:%s:*:*:*:*:*:*:*", cpeVersion)}
	case strings.Contains(lower, "dovecot"), strings.Contains(lower, "pigeonhole"):
		return []string{fmt.Sprintf("cpe:2.3:a:dovecot:dovecot:%s:*:*:*:*:*:*:*", cpeVersion)}
	default:
		return nil
	}
}

// Run performs ManageSieve fingerprinting by passively reading the server's
// greeting (no probe is sent) and parsing its capability lines.
//
// Returns nil, nil when the response is not a valid ManageSieve greeting
// (no capability lines, or no terminating OK response).
func (p *ManageSievePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	lines := strings.Split(string(response), "\r\n")

	var hasCoreCapability, hasOK bool
	var implementation string
	var saslMechanisms []string
	var starttls bool
	var sieveExtensions []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if hasOK {
			// Content after OK response invalidates the greeting.
			hasOK = false
		}

		if strings.HasPrefix(trimmed, `"`) {
			keyword, value, ok := parseCapabilityLine(trimmed)
			if !ok {
				continue
			}

			switch keyword {
			case "IMPLEMENTATION":
				hasCoreCapability = true
				implementation = value
			case "SASL":
				hasCoreCapability = true
				if value != "" {
					saslMechanisms = strings.Fields(value)
				}
			case "STARTTLS":
				hasCoreCapability = true
				starttls = true
			case "SIEVE":
				hasCoreCapability = true
				if value != "" {
					sieveExtensions = strings.Fields(value)
				}
			case "NOTIFY", "VERSION", "UNAUTHENTICATE", "LANGUAGE", "MAXREDIRECTS", "OWNER":
			}
			continue
		}

		if trimmed == "OK" || strings.HasPrefix(trimmed, "OK ") {
			hasOK = true
		}
	}

	if !hasCoreCapability || !hasOK {
		return nil, nil
	}

	version := extractVersion(implementation)
	cpes := buildCPEs(implementation, version)

	payload := plugins.ServiceManageSieve{
		Implementation:    implementation,
		SASLMechanisms:    saslMechanisms,
		StarttlsAvailable: starttls,
		SieveExtensions:   sieveExtensions,
		CPEs:              cpes,
	}

	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	return service, nil
}
