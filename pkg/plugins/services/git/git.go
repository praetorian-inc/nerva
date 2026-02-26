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

// Package git provides fingerprinting for the Git daemon service.
//
// Git daemon serves Git repositories over TCP port 9418 using the pkt-line
// protocol. It provides unauthenticated read access to public repositories.
// Detection is performed by sending a git-upload-pack request and parsing
// the pkt-line ref advertisement response.
//
// Protocol reference: https://git-scm.com/docs/pack-protocol
// Wire format: https://git-scm.com/docs/gitprotocol-pack
package git

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	gitDefaultPort = 9418
	gitPriority    = 2
)

// TCPPlugin implements the plugins.Plugin interface for Git daemon fingerprinting.
type TCPPlugin struct{}

// ref represents a single Git reference (branch, tag, or HEAD).
type ref struct {
	Hash string
	Name string
}

func init() {
	plugins.RegisterPlugin(&TCPPlugin{})
}

// Name returns the protocol identifier for this plugin.
func (p *TCPPlugin) Name() string {
	return plugins.ProtoGit
}

// Type returns the transport protocol used by Git daemon.
func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the execution priority for this plugin.
func (p *TCPPlugin) Priority() int {
	return gitPriority
}

// PortPriority returns true if port 9418 is the default Git daemon port.
func (p *TCPPlugin) PortPriority(port uint16) bool {
	return port == gitDefaultPort
}

// Run performs Git daemon fingerprinting by sending a git-upload-pack request
// and parsing the pkt-line ref advertisement response.
//
// Returns nil, nil when the target is not a Git daemon (empty response, flush-only,
// or ERR response). Returns a Service on successful detection.
func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	request := buildUploadPackRequest(target.Host)

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	refs, capabilities, protocolVersion, err := parseRefAdvertisement(response)
	if err != nil {
		return nil, nil
	}

	// Empty response (flush-only or ERR) means not a Git daemon or access denied.
	if refs == nil {
		return nil, nil
	}

	// Extract HEAD ref and classify branches/tags.
	var headRef string
	var branches []string
	var tags []string

	for _, r := range refs {
		switch {
		case r.Name == "HEAD":
			headRef = r.Hash
		case strings.HasPrefix(r.Name, "refs/heads/"):
			branches = append(branches, strings.TrimPrefix(r.Name, "refs/heads/"))
		case strings.HasPrefix(r.Name, "refs/tags/") && !strings.HasSuffix(r.Name, "^{}"):
			tags = append(tags, strings.TrimPrefix(r.Name, "refs/tags/"))
		}
	}

	// Build version string from protocol version.
	var versionStr string
	switch protocolVersion {
	case 1:
		versionStr = "1"
	case 2:
		versionStr = "2"
	default:
		versionStr = ""
	}

	payload := plugins.ServiceGit{
		ProtocolVersion: protocolVersion,
		HeadRef:         headRef,
		Branches:        branches,
		Tags:            tags,
		Capabilities:    capabilities,
	}

	return plugins.CreateServiceFrom(target, payload, false, versionStr, plugins.TCP), nil
}

// buildUploadPackRequest builds a pkt-line encoded git-upload-pack request.
//
// The request format is:
//
//	<4-byte-hex-length>git-upload-pack /test.git\0host=<hostname>\0
//
// where the 4-byte hex length includes itself.
func buildUploadPackRequest(host string) []byte {
	data := fmt.Sprintf("git-upload-pack /test.git\x00host=%s\x00", host)
	return encodePktLine(data)
}

// encodePktLine encodes a string into pkt-line format.
//
// The pkt-line format prefixes data with a 4-byte hex length that includes
// the 4 bytes of the length prefix itself.
func encodePktLine(data string) []byte {
	length := len(data) + 4
	return []byte(fmt.Sprintf("%04x%s", length, data))
}

// decodePktLine decodes one pkt-line from bytes.
//
// Returns the line content, the number of bytes consumed, and any error.
// For flush packets (0000), returns empty string with bytesConsumed=4.
// Returns an error for data shorter than 4 bytes or invalid hex length.
func decodePktLine(data []byte) (line string, bytesConsumed int, err error) {
	if len(data) < 4 {
		return "", 0, fmt.Errorf("pkt-line too short: %d bytes", len(data))
	}

	hexLen := string(data[:4])

	// Flush packet.
	if hexLen == "0000" {
		return "", 4, nil
	}

	// Validate hex length bytes.
	decoded, err := hex.DecodeString(hexLen)
	if err != nil {
		return "", 0, fmt.Errorf("invalid pkt-line length hex %q: %w", hexLen, err)
	}

	// Length is big-endian 2-byte value from hex decode.
	pktLen := int(decoded[0])<<8 | int(decoded[1])

	if pktLen < 4 {
		return "", 0, fmt.Errorf("invalid pkt-line length %d (minimum 4)", pktLen)
	}

	if len(data) < pktLen {
		return "", 0, fmt.Errorf("pkt-line truncated: need %d bytes, have %d", pktLen, len(data))
	}

	return string(data[4:pktLen]), pktLen, nil
}

// parseRefAdvertisement parses a full Git ref advertisement response.
//
// Returns the list of refs, server capabilities, detected protocol version,
// and any parse error. Returns nil refs on flush-only or ERR responses.
//
// Protocol versions:
//   - 0: implicit (legacy, no version line)
//   - 1: explicit "version 1" line present
//   - 2: explicit "version 2" line present
func parseRefAdvertisement(data []byte) (refs []ref, capabilities []string, protocolVersion int, err error) {
	if len(data) == 0 {
		return nil, nil, 0, nil
	}

	pos := 0
	firstLine := true
	var parsedRefs []ref
	var caps []string
	version := 0

	for pos < len(data) {
		line, consumed, decodeErr := decodePktLine(data[pos:])
		if decodeErr != nil {
			// Truncated or invalid response — not a Git daemon.
			return nil, nil, 0, nil
		}

		pos += consumed

		// Flush packet marks end of ref advertisement.
		if consumed == 4 && line == "" {
			break
		}

		// Strip trailing newline.
		line = strings.TrimSuffix(line, "\n")

		// ERR packet — access denied or no repos.
		if strings.HasPrefix(line, "ERR ") {
			return nil, nil, 0, nil
		}

		// Protocol version line (protocol v2 or explicit v1).
		if firstLine && strings.HasPrefix(line, "version ") {
			vStr := strings.TrimPrefix(line, "version ")
			switch strings.TrimSpace(vStr) {
			case "1":
				version = 1
			case "2":
				version = 2
			}
			firstLine = false
			continue
		}

		firstLine = false

		// Parse ref line: "<sha1> <refname>" or first line with capabilities.
		// A SHA-1 hash is exactly 40 hex characters.
		if len(line) < 42 {
			// Too short to be a valid ref line (40 hash + space + at least 1 char name).
			continue
		}

		hashPart := line[:40]
		if !isHexString(hashPart) {
			continue
		}

		rest := line[41:]

		// First ref line may contain capabilities after a NUL byte.
		nullIdx := strings.IndexByte(rest, 0)
		refName := rest
		if nullIdx >= 0 {
			refName = rest[:nullIdx]
			capStr := rest[nullIdx+1:]
			caps = strings.Fields(capStr)
		}

		parsedRefs = append(parsedRefs, ref{
			Hash: hashPart,
			Name: refName,
		})
	}

	// If we got no refs at all, treat as non-git.
	if len(parsedRefs) == 0 {
		return nil, nil, 0, nil
	}

	return parsedRefs, caps, version, nil
}

// isHexString returns true if s consists entirely of valid hex characters.
func isHexString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
