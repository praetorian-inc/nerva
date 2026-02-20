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

package svn

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type SVNPlugin struct{}

const SVN = "svn"

func init() {
	plugins.RegisterPlugin(&SVNPlugin{})
}

func (p *SVNPlugin) PortPriority(port uint16) bool {
	return port == 3690
}

// checkSVN verifies if the response starts with "( success (" which indicates SVN protocol
func checkSVN(data []byte) bool {
	if len(data) < 11 {
		return false
	}
	prefix := []byte("( success (")
	return bytes.HasPrefix(data, prefix)
}

// parseSVNGreeting parses the SVN S-expression greeting format:
// ( success ( MIN_VERSION MAX_VERSION ( AUTH_MECHANISMS... ) ( CAPABILITIES... ) ) )
func parseSVNGreeting(data []byte) (minVersion, maxVersion int, authMechs, capabilities []string, err error) {
	greeting := string(data)

	// Remove outer "( success ( ... ) )"
	if !strings.HasPrefix(greeting, "( success (") {
		return 0, 0, nil, nil, fmt.Errorf("invalid SVN greeting format")
	}

	// Find the content inside "( success ( ... ) )"
	content := strings.TrimSpace(greeting[11:])
	if !strings.HasSuffix(content, ") )") {
		return 0, 0, nil, nil, fmt.Errorf("invalid SVN greeting termination")
	}
	content = strings.TrimSuffix(content, ") )")
	content = strings.TrimSpace(content)

	// Parse: MIN_VERSION MAX_VERSION ( AUTH_MECHANISMS ) ( CAPABILITIES )
	parts := tokenize(content)
	if len(parts) < 4 {
		return 0, 0, nil, nil, fmt.Errorf("insufficient parts in SVN greeting")
	}

	// Parse versions
	minVersion, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("invalid min version: %w", err)
	}

	maxVersion, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("invalid max version: %w", err)
	}

	// Parse auth mechanisms list
	authMechs = parseList(parts[2])

	// Parse capabilities list
	if len(parts) > 3 {
		capabilities = parseList(parts[3])
	}

	return minVersion, maxVersion, authMechs, capabilities, nil
}

// tokenize splits the content by lists (parentheses) and tokens
func tokenize(content string) []string {
	var tokens []string
	var current strings.Builder
	depth := 0
	inList := false

	for _, ch := range content {
		switch ch {
		case '(':
			if depth == 0 {
				// Start of a list
				if current.Len() > 0 {
					tokens = append(tokens, strings.TrimSpace(current.String()))
					current.Reset()
				}
				inList = true
				current.WriteRune(ch)
			} else {
				current.WriteRune(ch)
			}
			depth++
		case ')':
			depth--
			current.WriteRune(ch)
			if depth == 0 && inList {
				// End of a list
				tokens = append(tokens, current.String())
				current.Reset()
				inList = false
			}
		case ' ', '\t', '\n', '\r':
			if depth > 0 {
				current.WriteRune(ch)
			} else if current.Len() > 0 {
				tokens = append(tokens, strings.TrimSpace(current.String()))
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, strings.TrimSpace(current.String()))
	}

	return tokens
}

// parseList extracts items from a list string like "( item1 item2 item3 )"
func parseList(listStr string) []string {
	listStr = strings.TrimSpace(listStr)
	if !strings.HasPrefix(listStr, "(") || !strings.HasSuffix(listStr, ")") {
		return []string{}
	}

	// Remove parentheses
	listStr = strings.TrimPrefix(listStr, "(")
	listStr = strings.TrimSuffix(listStr, ")")
	listStr = strings.TrimSpace(listStr)

	if listStr == "" {
		return []string{}
	}

	// Split by whitespace
	items := strings.Fields(listStr)
	return items
}

func (p *SVNPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// SVN server sends greeting immediately upon connection
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Check if this is an SVN response
	if !checkSVN(response) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: SVN,
			Info:    "invalid SVN greeting prefix",
		}
	}

	// Parse the SVN greeting
	minVersion, maxVersion, authMechs, capabilities, err := parseSVNGreeting(response)
	if err != nil {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: SVN,
			Info:    fmt.Sprintf("failed to parse SVN greeting: %v", err),
		}
	}

	payload := plugins.ServiceSVN{
		MinVersion:   minVersion,
		MaxVersion:   maxVersion,
		AuthMechs:    authMechs,
		Capabilities: capabilities,
	}

	// Generate CPE for the detected version
	version := fmt.Sprintf("%d", maxVersion)
	cpe := fmt.Sprintf("cpe:2.3:a:apache:subversion:%s:*:*:*:*:*:*:*", version)

	return plugins.CreateServiceFrom(target, payload, false, cpe, plugins.TCP), nil
}

func (p *SVNPlugin) Name() string {
	return SVN
}

func (p *SVNPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SVNPlugin) Priority() int {
	return 2
}
