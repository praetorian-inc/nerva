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

package sstp

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type SSTPluginHTTPS struct{}

const SSTP = "sstp"

func init() {
	plugins.RegisterPlugin(&SSTPluginHTTPS{})
}

// generateGUID generates a random GUID in the format {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
func generateGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (p *SSTPluginHTTPS) PortPriority(port uint16) bool {
	// Port 443 is the standard SSTP port
	return port == 443
}

func (p *SSTPluginHTTPS) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Set deadline for the entire operation
	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	// Generate a random GUID for SSTPCORRELATIONID
	correlationID := generateGUID()

	// Construct the SSTP_DUPLEX_POST request
	// The special URI is /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/
	request := fmt.Sprintf(
		"SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"SSTPCORRELATIONID: %s\r\n"+
			"Content-Length: 18446744073709551615\r\n"+
			"\r\n",
		conn.RemoteAddr().String(),
		correlationID,
	)

	// Write the request manually (SSTP_DUPLEX_POST is not a standard HTTP method)
	_, err := conn.Write([]byte(request))
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}

	// Read and parse the response
	reader := bufio.NewReader(conn)

	// Read status line
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, &utils.RequestError{Message: err.Error()}
	}

	// Parse status code
	var statusCode int
	if _, err := fmt.Sscanf(statusLine, "HTTP/1.1 %d", &statusCode); err != nil {
		return nil, &utils.RequestError{Message: "failed to parse HTTP status"}
	}

	// If not HTTP 200, this is not SSTP
	if statusCode != 200 {
		return nil, nil
	}

	// Parse headers to find Server header
	serverHeader := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		// Look for Server header
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				serverHeader = strings.TrimSpace(parts[1])
			}
		}
	}

	// Identify vendor based on Server header
	vendor := "Unknown"
	var cpes []string

	if strings.Contains(serverHeader, "Microsoft-HTTPAPI") {
		vendor = "Microsoft"
		// Windows SSTP (RRAS) CPEs
		cpes = []string{
			"cpe:/o:microsoft:windows",
			"cpe:/a:microsoft:routing_and_remote_access",
		}
	} else if strings.Contains(serverHeader, "MikroTik") {
		vendor = "MikroTik"
		// MikroTik RouterOS CPEs
		cpes = []string{
			"cpe:/o:mikrotik:routeros",
		}
	}

	payload := plugins.ServiceSSTP{
		Server: serverHeader,
		Vendor: vendor,
		CPEs:   cpes,
	}

	return plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS), nil
}

func (p *SSTPluginHTTPS) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *SSTPluginHTTPS) Priority() int {
	// Priority 300 to run before generic HTTPS (which has priority 1)
	return 300
}

func (p *SSTPluginHTTPS) Name() string {
	return SSTP
}
