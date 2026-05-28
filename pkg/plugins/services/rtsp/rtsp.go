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

package rtsp

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	RtspMagicHeader        = "RTSP/1.0"
	RtspMagicHeaderLength  = 8
	RtspCseqHeader         = "CSeq: "
	RtspCseqHeaderLength   = 6
	RtspServerHeader       = "Server: "
	RtspServerHeaderLength = 8
	RtspNewlineLength      = 2
	RTSP                   = "rtsp"
)

type RTSPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&RTSPPlugin{})
}

func (p *RTSPPlugin) PortPriority(port uint16) bool {
	return port == 554
}

/*
   rtsp is a media control protocol used to control the flow of data from a real time
   data streaming protocol. rtsp itself does not transport any data. The structure of rtsp
   requests is very similar to that of http requests.

   To detect the presence of RTSP, this program sends an OPTIONS request, and then validates
   the returned header and cseq value.

   This program was tested with docker run -p 554:8554 aler9/rtsp-simple-server.
   The default port for rtsp is 554.
*/

func (p *RTSPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	cseq := strconv.Itoa(rand.Intn(10000)) //#nosec G404 -- CSeq is not security-sensitive //nolint:gosec

	requestString := strings.Join([]string{
		"OPTIONS rtsp://example.com RTSP/1.0\r\n",
		"Cseq: ", cseq, "\r\n",
		"\r\n",
	}, "")

	requestBytes := []byte(requestString)

	responseBytes, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(responseBytes) == 0 {
		return nil, nil
	}
	response := string(responseBytes)

	if len(response) < RtspMagicHeaderLength {
		return nil, nil
	}
	if response[:RtspMagicHeaderLength] == RtspMagicHeader {
		cseqStart := strings.Index(response, RtspCseqHeader)
		if cseqStart == -1 {
			return nil, nil
		}

		cseqValueStart := cseqStart + RtspCseqHeaderLength
		cseqValueEnd := cseqValueStart + len(cseq) + RtspNewlineLength
		if cseqValueEnd > len(response) {
			return nil, nil
		}
		if response[cseqValueStart:cseqValueEnd] != cseq+"\r\n" {
			return nil, nil
		}

		serverStart := strings.Index(response, RtspServerHeader)
		if serverStart == -1 {
			return nil, nil
		}

		serverValueStart := serverStart + RtspServerHeaderLength
		serverValueEnd := strings.Index(response[serverValueStart:], "\r\n")
		if serverValueStart+serverValueEnd >= len(response) {
			return nil, nil
		}

		serverinfo := response[serverValueStart : serverValueStart+serverValueEnd]
		payload := plugins.ServiceRtsp{
			ServerInfo: serverinfo,
		}
		service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
		if target.Misconfigs && !strings.ContainsAny(target.Host, "\r\n") {
			describeCseq := strconv.Itoa(rand.Intn(10000)) //#nosec G404 -- CSeq is not security-sensitive //nolint:gosec
			// Probes the common /stream default path. Servers using other paths may not generate this finding.
			describeRequest := fmt.Sprintf(
				"DESCRIBE rtsp://%s:%d/stream RTSP/1.0\r\nCSeq: %s\r\nAccept: application/sdp\r\n\r\n",
				target.Host, target.Address.Port(), describeCseq,
			)
			describeResponse, describeErr := utils.SendRecv(conn, []byte(describeRequest), timeout)
			if describeErr == nil && len(describeResponse) > 0 {
				statusCode := parseRTSPStatusCode(string(describeResponse))
				if statusCode == 200 {
					service.AnonymousAccess = true
					service.SecurityFindings = []plugins.SecurityFinding{{
						ID:          "rtsp-unauthenticated-stream",
						Severity:    plugins.SeverityHigh,
						Description: "RTSP stream accessible without authentication",
						Evidence:    sanitizeEvidence(string(describeResponse)),
					}}
				}
			}
		}
		return service, nil
	}

	return nil, nil
}

// sanitizeEvidence extracts the first line, caps at 256 bytes, and strips control characters.
func sanitizeEvidence(raw string) string {
	if idx := strings.Index(raw, "\r\n"); idx != -1 {
		raw = raw[:idx]
	}
	if len(raw) > 256 {
		raw = raw[:256]
	}
	var b strings.Builder
	for _, r := range raw {
		if r >= 0x20 && r != 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// parseRTSPStatusCode extracts the status code from an RTSP response line.
// Expected format: "RTSP/1.0 200 OK\r\n..."
func parseRTSPStatusCode(response string) int {
	const prefix = "RTSP/1.0 "
	if !strings.HasPrefix(response, prefix) {
		return 0
	}
	rest := response[len(prefix):]
	end := strings.IndexAny(rest, " \r\n")
	if end == -1 {
		end = len(rest)
	}
	if end != 3 {
		return 0
	}
	code, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return code
}

func (p *RTSPPlugin) Name() string {
	return RTSP
}
func (p *RTSPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RTSPPlugin) Priority() int {
	return 1001
}
