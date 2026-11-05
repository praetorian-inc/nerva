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

package redissentinel

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

type RedisSentinelPlugin struct{}

const RedisSentinelName = "redis-sentinel"

// checkRedisResponse validates a PING response and reports whether authentication
// is required. Sentinel and Redis share the same PING/NOAUTH wire format, so this
// alone cannot distinguish between them; INFO must be inspected for that.
func checkRedisResponse(data []byte) (authRequired bool, err error) {
	pong := []byte("+PONG\r\n")
	noauth := []byte("-NOAUTH")

	if len(data) < 7 {
		return false, &utils.InvalidResponseErrorInfo{
			Service: RedisSentinelName,
			Info:    "too short of a response",
		}
	}

	if bytes.Equal(data, pong) {
		return false, nil
	}

	if bytes.HasPrefix(data, noauth) {
		return true, nil
	}

	return false, &utils.InvalidResponseErrorInfo{
		Service: RedisSentinelName,
		Info:    "invalid PING response",
	}
}

// parseInfoBulkString extracts the data portion of a RESP bulk string response
// in the format "$<length>\r\n<data>\r\n".
func parseInfoBulkString(resp []byte) string {
	if len(resp) < 2 || resp[0] != '$' {
		return ""
	}
	for i := 1; i < len(resp)-1; i++ {
		if resp[i] == '\r' && resp[i+1] == '\n' {
			dataStart := i + 2
			if dataStart <= len(resp) {
				return string(resp[dataStart:])
			}
			break
		}
	}
	return ""
}

// extractRedisVersion extracts the "redis_version" field from an INFO response.
func extractRedisVersion(response string) string {
	if response == "" {
		return ""
	}

	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "redis_version:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// extractSentinelMasters extracts the "sentinel_masters" count from the
// "# Sentinel" section of an INFO response. Returns 0 if missing or malformed.
func extractSentinelMasters(response string) int {
	if response == "" {
		return 0
	}

	lines := strings.Split(strings.ReplaceAll(response, "\r\n", "\n"), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "sentinel_masters:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
				if err == nil {
					return n
				}
			}
		}
	}

	return 0
}

// buildRedisCPE generates a CPE string for the Redis product underlying a Sentinel
// instance. Uses "*" wildcard when the version is unknown.
func buildRedisCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:redis:redis:%s:*:*:*:*:*:*:*", version)
}

func init() {
	plugins.RegisterPlugin(&RedisSentinelPlugin{})
}

func (p *RedisSentinelPlugin) PortPriority(port uint16) bool {
	return port == 26379
}

func DetectRedisSentinel(conn net.Conn, target plugins.Target, timeout time.Duration) (*plugins.Service, error) {
	// PING: [*1(CR)(NL)$4(CR)(NL)PING(CR)(NL)]
	ping := []byte("*1\r\n$4\r\nPING\r\n")

	response, err := utils.SendRecv(conn, ping, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	authRequired, err := checkRedisResponse(response)
	if err != nil {
		return nil, nil
	}
	if authRequired {
		// Can't distinguish Sentinel from Redis without INFO. The Redis plugin
		// handles auth-required instances.
		return nil, nil
	}

	// Scoped to the sentinel section to avoid truncation — full INFO can exceed
	// the 4096-byte read buffer, and # Sentinel appears last.
	infoSentinelCmd := []byte("*2\r\n$4\r\nINFO\r\n$8\r\nsentinel\r\n")

	sentinelResp, err := utils.SendRecv(conn, infoSentinelCmd, timeout)
	if err != nil || len(sentinelResp) == 0 {
		return nil, nil
	}

	sentinelData := parseInfoBulkString(sentinelResp)
	if !strings.Contains(sentinelData, "# Sentinel") {
		return nil, nil
	}

	sentinelMasters := extractSentinelMasters(sentinelData)

	infoServerCmd := []byte("*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
	version := ""
	serverResp, err := utils.SendRecv(conn, infoServerCmd, timeout)
	if err == nil && len(serverResp) > 0 {
		version = extractRedisVersion(parseInfoBulkString(serverResp))
	}
	cpe := buildRedisCPE(version)

	payload := plugins.ServiceRedisSentinel{
		SentinelMasters: sentinelMasters,
		CPEs:            []string{cpe},
	}

	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	return service, nil
}

func (p *RedisSentinelPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectRedisSentinel(conn, target, timeout)
}

func (p *RedisSentinelPlugin) Name() string {
	return RedisSentinelName
}

func (p *RedisSentinelPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RedisSentinelPlugin) Priority() int {
	return 412
}
