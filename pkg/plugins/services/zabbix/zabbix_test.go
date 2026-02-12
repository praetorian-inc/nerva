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

package zabbix

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// buildZBXDResponse constructs a ZBXD protocol response for testing.
// flags: 0x01 for standard packet, 0x05 for large packet (0x01 | 0x04)
func buildZBXDResponse(flags byte, payload string) []byte {
	payloadBytes := []byte(payload)
	payloadLen := uint32(len(payloadBytes))

	if flags&0x04 != 0 {
		// Large packet: 21-byte header (magic + flags + 8-byte datalen + 8-byte reserved)
		header := make([]byte, 21)
		copy(header[0:4], []byte("ZBXD"))
		header[4] = flags
		binary.LittleEndian.PutUint64(header[5:13], uint64(payloadLen))
		binary.LittleEndian.PutUint64(header[13:21], 0) // reserved
		return append(header, payloadBytes...)
	}

	// Standard packet: 13-byte header (magic + flags + 4-byte datalen + 4-byte reserved)
	header := make([]byte, 13)
	copy(header[0:4], []byte("ZBXD"))
	header[4] = flags
	binary.LittleEndian.PutUint32(header[5:9], payloadLen)
	binary.LittleEndian.PutUint32(header[9:13], 0) // reserved
	return append(header, payloadBytes...)
}

func TestParseZBXDResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantPayload string
		wantErr     bool
	}{
		{
			name:        "valid standard response with version 6.0.27",
			data:        buildZBXDResponse(0x01, "6.0.27"),
			wantPayload: "6.0.27",
			wantErr:     false,
		},
		{
			name:        "valid standard response with version 5.4.1",
			data:        buildZBXDResponse(0x01, "5.4.1"),
			wantPayload: "5.4.1",
			wantErr:     false,
		},
		{
			name:        "valid standard response with version 7.0.0",
			data:        buildZBXDResponse(0x01, "7.0.0"),
			wantPayload: "7.0.0",
			wantErr:     false,
		},
		{
			name:        "ZBX_NOTSUPPORTED response",
			data:        buildZBXDResponse(0x01, "ZBX_NOTSUPPORTED\x00Metric not supported"),
			wantPayload: "ZBX_NOTSUPPORTED\x00Metric not supported",
			wantErr:     false,
		},
		{
			name:    "response too short (< 13 bytes)",
			data:    []byte{0x5A, 0x42, 0x58, 0x44, 0x01, 0x06}, // Only 6 bytes
			wantErr: true,
		},
		{
			name:    "invalid magic bytes",
			data:    buildZBXDResponse(0x01, "6.0.27"),
			wantErr: true,
		},
		{
			name:    "empty response",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:        "compressed flag response (FLAGS=0x03: standard + compressed)",
			data:        buildZBXDResponse(0x03, "6.0.27"),
			wantPayload: "6.0.27",
			wantErr:     false,
		},
		{
			name:        "large packet flag response (FLAGS=0x05: standard + large)",
			data:        buildZBXDResponse(0x05, "7.0.0"),
			wantPayload: "7.0.0",
			wantErr:     false,
		},
	}

	// Modify the test data for "invalid magic bytes" test
	for i := range tests {
		if tests[i].name == "invalid magic bytes" {
			// Corrupt the magic bytes
			tests[i].data[0] = 0xFF
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := parseZBXDResponse(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseZBXDResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(payload) != tt.wantPayload {
				t.Errorf("parseZBXDResponse() payload = %q, want %q", string(payload), tt.wantPayload)
			}
		})
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    string
	}{
		{
			name:    "standard version 6.0.27",
			payload: []byte("6.0.27"),
			want:    "6.0.27",
		},
		{
			name:    "version 5.4.1",
			payload: []byte("5.4.1"),
			want:    "5.4.1",
		},
		{
			name:    "version 7.0.0",
			payload: []byte("7.0.0"),
			want:    "7.0.0",
		},
		{
			name:    "version with extra text",
			payload: []byte("6.0.27 (revision abc123)"),
			want:    "6.0.27",
		},
		{
			name:    "empty payload",
			payload: []byte{},
			want:    "",
		},
		{
			name:    "non-version text",
			payload: []byte("not a version"),
			want:    "",
		},
		{
			name:    "ZBX_NOTSUPPORTED payload",
			payload: []byte("ZBX_NOTSUPPORTED\x00Metric not supported"),
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVersion(tt.payload)
			if got != tt.want {
				t.Errorf("extractVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildZabbixAgentCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "known version 6.0.27",
			version: "6.0.27",
			want:    "cpe:2.3:a:zabbix:zabbix_agent:6.0.27:*:*:*:*:*:*:*",
		},
		{
			name:    "version 5.4.1",
			version: "5.4.1",
			want:    "cpe:2.3:a:zabbix:zabbix_agent:5.4.1:*:*:*:*:*:*:*",
		},
		{
			name:    "version 7.0.0",
			version: "7.0.0",
			want:    "cpe:2.3:a:zabbix:zabbix_agent:7.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:zabbix:zabbix_agent:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildZabbixAgentCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildZabbixAgentCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildZBXDRequest(t *testing.T) {
	tests := []struct {
		name    string
		itemKey string
		wantLen int
	}{
		{
			name:    "agent.version request",
			itemKey: "agent.version",
			wantLen: 13 + len("agent.version"), // header + payload
		},
		{
			name:    "system.run[id] request",
			itemKey: "system.run[id]",
			wantLen: 13 + len("system.run[id]"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildZBXDRequest(tt.itemKey)
			if len(got) != tt.wantLen {
				t.Errorf("buildZBXDRequest() len = %d, want %d", len(got), tt.wantLen)
			}
			// Verify ZBXD magic
			if string(got[0:4]) != "ZBXD" {
				t.Errorf("buildZBXDRequest() magic = %q, want \"ZBXD\"", string(got[0:4]))
			}
			// Verify FLAGS
			if got[4] != 0x01 {
				t.Errorf("buildZBXDRequest() flags = 0x%02x, want 0x01", got[4])
			}
			// Verify datalen
			datalen := binary.LittleEndian.Uint32(got[5:9])
			if int(datalen) != len(tt.itemKey) {
				t.Errorf("buildZBXDRequest() datalen = %d, want %d", datalen, len(tt.itemKey))
			}
			// Verify payload
			payload := string(got[13:])
			if payload != tt.itemKey {
				t.Errorf("buildZBXDRequest() payload = %q, want %q", payload, tt.itemKey)
			}
		})
	}
}

func TestCheckRemoteCommands(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
	}{
		{
			name:     "command output (remote commands enabled)",
			response: buildZBXDResponse(0x01, "uid=0(root) gid=0(root) groups=0(root)"),
			want:     true,
		},
		{
			name:     "ZBX_NOTSUPPORTED (remote commands disabled)",
			response: buildZBXDResponse(0x01, "ZBX_NOTSUPPORTED\x00Remote commands are not enabled"),
			want:     false,
		},
		{
			name:     "empty response (disabled/error)",
			response: []byte{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test checks the parsing logic only
			// In real usage, checkRemoteCommands would use a network connection
			payload, err := parseZBXDResponse(tt.response)
			if err != nil && len(tt.response) > 0 {
				t.Fatalf("parseZBXDResponse() failed: %v", err)
			}

			var enabled bool
			if len(payload) > 0 {
				payloadStr := string(payload)
				enabled = !bytes.HasPrefix([]byte(payloadStr), []byte("ZBX_NOTSUPPORTED"))
			}

			if enabled != tt.want {
				t.Errorf("checkRemoteCommands() = %v, want %v", enabled, tt.want)
			}
		})
	}
}

func TestZabbixAgent(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "zabbix-agent",
			Port:        10050,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "zabbix/zabbix-agent",
				Tag:        "alpine-6.0-latest",
				Entrypoint: []string{"sh", "-c"},
				Cmd: []string{
					"sed -i 's/^Server=.*/Server=0.0.0.0\\/0/' /etc/zabbix/zabbix_agentd.conf && " +
						"sed -i 's/^ServerActive=.*/ServerActive=/' /etc/zabbix/zabbix_agentd.conf && " +
						"echo 'LogType=console' >> /etc/zabbix/zabbix_agentd.conf && " +
						"exec /usr/sbin/zabbix_agentd -f -c /etc/zabbix/zabbix_agentd.conf",
				},
			},
		},
	}

	p := &ZabbixAgentPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}
