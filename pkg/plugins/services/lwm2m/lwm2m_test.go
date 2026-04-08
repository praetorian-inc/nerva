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

package lwm2m

import (
	"net"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// buildCoAPResponse constructs a minimal valid CoAP ACK response with the given
// message ID and payload. The header uses:
//
//	0x60 = Ver=1, Type=ACK (2), TKL=0
//	0x45 = Code 2.05 (Content)
func buildCoAPResponse(msgID [2]byte, payload []byte) []byte {
	pkt := []byte{0x60, 0x45, msgID[0], msgID[1]}
	if len(payload) > 0 {
		pkt = append(pkt, 0xFF)
		pkt = append(pkt, payload...)
	}
	return pkt
}

func TestExtractLwM2MPayload(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     *plugins.ServiceLwM2M
	}{
		{
			name: "valid lwm2m with rd and bs",
			response: buildCoAPResponse([2]byte{0x00, 0x01},
				[]byte(`</rd>;rt="oma.lwm2m.rd",</bs>;rt="oma.lwm2m.bs",</.well-known/core>`)),
			want: &plugins.ServiceLwM2M{
				HasRegistration: true,
				HasBootstrap:    true,
				ServerImpl:      "unknown",
				Resources:       `</rd>;rt="oma.lwm2m.rd",</bs>;rt="oma.lwm2m.bs",</.well-known/core>`,
			},
		},
		{
			name: "lwm2m with rd only no bootstrap",
			response: buildCoAPResponse([2]byte{0x00, 0x02},
				[]byte(`</rd>;rt="oma.lwm2m.rd",</.well-known/core>`)),
			want: &plugins.ServiceLwM2M{
				HasRegistration: true,
				HasBootstrap:    false,
				ServerImpl:      "unknown",
				Resources:       `</rd>;rt="oma.lwm2m.rd",</.well-known/core>`,
			},
		},
		{
			name: "lwm2m with californium identifier",
			response: buildCoAPResponse([2]byte{0x00, 0x03},
				[]byte(`</rd>;rt="oma.lwm2m.rd",Cf 3.7.0`)),
			want: &plugins.ServiceLwM2M{
				HasRegistration: true,
				HasBootstrap:    false,
				ServerImpl:      "leshan",
				Resources:       `</rd>;rt="oma.lwm2m.rd",Cf 3.7.0`,
			},
		},
		{
			name: "plain coap without rd - not lwm2m",
			response: buildCoAPResponse([2]byte{0x00, 0x04},
				[]byte(`</.well-known/core>,</sensors/temp>`)),
			want: nil,
		},
		{
			name:     "empty response",
			response: []byte{},
			want:     nil,
		},
		{
			name:     "response too short",
			response: []byte{0x60, 0x45, 0x00},
			want:     nil,
		},
		{
			name:     "payload marker at end with no payload",
			response: []byte{0x60, 0x45, 0x00, 0x01, 0xFF},
			want:     nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractLwM2MPayload(tt.response)
			if tt.want == nil {
				if got != nil {
					t.Errorf("extractLwM2MPayload() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("extractLwM2MPayload() = nil, want %+v", tt.want)
				return
			}
			if got.HasRegistration != tt.want.HasRegistration {
				t.Errorf("HasRegistration = %v, want %v", got.HasRegistration, tt.want.HasRegistration)
			}
			if got.HasBootstrap != tt.want.HasBootstrap {
				t.Errorf("HasBootstrap = %v, want %v", got.HasBootstrap, tt.want.HasBootstrap)
			}
			if got.ServerImpl != tt.want.ServerImpl {
				t.Errorf("ServerImpl = %q, want %q", got.ServerImpl, tt.want.ServerImpl)
			}
			if got.Resources != tt.want.Resources {
				t.Errorf("Resources = %q, want %q", got.Resources, tt.want.Resources)
			}
		})
	}
}

// mockConn is a net.Conn that returns a predetermined response.
type mockConn struct {
	response []byte
	written  []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	n = copy(b, m.response)
	m.response = m.response[n:]
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.written = append(m.written, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestLwM2MRun(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantNil  bool
	}{
		{
			name: "valid lwm2m server response",
			// ACK response with matching msgID will be extracted by Run;
			// since we can't predict the random msgID, use NON-confirmable (typ=1)
			// which skips the msgID check.
			// 0x50 = Ver=1, Type=NON (1), TKL=0; 0x45 = 2.05 Content
			response: append(
				[]byte{0x50, 0x45, 0x00, 0x01, 0xFF},
				[]byte(`</rd>;rt="oma.lwm2m.rd",</bs>;rt="oma.lwm2m.bs"`)...,
			),
			wantNil: false,
		},
		{
			name: "plain coap response without rd",
			response: append(
				[]byte{0x50, 0x45, 0x00, 0x01, 0xFF},
				[]byte(`</.well-known/core>,</sensors/temp>`)...,
			),
			wantNil: true,
		},
		{
			name:     "invalid coap response",
			response: []byte{0x00, 0x00, 0x00, 0x00},
			wantNil:  true,
		},
	}

	p := &LwM2MPlugin{}
	target := plugins.Target{}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			conn := &mockConn{response: tt.response}
			svc, err := p.Run(conn, time.Second, target)
			if err != nil {
				t.Errorf("Run() unexpected error: %v", err)
				return
			}
			if tt.wantNil && svc != nil {
				t.Errorf("Run() = %+v, want nil", svc)
			}
			if !tt.wantNil && svc == nil {
				t.Error("Run() = nil, want non-nil service")
			}
		})
	}
}

// NOTE: The corfr/leshan Docker image is linux/amd64 only. On ARM64 hosts
// (e.g., Apple Silicon Macs), the emulated container starts too slowly for
// the test framework's UDP retry window, causing this test to fail. This is
// a pre-existing environment issue that also affects the CoAP Docker test
// (TestCoAP in pkg/plugins/services/coap/). The test passes on amd64 CI runners.
func TestLwM2M(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "lwm2m",
			Port:        5683,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "corfr/leshan",
				Tag:          "latest",
				ExposedPorts: []string{"5683/udp"},
			},
		},
	}
	var p *LwM2MPlugin
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}
