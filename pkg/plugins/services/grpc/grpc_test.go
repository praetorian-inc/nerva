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

package grpc

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestGRPCPluginInterface(t *testing.T) {
	p := &GRPCPlugin{}

	if p.Name() != "grpc" {
		t.Errorf("Name() = %q, want %q", p.Name(), "grpc")
	}
	if p.Type() != plugins.TCP {
		t.Errorf("Type() = %v, want TCP", p.Type())
	}
	if p.Priority() != 300 {
		t.Errorf("Priority() = %d, want 300", p.Priority())
	}
}

func TestGRPCPluginPortPriority(t *testing.T) {
	p := &GRPCPlugin{}

	tests := []struct {
		name string
		port uint16
		want bool
	}{
		{"default gRPC port", 50051, true},
		{"common gRPC port", 9090, true},
		{"HTTP port", 80, false},
		{"HTTPS port", 443, false},
		{"Milvus port", 19530, false},
		{"random port", 8080, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := p.PortPriority(tt.port); got != tt.want {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

func TestParseHealthStatus(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"UNKNOWN", []byte{0x08, 0x00}, "UNKNOWN"},
		{"SERVING", []byte{0x08, 0x01}, "SERVING"},
		{"NOT_SERVING", []byte{0x08, 0x02}, "NOT_SERVING"},
		{"SERVICE_UNKNOWN", []byte{0x08, 0x03}, "SERVICE_UNKNOWN"},
		{"empty response", []byte{}, ""},
		{"single byte", []byte{0x08}, ""},
		{"invalid status value", []byte{0x08, 0x05}, ""},
		{"no field 1 tag", []byte{0x10, 0x01}, ""},
		{"field 1 tag mid-message", []byte{0x10, 0x00, 0x08, 0x01}, "SERVING"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseHealthStatus(tt.data); got != tt.want {
				t.Errorf("parseHealthStatus(%v) = %q, want %q", tt.data, got, tt.want)
			}
		})
	}
}

func TestParseReflectionResponse(t *testing.T) {
	// Build a realistic ServerReflectionResponse for "grpc.health.v1.Health"
	// Wire format (3-level nesting):
	//   field 6 (list_services_response), wire type 2: tag=0x32
	//     field 1 (service), wire type 2: tag=0x0a
	//       field 1 (name), wire type 2: tag=0x0a
	//         "grpc.health.v1.Health" (21 bytes)
	serviceName := []byte("grpc.health.v1.Health")
	// Inner ServiceResponse: tag(0x0a) + len(21) + name
	innerMsg := append([]byte{0x0a, byte(len(serviceName))}, serviceName...)
	// ListServiceResponse.service: tag(0x0a) + len(innerMsg) + innerMsg
	listEntry := append([]byte{0x0a, byte(len(innerMsg))}, innerMsg...)
	// ServerReflectionResponse.list_services_response: tag(0x32) + len(listEntry) + listEntry
	fullResp := append([]byte{0x32, byte(len(listEntry))}, listEntry...)

	// Two services response
	svc1 := []byte("grpc.health.v1.Health")
	svc2 := []byte("myapp.v1.UserService")
	inner1 := append([]byte{0x0a, byte(len(svc1))}, svc1...)
	entry1 := append([]byte{0x0a, byte(len(inner1))}, inner1...)
	inner2 := append([]byte{0x0a, byte(len(svc2))}, svc2...)
	entry2 := append([]byte{0x0a, byte(len(inner2))}, inner2...)
	listData := append(entry1, entry2...)
	twoSvcResp := append([]byte{0x32, byte(len(listData))}, listData...)

	tests := []struct {
		name     string
		data     []byte
		want     int
		wantName string // first service name to check (empty = don't check)
	}{
		{"empty response", []byte{}, 0, ""},
		{"nil", nil, 0, ""},
		{"single service", fullResp, 1, "grpc.health.v1.Health"},
		{"two services", twoSvcResp, 2, "grpc.health.v1.Health"},
		{"truncated data", []byte{0x32, 0x05, 0x0a, 0x03}, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseReflectionResponse(tt.data)
			if len(got) != tt.want {
				t.Errorf("parseReflectionResponse() returned %d services, want %d; got=%v", len(got), tt.want, got)
			}
			if tt.wantName != "" && len(got) > 0 && got[0] != tt.wantName {
				t.Errorf("first service = %q, want %q", got[0], tt.wantName)
			}
		})
	}
}

func TestIsServiceName(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"valid service", []byte("grpc.health.v1.Health"), true},
		{"valid with underscore", []byte("my_package.MyService"), true},
		{"no dots", []byte("MyService"), false},
		{"empty", []byte{}, false},
		{"binary data", []byte{0x00, 0x01, 0x02}, false},
		{"with spaces", []byte("my service.Name"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isServiceName(tt.data); got != tt.want {
				t.Errorf("isServiceName(%q) = %v, want %v", string(tt.data), got, tt.want)
			}
		})
	}
}

func TestServiceGRPCType(t *testing.T) {
	s := plugins.ServiceGRPC{}
	if s.Type() != "grpc" {
		t.Errorf("ServiceGRPC.Type() = %q, want %q", s.Type(), "grpc")
	}
}

func TestExtractServiceNames_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantLen  int
	}{
		{
			name: "varint field wire type 0 is skipped",
			// Tag byte: field 1, wire type 0 (varint) = 0x08, value byte: 0x05
			// Then field with valid service name to confirm parsing continues
			data: func() []byte {
				// varint field: tag=0x08 (field 1, wire type 0), value=0x05
				// Then a length-delimited field with a valid service name
				svc := []byte("grpc.health.v1.Health")
				inner := append([]byte{0x0a, byte(len(svc))}, svc...)
				return append([]byte{0x08, 0x05, 0x0a, byte(len(inner))}, inner...)
			}(),
			wantLen: 1,
		},
		{
			name: "unknown wire type terminates parsing",
			// Wire type 6 is unknown and not handled, triggers return
			// Tag: field 1, wire type 6 = 0x0e
			data:    []byte{0x0e, 0x01, 0x02, 0x03, 0x04},
			wantLen: 0,
		},
		{
			name: "wire type 5 (32-bit fixed) is skipped",
			data: func() []byte {
				svc := []byte("grpc.health.v1.Health")
				inner := append([]byte{0x0a, byte(len(svc))}, svc...)
				prefix := []byte{0x0d, 0x01, 0x02, 0x03, 0x04}
				return append(prefix, append([]byte{0x0a, byte(len(inner))}, inner...)...)
			}(),
			wantLen: 1,
		},
		{
			name: "wire type 1 (64-bit fixed) is skipped",
			data: func() []byte {
				svc := []byte("grpc.health.v1.Health")
				inner := append([]byte{0x0a, byte(len(svc))}, svc...)
				prefix := []byte{0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
				return append(prefix, append([]byte{0x0a, byte(len(inner))}, inner...)...)
			}(),
			wantLen: 1,
		},
		{
			name: "deep nesting beyond limit returns no panic",
			data: func() []byte {
				svc := []byte("grpc.health.v1.Health")
				msg := append([]byte{0x0a, byte(len(svc))}, svc...)
				for i := 0; i < 12; i++ {
					msg = append([]byte{0x0a, byte(len(msg))}, msg...)
				}
				return msg
			}(),
			wantLen: 0,
		},
		{
			name: "length exceeds remaining data triggers bounds check",
			// Tag: field 1, wire type 2 = 0x0a; length: 100 (exceeds remaining 2 bytes)
			data:    []byte{0x0a, 0x64, 0x01, 0x02},
			wantLen: 0,
		},
		{
			name:    "empty data returns no services",
			data:    []byte{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var services []string
			extractServiceNames(tt.data, &services)
			if len(services) != tt.wantLen {
				t.Errorf("extractServiceNames() returned %d services, want %d; got=%v", len(services), tt.wantLen, services)
			}
		})
	}
}

func TestReadVarint(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		wantVal       int
		wantBytesRead int
	}{
		{
			name:          "valid single-byte varint",
			data:          []byte{0x05},
			wantVal:       5,
			wantBytesRead: 1,
		},
		{
			name:          "valid multi-byte varint",
			data:          []byte{0xAC, 0x02},
			wantVal:       300,
			wantBytesRead: 2,
		},
		{
			name:          "empty input returns 0 and len(data)",
			data:          []byte{},
			wantVal:       0,
			wantBytesRead: 0,
		},
		{
			name: "malformed varint all continuation bits set returns 0 and len(data)",
			// 10 bytes all with MSB set = malformed (no termination)
			data:          []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
			wantVal:       0,
			wantBytesRead: 11, // len(data)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVal, gotBytes := readVarint(tt.data)
			if gotVal != tt.wantVal {
				t.Errorf("readVarint() val = %d, want %d", gotVal, tt.wantVal)
			}
			if gotBytes != tt.wantBytesRead {
				t.Errorf("readVarint() bytesRead = %d, want %d", gotBytes, tt.wantBytesRead)
			}
		})
	}
}

func TestIsDuplicate(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		s     string
		want  bool
	}{
		{
			name:  "empty slice returns false",
			slice: []string{},
			s:     "grpc.health.v1.Health",
			want:  false,
		},
		{
			name:  "string not in slice returns false",
			slice: []string{"grpc.health.v1.Health", "myapp.v1.UserService"},
			s:     "other.v1.Service",
			want:  false,
		},
		{
			name:  "string in slice returns true",
			slice: []string{"grpc.health.v1.Health", "myapp.v1.UserService"},
			s:     "grpc.health.v1.Health",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDuplicate(tt.slice, tt.s)
			if got != tt.want {
				t.Errorf("isDuplicate(%v, %q) = %v, want %v", tt.slice, tt.s, got, tt.want)
			}
		})
	}
}

func TestParseReflectionResponse_DuplicateServices(t *testing.T) {
	// Construct a response with the same service name appearing twice.
	// Both entries should deduplicate to just one result.
	svcName := []byte("grpc.health.v1.Health")

	// Build first ServiceResponse entry
	inner1 := append([]byte{0x0a, byte(len(svcName))}, svcName...)
	entry1 := append([]byte{0x0a, byte(len(inner1))}, inner1...)

	// Build second ServiceResponse entry with the same name
	inner2 := append([]byte{0x0a, byte(len(svcName))}, svcName...)
	entry2 := append([]byte{0x0a, byte(len(inner2))}, inner2...)

	listData := append(entry1, entry2...)
	fullResp := append([]byte{0x32, byte(len(listData))}, listData...)

	got := parseReflectionResponse(fullResp)
	if len(got) != 1 {
		t.Errorf("parseReflectionResponse() with duplicate service names: got %d services, want 1; services=%v", len(got), got)
	}
	if len(got) > 0 && got[0] != "grpc.health.v1.Health" {
		t.Errorf("parseReflectionResponse() service[0] = %q, want %q", got[0], "grpc.health.v1.Health")
	}
}

func TestParseReflectionResponse_ShortServiceNames(t *testing.T) {
	// Service names with len <= 2 should be filtered out.
	// "a." is exactly 2 chars, which should be filtered (len > 2 check).
	shortName := []byte("a.")

	inner := append([]byte{0x0a, byte(len(shortName))}, shortName...)
	entry := append([]byte{0x0a, byte(len(inner))}, inner...)
	fullResp := append([]byte{0x32, byte(len(entry))}, entry...)

	got := parseReflectionResponse(fullResp)
	if len(got) != 0 {
		t.Errorf("parseReflectionResponse() with short service name %q: got %d services, want 0; services=%v", "a.", len(got), got)
	}
}
