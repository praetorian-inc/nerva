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
	"context"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPCPlugin implements gRPC service fingerprinting.
// It detects any service speaking the gRPC protocol over HTTP/2 and
// enriches with metadata about reflection and health check availability.
type GRPCPlugin struct{}

const GRPC = "grpc"

func init() {
	plugins.RegisterPlugin(&GRPCPlugin{})
}

func (p *GRPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build target address from target.Address (NOT target.Host which may be empty for IP-only scans)
	targetAddr := target.Address.String()

	// Primary detection: establish gRPC connection (validates HTTP/2 handshake)
	grpcConn, err := utils.GRPCDialWithTimeout(targetAddr, timeout)
	if err != nil {
		return nil, err
	}
	defer grpcConn.Close()

	// gRPC specificity check: call a known-invalid method.
	// True gRPC servers respond with gRPC status codes.
	// Plain HTTP/2 servers return different errors.
	if !isGRPCServer(grpcConn, timeout) {
		return nil, nil
	}

	payload := plugins.ServiceGRPC{}

	// Enrichment: try reflection
	reflectionEnabled, services := tryReflection(grpcConn, timeout)
	payload.ReflectionEnabled = reflectionEnabled
	payload.Services = services

	// Enrichment: try health check
	payload.HealthStatus = tryHealthCheck(grpcConn, timeout)

	svc := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)

	// Security finding: reflection exposed
	if target.Misconfigs && reflectionEnabled {
		finding := plugins.SecurityFinding{
			ID:          "grpc-reflection-exposed",
			Severity:    plugins.SeverityMedium,
			Description: "gRPC Server Reflection is enabled, exposing service and method definitions",
		}
		if len(services) > 0 {
			finding.Evidence = fmt.Sprintf("Exposed services: %v", services)
		}
		svc.SecurityFindings = append(svc.SecurityFindings, finding)
	}

	return svc, nil
}

// isGRPCServer verifies the remote is a true gRPC server (not just HTTP/2).
// It calls a known-invalid gRPC method and checks for a gRPC status code response.
func isGRPCServer(conn *grpc.ClientConn, timeout time.Duration) bool {
	_, err := utils.GRPCInvokeUnary(conn, "/grpc.invalid/Probe", []byte{}, timeout, grpc.ForceCodec(utils.RawBytesCodec{}))
	if err == nil {
		// Unexpected success - still gRPC
		return true
	}
	_, ok := status.FromError(err)
	if !ok {
		// Not a gRPC status error - likely plain HTTP/2
		return false
	}
	// Any gRPC status code means this is a gRPC server.
	// Typical responses: Unimplemented, NotFound, PermissionDenied, Unauthenticated.
	return true
}

// tryReflection attempts to enumerate services via gRPC Server Reflection.
// Uses bidirectional streaming via conn.NewStream() since ServerReflectionInfo
// is a streaming RPC (not unary).
func tryReflection(conn *grpc.ClientConn, timeout time.Duration) (bool, []string) {
	// Try v1alpha first (most widely deployed), then v1
	methods := []string{
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
	}

	// Hand-encoded protobuf: ServerReflectionRequest { list_services: "" }
	// Field 7, wire type 2 (length-delimited), length 0
	listServicesReq := []byte{0x3a, 0x00}

	for _, method := range methods {
		enabled, services := tryReflectionMethod(conn, method, listServicesReq, timeout)
		if enabled {
			return true, services
		}
	}
	return false, nil
}

func tryReflectionMethod(conn *grpc.ClientConn, method string, request []byte, timeout time.Duration) (bool, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create stream descriptor for bidirectional streaming
	streamDesc := &grpc.StreamDesc{
		StreamName:    "ServerReflectionInfo",
		ServerStreams: true,
		ClientStreams: true,
	}

	stream, err := conn.NewStream(ctx, streamDesc, method, grpc.ForceCodec(utils.RawBytesCodec{}))
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unimplemented {
			return false, nil
		}
		// Other error - could be transient, assume not available
		return false, nil
	}

	// Send the ListServices request
	if err := stream.SendMsg(request); err != nil {
		return false, nil
	}

	// Close the send side
	if err := stream.CloseSend(); err != nil {
		return false, nil
	}

	// Receive response
	var response []byte
	if err := stream.RecvMsg(&response); err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unimplemented {
			return false, nil
		}
		// Got an error but method was found - reflection is registered
		return true, nil
	}

	// Parse service names from response
	services := parseReflectionResponse(response)
	return true, services
}

// tryHealthCheck probes the standard gRPC Health Check service.
func tryHealthCheck(conn *grpc.ClientConn, timeout time.Duration) string {
	method := "/grpc.health.v1.Health/Check"
	// Empty HealthCheckRequest = check overall server health
	resp, err := utils.GRPCInvokeUnary(conn, method, []byte{}, timeout, grpc.ForceCodec(utils.RawBytesCodec{}))
	if err != nil {
		return ""
	}
	return parseHealthStatus(resp)
}

// parseHealthStatus extracts the health status from a HealthCheckResponse protobuf.
// HealthCheckResponse has field 1 (status) as an enum varint:
// 0=UNKNOWN, 1=SERVING, 2=NOT_SERVING, 3=SERVICE_UNKNOWN
func parseHealthStatus(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Look for field 1 (tag 0x08 = field 1, wire type 0 varint)
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x08 {
			val := data[i+1]
			switch val {
			case 0:
				return "UNKNOWN"
			case 1:
				return "SERVING"
			case 2:
				return "NOT_SERVING"
			case 3:
				return "SERVICE_UNKNOWN"
			default:
				return ""
			}
		}
	}
	return ""
}

// parseReflectionResponse extracts service names from a ServerReflectionResponse.
// The response has three-level nesting:
//
//	ServerReflectionResponse {
//	  list_services_response (field 6): ListServiceResponse {
//	    service (field 1): repeated ServiceResponse {
//	      name (field 1): string "grpc.health.v1.Health"
//	    }
//	  }
//	}
//
// This is best-effort parsing of raw protobuf without importing reflection proto types.
func parseReflectionResponse(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var services []string
	extractServiceNames(data, &services)
	return services
}

// extractServiceNames recursively walks protobuf data looking for string fields
// that look like gRPC service names (contain dots, printable ASCII).
func extractServiceNames(data []byte, services *[]string) {
	extractServiceNamesDepth(data, services, 0)
}

func extractServiceNamesDepth(data []byte, services *[]string, depth int) {
	if depth > 10 {
		return
	}
	i := 0
	for i < len(data) {
		tag := data[i]
		i++
		wireType := tag & 0x07

		switch wireType {
		case 0: // varint - skip
			for i < len(data) && data[i]&0x80 != 0 {
				i++
			}
			if i < len(data) {
				i++
			}
		case 1: // 64-bit (fixed64, sfixed64, double)
			if i+8 > len(data) {
				return
			}
			i += 8
		case 2: // length-delimited
			if i >= len(data) {
				return
			}
			// Read varint length
			length, bytesRead := readVarint(data[i:])
			i += bytesRead
			if length < 0 || length > len(data)-i {
				return
			}
			fieldData := data[i : i+length]
			i += length

			// Check if this is a service name string
			if isServiceName(fieldData) {
				name := string(fieldData)
				if len(name) > 2 && !isDuplicate(*services, name) {
					*services = append(*services, name)
				}
			} else if length > 0 {
				// Recurse into nested message
				extractServiceNamesDepth(fieldData, services, depth+1)
			}
		case 5: // 32-bit (fixed32, sfixed32, float)
			if i+4 > len(data) {
				return
			}
			i += 4
		default:
			// Unknown wire type, stop parsing this level
			return
		}
	}
}

// readVarint reads a protobuf varint from data and returns (value, bytesRead).
func readVarint(data []byte) (int, int) {
	val := 0
	shift := 0
	for i := 0; i < len(data) && i < 10; i++ {
		b := int(data[i])
		val |= (b & 0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			return val, i + 1
		}
	}
	// Malformed varint - return 0 consumed bytes to trigger bounds check
	return 0, len(data)
}

func isServiceName(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	hasDot := false
	for _, b := range data {
		if b == '.' {
			hasDot = true
			continue
		}
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '_' || b == '-' {
			continue
		}
		return false
	}
	// gRPC service names typically contain dots (package.ServiceName)
	return hasDot
}

func isDuplicate(slice []string, s string) bool {
	for _, existing := range slice {
		if existing == s {
			return true
		}
	}
	return false
}

func (p *GRPCPlugin) PortPriority(port uint16) bool {
	return port == 50051 || port == 9090
}

func (p *GRPCPlugin) Name() string {
	return GRPC
}

func (p *GRPCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *GRPCPlugin) Priority() int {
	return 300
}
