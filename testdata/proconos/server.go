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

// Package main implements a mock ProConOS TCP server for integration testing
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	// Protocol constants
	ProbeSignature           = 0xcc
	ResponseSignature        = 0xcc
	LadderLogicRuntimeOffset = 13
	PLCTypeOffset            = 45
	ProjectNameOffset        = 78
	DefaultPort              = "20547"
)

// buildProConOSResponse creates a mock ProConOS protocol response
func buildProConOSResponse() []byte {
	// Response must be at least long enough for all fields
	response := make([]byte, 150)
	response[0] = ResponseSignature // Valid ProConOS signature

	// Add Ladder Logic Runtime at offset 13
	ladderRuntime := "3.5.0.10"
	copy(response[LadderLogicRuntimeOffset:], ladderRuntime)
	response[LadderLogicRuntimeOffset+len(ladderRuntime)] = 0x00 // Null terminator

	// Add PLC Type at offset 45
	plcType := "ProConOS"
	copy(response[PLCTypeOffset:], plcType)
	response[PLCTypeOffset+len(plcType)] = 0x00

	// Add Project Name at offset 78
	projectName := "TestProject"
	copy(response[ProjectNameOffset:], projectName)
	response[ProjectNameOffset+len(projectName)] = 0x00

	// Add Boot Project after Project Name
	bootProjectOffset := ProjectNameOffset + len(projectName) + 1
	bootProject := "BootProj"
	copy(response[bootProjectOffset:], bootProject)
	response[bootProjectOffset+len(bootProject)] = 0x00

	// Add Project Source Code after Boot Project
	sourceCodeOffset := bootProjectOffset + len(bootProject) + 1
	sourceCode := "Source.pro"
	copy(response[sourceCodeOffset:], sourceCode)
	response[sourceCodeOffset+len(sourceCode)] = 0x00

	return response
}

// handleConnection handles a single client connection
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read probe packet (10 bytes expected)
	buf := make([]byte, 10)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading from connection: %v", err)
		return
	}

	if n < 1 {
		log.Printf("Received empty request")
		return
	}

	// Validate probe starts with 0xcc
	if buf[0] != ProbeSignature {
		log.Printf("Invalid probe signature: 0x%02x (expected 0x%02x)", buf[0], ProbeSignature)
		return
	}

	log.Printf("Received valid ProConOS probe from %s", conn.RemoteAddr())

	// Send ProConOS response
	response := buildProConOSResponse()
	_, err = conn.Write(response)
	if err != nil {
		log.Printf("Error writing response: %v", err)
		return
	}

	log.Printf("Sent ProConOS response to %s", conn.RemoteAddr())
}

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer listener.Close()

	log.Printf("ProConOS mock server listening on port %s", port)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Accept connections in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("Error accepting connection: %v", err)
				continue
			}

			go handleConnection(conn)
		}
	}()

	// Wait for shutdown signal
	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
}
