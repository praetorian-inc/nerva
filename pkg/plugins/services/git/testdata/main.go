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

// Package main implements a mock Git daemon server for integration testing.
//
// The server listens for TCP connections on port 9418 (configurable via
// GIT_PORT environment variable) and responds to git-upload-pack requests
// with a configurable ref advertisement.
//
// Environment variables:
//
//	GIT_PORT     - TCP port to listen on (default: 9418)
//	GIT_REFS     - Comma-separated list of "name:hash" pairs for refs
//	              (default: "refs/heads/main:da39a3ee5e6b4b0d3255bfef95601890afd80709")
//	GIT_CAPS     - Space-separated capability string (default: standard caps)
//	GIT_VERSION  - Protocol version to advertise: "0", "1", or "2" (default: "0")
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const (
	defaultPort    = "9418"
	defaultRefName = "refs/heads/main"
	defaultHash    = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	defaultCaps    = "multi_ack side-band-64k ofs-delta agent=git/2.39.0"
)

// encodePktLine encodes a string into pkt-line format.
func encodePktLine(data string) []byte {
	length := len(data) + 4
	return []byte(fmt.Sprintf("%04x%s", length, data))
}

// buildRefAdvertisement constructs a pkt-line ref advertisement response.
func buildRefAdvertisement(refs []string, caps string, version string) []byte {
	var buf []byte

	// Protocol version line (protocol v1 or v2 only).
	if version == "1" || version == "2" {
		buf = append(buf, encodePktLine("version "+version+"\n")...)
	}

	// Build HEAD ref (first ref gets capabilities appended after NUL).
	headHash := defaultHash
	for _, r := range refs {
		parts := strings.SplitN(r, ":", 2)
		if len(parts) == 2 && parts[0] == "HEAD" {
			headHash = parts[1]
			break
		}
	}

	// HEAD line with capabilities.
	firstLine := headHash + " HEAD\x00" + caps + "\n"
	buf = append(buf, encodePktLine(firstLine)...)

	// Remaining refs.
	for _, r := range refs {
		parts := strings.SplitN(r, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name, hash := parts[0], parts[1]
		if name == "HEAD" {
			// HEAD already written as first line.
			continue
		}
		buf = append(buf, encodePktLine(hash+" "+name+"\n")...)
	}

	// Flush packet.
	buf = append(buf, []byte("0000")...)
	return buf
}

// parseRefsFromEnv parses the GIT_REFS environment variable.
func parseRefsFromEnv() []string {
	refsEnv := os.Getenv("GIT_REFS")
	if refsEnv == "" {
		return []string{
			"HEAD:" + defaultHash,
			defaultRefName + ":" + defaultHash,
		}
	}

	var refs []string
	for _, r := range strings.Split(refsEnv, ",") {
		r = strings.TrimSpace(r)
		if r != "" {
			refs = append(refs, r)
		}
	}
	return refs
}

func handleConnection(conn net.Conn, advertisement []byte) {
	defer conn.Close()

	// Read the git-upload-pack request from the client.
	buf := make([]byte, 512)
	conn.Read(buf)

	// Send the ref advertisement.
	if _, err := conn.Write(advertisement); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing response: %v\n", err)
	}
}

func main() {
	port := os.Getenv("GIT_PORT")
	if port == "" {
		port = defaultPort
	}

	caps := os.Getenv("GIT_CAPS")
	if caps == "" {
		caps = defaultCaps
	}

	version := os.Getenv("GIT_VERSION")
	if version == "" {
		version = "0"
	}

	refs := parseRefsFromEnv()

	// Pre-build the advertisement to send to every client.
	advertisement := buildRefAdvertisement(refs, caps, version)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on port %s: %v\n", port, err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("Mock Git daemon listening on port %s\n", port)
	fmt.Printf("Refs: %v\n", refs)
	fmt.Printf("Caps: %s\n", caps)
	fmt.Printf("Version: %s\n", version)

	// Handle graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		fmt.Println("Shutting down mock Git daemon")
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			// Listener closed — expected on shutdown.
			return
		}
		go handleConnection(conn, advertisement)
	}
}
