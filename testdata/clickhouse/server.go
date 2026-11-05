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

// Package main implements a mock ClickHouse server exposing both the native
// TCP protocol (port 9000) and the HTTP interface (port 8123) for
// integration testing.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	DefaultNativePort = "9000"
	DefaultHTTPPort   = "8123"

	// packetTypeHello is the ClickHouse native protocol packet type sent by
	// clients as the first packet of a connection.
	packetTypeHello = 0

	serverName      = "ClickHouse"
	serverVersion   = "24.8.3.53"
	versionMajor    = 24
	versionMinor    = 8
	versionPatch    = 3
	protocolVersion = 54401
	timezone        = "UTC"
	displayName     = "clickhouse-mock"

	// maxVarUIntBytes bounds LEB128 decoding so a malformed/malicious client
	// cannot force an unbounded read loop.
	maxVarUIntBytes = 10
	// maxStringLen bounds the length prefix on incoming strings to avoid
	// huge allocations from a malformed length field.
	maxStringLen = 1 << 20 // 1MB

	connReadTimeout = 10 * time.Second
)

// readVarUInt reads a LEB128-encoded unsigned varint from r.
func readVarUInt(r io.Reader) (uint64, error) {
	var (
		result uint64
		shift  uint
		buf    [1]byte
	)
	for i := 0; i < maxVarUIntBytes; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		b := buf[0]
		result |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("varuint too long")
}

// writeVarUInt writes v to w using LEB128 encoding.
func writeVarUInt(w io.Writer, v uint64) error {
	var buf []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if v == 0 {
			break
		}
	}
	_, err := w.Write(buf)
	return err
}

// readClickHouseString reads a VarUInt-length-prefixed string from r.
func readClickHouseString(r io.Reader) (string, error) {
	n, err := readVarUInt(r)
	if err != nil {
		return "", err
	}
	if n > maxStringLen {
		return "", fmt.Errorf("string length %d exceeds max %d", n, maxStringLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// writeClickHouseString writes s to w as a VarUInt-length-prefixed string.
func writeClickHouseString(w io.Writer, s string) error {
	if err := writeVarUInt(w, uint64(len(s))); err != nil {
		return err
	}
	_, err := io.WriteString(w, s)
	return err
}

// readClientHello reads and validates an incoming ClientHello packet,
// returning an error if the connection does not present a valid Hello.
func readClientHello(r io.Reader) error {
	packetType, err := readVarUInt(r)
	if err != nil {
		return fmt.Errorf("reading packet type: %w", err)
	}
	if packetType != packetTypeHello {
		return fmt.Errorf("unexpected packet type %d, expected Hello (%d)", packetType, packetTypeHello)
	}

	if _, err := readClickHouseString(r); err != nil { // client_name
		return fmt.Errorf("reading client_name: %w", err)
	}
	if _, err := readVarUInt(r); err != nil { // version_major
		return fmt.Errorf("reading version_major: %w", err)
	}
	if _, err := readVarUInt(r); err != nil { // version_minor
		return fmt.Errorf("reading version_minor: %w", err)
	}
	if _, err := readVarUInt(r); err != nil { // protocol_version
		return fmt.Errorf("reading protocol_version: %w", err)
	}
	if _, err := readClickHouseString(r); err != nil { // database
		return fmt.Errorf("reading database: %w", err)
	}
	if _, err := readClickHouseString(r); err != nil { // user
		return fmt.Errorf("reading user: %w", err)
	}
	if _, err := readClickHouseString(r); err != nil { // password
		return fmt.Errorf("reading password: %w", err)
	}

	return nil
}

// writeServerHello writes a ServerHello response packet to w.
func writeServerHello(w io.Writer) error {
	if err := writeVarUInt(w, packetTypeHello); err != nil {
		return err
	}
	if err := writeClickHouseString(w, serverName); err != nil {
		return err
	}
	if err := writeVarUInt(w, versionMajor); err != nil {
		return err
	}
	if err := writeVarUInt(w, versionMinor); err != nil {
		return err
	}
	if err := writeVarUInt(w, protocolVersion); err != nil {
		return err
	}
	if err := writeClickHouseString(w, timezone); err != nil {
		return err
	}
	if err := writeClickHouseString(w, displayName); err != nil {
		return err
	}
	if err := writeVarUInt(w, versionPatch); err != nil {
		return err
	}
	return nil
}

// handleNativeConnection services a single native protocol TCP connection.
func handleNativeConnection(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(connReadTimeout)); err != nil {
		log.Printf("Error setting deadline for %s: %v", conn.RemoteAddr(), err)
		return
	}

	reader := bufio.NewReader(conn)
	if err := readClientHello(reader); err != nil {
		log.Printf("Invalid ClientHello from %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("Received valid ClientHello from %s", conn.RemoteAddr())

	writer := bufio.NewWriter(conn)
	if err := writeServerHello(writer); err != nil {
		log.Printf("Error writing ServerHello to %s: %v", conn.RemoteAddr(), err)
		return
	}
	if err := writer.Flush(); err != nil {
		log.Printf("Error flushing ServerHello to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("Sent ServerHello to %s", conn.RemoteAddr())
}

// runNativeServer accepts native protocol connections until listener is closed.
func runNativeServer(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go handleNativeConnection(conn)
	}
}

func setClickHouseHeaders(w http.ResponseWriter) {
	w.Header().Set("X-ClickHouse-Summary", "{}")
	w.Header().Set("X-ClickHouse-Server-Display-Name", displayName)
}

func httpHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")

	switch query {
	case "SELECT version()":
		log.Printf("%s %s?query=%s from %s", r.Method, r.URL.Path, query, r.RemoteAddr)
		setClickHouseHeaders(w)
		w.Header().Set("X-ClickHouse-Query-Id", "mock-query-id")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "%s\n", serverVersion)
	default:
		log.Printf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		setClickHouseHeaders(w)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ok.\n")
	}
}

func main() {
	nativePort := DefaultNativePort
	if p := os.Getenv("NATIVE_PORT"); p != "" {
		nativePort = p
	}
	httpPort := DefaultHTTPPort
	if p := os.Getenv("HTTP_PORT"); p != "" {
		httpPort = p
	}

	listener, err := net.Listen("tcp", ":"+nativePort)
	if err != nil {
		log.Fatalf("Failed to start native protocol listener: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", httpHandler)

	httpSrv := &http.Server{
		Addr:              ":" + httpPort,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("ClickHouse mock native protocol server listening on port %s", nativePort)
	log.Printf("ClickHouse mock HTTP interface listening on port %s", httpPort)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go runNativeServer(listener)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}
	if err := listener.Close(); err != nil {
		log.Printf("Native listener close error: %v", err)
	}
}
