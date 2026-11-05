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

// Package main implements a mock ManageSieve (RFC 5804) TCP server for
// integration testing. It writes a Dovecot Pigeonhole-style greeting
// immediately upon connection and closes.
package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const DefaultPort = "4190"

// greeting is a Dovecot Pigeonhole-style ManageSieve greeting (RFC 5804).
const greeting = "\"IMPLEMENTATION\" \"Dovecot Pigeonhole\"\r\n" +
	"\"SIEVE\" \"fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date ihave\"\r\n" +
	"\"NOTIFY\" \"mailto\"\r\n" +
	"\"SASL\" \"PLAIN LOGIN\"\r\n" +
	"\"STARTTLS\"\r\n" +
	"\"VERSION\" \"1.0\"\r\n" +
	"OK \"Dovecot ready.\"\r\n"

// handleConnection writes the ManageSieve greeting and closes the connection.
func handleConnection(conn net.Conn) {
	defer conn.Close()

	if _, err := conn.Write([]byte(greeting)); err != nil {
		log.Printf("Error writing greeting to %s: %v", conn.RemoteAddr(), err)
		return
	}

	log.Printf("Sent ManageSieve greeting to %s", conn.RemoteAddr())
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

	log.Printf("ManageSieve mock server listening on port %s", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

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

	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)
}
