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

// Package main implements a mock Sonatype Nexus Repository Manager HTTP
// server for integration testing.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const DefaultPort = "8081"

const nexusServerHeader = "Nexus/3.63.0-01 (PRO)"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/service/rest/v1/status", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /service/rest/v1/status from %s", r.RemoteAddr)
		w.Header().Set("Server", nexusServerHeader)
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.Header().Set("Server", nexusServerHeader)
			http.NotFound(w, r)
			return
		}
		log.Printf("GET / from %s", r.RemoteAddr)
		w.Header().Set("Server", nexusServerHeader)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>Sonatype Nexus Repository</title>
</head>
<body>
  <div id="root"></div>
</body>
</html>`)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Nexus mock server listening on port %s", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}
