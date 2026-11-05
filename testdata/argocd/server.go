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

// Package main implements a mock Argo CD HTTP server for integration testing.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const DefaultPort = "8080"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /api/version from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"Version":          "v2.9.3+6eba5be",
			"BuildDate":        "2024-01-01T00:00:00Z",
			"GitCommit":        "6eba5be1234567890abcdef1234567890abcdef",
			"GoVersion":        "go1.21.5",
			"Compiler":         "gc",
			"Platform":         "linux/amd64",
			"KsonnetVersion":   "v0.13.1",
			"KustomizeVersion": "v4.5.7",
			"HelmVersion":      "v3.13.2",
		}); err != nil {
			log.Printf("encode error: %v", err)
			return
		}
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /login from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Argo CD</title>
</head>
<body>
  <noscript>You need to enable JavaScript to run this app.</noscript>
  <div id="app"></div>
</body>
</html>`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		log.Printf("GET / from %s, redirecting to /login", r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Argo CD mock server listening on port %s", port)

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
