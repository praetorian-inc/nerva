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

// Package main implements a mock Traefik dashboard/API HTTP server for integration testing
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

const DefaultPort = "8080"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		log.Printf("GET / from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>Traefik</title>
</head>
<body>
  <h1>Traefik Dashboard</h1>
</body>
</html>`)
	})

	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /api/overview from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "http": {
    "routers": {"total": 4, "warnings": 0, "errors": 0},
    "services": {"total": 4, "warnings": 0, "errors": 0},
    "middlewares": {"total": 6, "warnings": 0, "errors": 0}
  },
  "tcp": {
    "routers": {"total": 1, "warnings": 0, "errors": 0},
    "services": {"total": 1, "warnings": 0, "errors": 0},
    "middlewares": {"total": 0, "warnings": 0, "errors": 0}
  },
  "udp": {
    "routers": {"total": 0, "warnings": 0, "errors": 0},
    "services": {"total": 0, "warnings": 0, "errors": 0}
  }
}`)
	})

	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /api/version from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
  "Version": "v3.2.0",
  "Codename": "rocamadour",
  "startDate": "2024-10-01T00:00:00Z"
}`)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Traefik mock server listening on port %s", port)

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
