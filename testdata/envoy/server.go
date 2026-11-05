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

// Package main implements a mock Envoy admin interface HTTP server for
// integration testing.
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

const (
	DefaultPort = "9901"

	serverInfoJSON = `{
  "version": "c93f9f6c1e5adddd10a3e3646c7e049c649ae177/1.28.0/Clean/RELEASE/BoringSSL",
  "state": "LIVE",
  "hot_restart_version": "11.104",
  "command_line_options": {
    "base_id": "0",
    "concurrency": 2,
    "config_path": "/etc/envoy/envoy.yaml"
  },
  "uptime_current_epoch": "3600s",
  "uptime_all_epochs": "3600s",
  "node": {
    "id": "envoy-mock-1",
    "cluster": "mock-cluster",
    "user_agent_name": "envoy",
    "user_agent_version": "1.28.0"
  }
}`

	adminPage = `<!DOCTYPE html>
<html>
<head>
  <title>Envoy Admin</title>
</head>
<body>
  <h1>Envoy Admin</h1>
  <table>
    <tr><th>Endpoint</th><th>Description</th></tr>
    <tr><td><a href="/server_info">/server_info</a></td><td>print server version/status information</td></tr>
    <tr><td><a href="/stats">/stats</a></td><td>print server stats</td></tr>
    <tr><td><a href="/clusters">/clusters</a></td><td>upstream cluster status</td></tr>
    <tr><td><a href="/config_dump">/config_dump</a></td><td>dump current Envoy configs (json)</td></tr>
  </table>
</body>
</html>
`
)

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
		w.Header().Set("Server", "envoy")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, adminPage)
	})

	mux.HandleFunc("/server_info", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /server_info from %s", r.RemoteAddr)
		w.Header().Set("Server", "envoy")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, serverInfoJSON)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Envoy admin mock server listening on port %s", port)

	// Setup signal handling for graceful shutdown
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
