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

// Package main implements a mock OpenSearch HTTP server for integration
// testing. It serves the OpenSearch root API (cluster info JSON) at "/" and
// a minimal OpenSearch Dashboards HTML page at "/dashboards".
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

const DefaultPort = "9200"

const openSearchRootJSON = `{
  "name" : "opensearch-node",
  "cluster_name" : "opensearch-cluster",
  "cluster_uuid" : "abc-123",
  "version" : {
    "distribution" : "opensearch",
    "number" : "2.11.0",
    "build_type" : "tar",
    "build_hash" : "hash123",
    "build_date" : "2023-11-15T00:00:00Z",
    "build_snapshot" : false,
    "lucene_version" : "9.7.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}`

const openSearchDashboardsHTML = `<!DOCTYPE html>
<html>
<head>
  <title>OpenSearch Dashboards</title>
  <osd-injected-metadata data="{}"></osd-injected-metadata>
</head>
<body>
  <div id="osd-body"></div>
</body>
</html>`

const dashboardsVersion = "2.11.0"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/dashboards", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /dashboards from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("osd-version", dashboardsVersion)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, openSearchDashboardsHTML)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		log.Printf("GET / from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, openSearchRootJSON)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("OpenSearch mock server listening on port %s", port)

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
