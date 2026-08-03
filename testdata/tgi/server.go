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

// Package main implements a mock HuggingFace Text Generation Inference (TGI)
// HTTP server for integration testing.
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

const tgiMetrics = `# HELP tgi_request_count Total number of requests
# TYPE tgi_request_count counter
tgi_request_count 42
# HELP tgi_request_success Number of successful requests
# TYPE tgi_request_success counter
tgi_request_success 40
# HELP tgi_queue_size Current queue size
# TYPE tgi_queue_size gauge
tgi_queue_size 0
# HELP tgi_batch_current_size Current batch size
# TYPE tgi_batch_current_size gauge
tgi_batch_current_size 0
`

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /info from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"model_id":                "meta-llama/Meta-Llama-3-70B-Instruct",
			"model_sha":               nil,
			"model_pipeline_tag":      nil,
			"max_concurrent_requests": 128,
			"max_best_of":             2,
			"max_stop_sequences":      4,
			"max_input_tokens":        8191,
			"max_total_tokens":        8192,
			"waiting_served_ratio":    0.3,
			"max_batch_total_tokens":  1259392,
			"max_waiting_tokens":      20,
			"max_batch_size":          nil,
			"validation_workers":      32,
			"max_client_batch_size":   4,
			"router":                  "text-generation-router",
			"version":                 "2.0.2",
			"sha":                     "dccab72549635c7eb5ddb17f43f0b7cdff07c214",
			"docker_label":            "sha-dccab72",
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /metrics from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, tgiMetrics)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /health from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("TGI mock server listening on port %s", port)

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
