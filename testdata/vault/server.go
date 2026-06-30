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

// Package main implements mock HashiCorp Vault HTTP servers for integration testing.
// Four listeners are started:
//   - Port 8200: Unsealed Vault      (initialized=true, sealed=false)
//   - Port 8201: Sealed Vault        (initialized=true, sealed=true)
//   - Port 8202: Generic HTTP        (no Vault indicators, Server: nginx/1.24.0)
//   - Port 8203: Uninitialized Vault (initialized=false, sealed=true)
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

const vaultVersion = "1.16.3"

func vaultHealthHandler(initialized, sealed bool) http.HandlerFunc {
	sealedStr := "false"
	if sealed {
		sealedStr = "true"
	}
	initializedStr := "false"
	if initialized {
		initializedStr = "true"
	}
	body := fmt.Sprintf(
		`{"initialized":%s,"sealed":%s,"version":%q,"cluster_name":"test-cluster","enterprise":false}`,
		initializedStr, sealedStr, vaultVersion,
	)
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[port %q] %s %q from %s", r.Host, r.Method, r.URL.Path, r.RemoteAddr)
		if r.URL.Path != "/v1/sys/health" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
}

func genericHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[port 8202] %s %q from %s", r.Method, r.URL.Path, r.RemoteAddr)
	w.Header().Set("Server", "nginx/1.24.0")
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, "OK")
}

func startServer(addr string, handler http.Handler) *http.Server {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server %s error: %v", addr, err)
		}
	}()
	log.Printf("Mock server listening on %s", addr)
	return srv
}

func main() {
	unsealedMux := http.NewServeMux()
	unsealedMux.HandleFunc("/", vaultHealthHandler(true, false))

	sealedMux := http.NewServeMux()
	sealedMux.HandleFunc("/", vaultHealthHandler(true, true))

	genericMux := http.NewServeMux()
	genericMux.HandleFunc("/", genericHandler)

	uninitMux := http.NewServeMux()
	uninitMux.HandleFunc("/", vaultHealthHandler(false, true))

	s1 := startServer(":8200", unsealedMux)
	s2 := startServer(":8201", sealedMux)
	s3 := startServer(":8202", genericMux)
	s4 := startServer(":8203", uninitMux)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, srv := range []*http.Server{s1, s2, s3, s4} {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}
}
