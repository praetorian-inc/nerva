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

// Package main implements a mock NAKIVO Backup & Replication HTTP server for integration testing.
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

const DefaultPort = "4443"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/c/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>NAKIVO Backup &amp; Replication</title>
  <script>
    var ROUTER_URL = '/c/router';
    var AUTH_ACTION = 'AuthenticationManagement';
  </script>
</head>
<body>
  <h1>NAKIVO Backup &amp; Replication v10.11.3</h1>
  <form action="/c/router" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Log in">
  </form>
</body>
</html>`)
	})

	mux.HandleFunc("/c/router", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("POST %s from %s", r.URL.Path, r.RemoteAddr)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"action":"AuthenticationManagement","method":"isLogged","type":"rpc","tid":1,"result":{"logged":false}}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s from %s (404)", r.URL.Path, r.RemoteAddr)
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("NAKIVO mock server listening on port %s", port)

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
