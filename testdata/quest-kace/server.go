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

// Package main implements a mock Quest KACE SMA HTTP server for integration testing
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
	DefaultPort      = "8080"
	KACEVersion      = "14.1.101"
	KACEAppliance    = "K1000"
	KACEProductTitle = "KACE Systems Management Appliance"
)

// rootPage returns a basic HTML page for the root path (no KACE signals)
func rootPage() string {
	return `<!DOCTYPE html>
<html>
<head>
  <title>Welcome</title>
</head>
<body>
  <h1>Welcome</h1>
</body>
</html>
`
}

// adminPage returns the HTML body for the KACE SMA admin interface
func adminPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>%s</title>
</head>
<body>
  <h1>%s</h1>
  <div id="appliance-model">%s</div>
  <div id="version">%s</div>
</body>
</html>
`, KACEProductTitle, KACEProductTitle, KACEAppliance, KACEVersion)
}

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
		fmt.Fprint(w, rootPage())
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /admin from %s", r.RemoteAddr)
		w.Header().Set("X-KACE-Version", KACEVersion)
		w.Header().Set("X-KACE-Appliance", KACEAppliance)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, adminPage())
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Quest KACE SMA mock server listening on port %s", port)

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
