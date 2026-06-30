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

// Package main implements a mock DrayTek Vigor router HTTP server for integration testing
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
	DefaultPort     = "8080"
	ModelName       = "Vigor3910"
	FirmwareVersion = "4.4.5.3"
)

// webloginPage returns the HTML body for the DrayTek login page at /weblogin.htm
func webloginPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>DrayTek %s</title>
  <script>
    var fwVersion="%s";
  </script>
</head>
<body>
  <div id="brand">DrayTek</div>
  <div id="model">%s</div>
  <form method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" />
  </form>
</body>
</html>
`, ModelName, FirmwareVersion, ModelName)
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
		log.Printf("GET / from %s — redirecting to /weblogin.htm", r.RemoteAddr)
		http.Redirect(w, r, "/weblogin.htm", http.StatusFound)
	})

	mux.HandleFunc("/weblogin.htm", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /weblogin.htm from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, webloginPage())
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("DrayTek mock server listening on port %s", port)

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
