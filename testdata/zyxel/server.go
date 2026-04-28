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

// Package main implements a mock Zyxel ATP firewall HTTP server for integration testing
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

const (
	DefaultPort     = "443"
	ModelName       = "ATP200"
	FirmwareVersion = "V5.38(ABZH.0)"
)

// handlerPage returns the HTML body for the ZLD login page at /ztp/cgi-bin/handler
func handlerPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>Zyxel %s</title>
</head>
<body>
  <div id="brand">Zyxel</div>
  <div id="model">%s</div>
  <div id="firmware">%s</div>
  <form action="/weblogin.cgi" method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" />
  </form>
</body>
</html>
`, ModelName, ModelName, FirmwareVersion)
}

// webloginPage returns the HTML body for the /weblogin.cgi page
func webloginPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>Zyxel %s - Web Login</title>
</head>
<body>
  <div id="brand">Zyxel</div>
  <div id="model">%s</div>
  <div id="firmware">%s</div>
  <form method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" />
  </form>
</body>
</html>
`, ModelName, ModelName, FirmwareVersion)
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
		log.Printf("GET / from %s — redirecting to /ztp/cgi-bin/handler", r.RemoteAddr)
		http.Redirect(w, r, "/ztp/cgi-bin/handler", http.StatusFound)
	})

	mux.HandleFunc("/ztp/cgi-bin/handler", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /ztp/cgi-bin/handler from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, handlerPage())
	})

	mux.HandleFunc("/weblogin.cgi", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /weblogin.cgi from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, webloginPage())
	})

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("Zyxel mock server listening on port %s", port)

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
}
