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

// Package main implements a mock phpMyAdmin HTTP server for integration testing.
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
	MockVersion     = "5.2.1"
	MockSetupCookie = "phpMyAdmin=abc123"
)

// loginPage returns the HTML body for the phpMyAdmin login page, served at
// /phpmyadmin/, /pma/, and /phpMyAdmin/. It includes:
//   - <title>phpMyAdmin</title> for Signal 1 (standalone title match)
//   - name="pma_username" login form field for Signal 2 (paired with the
//     Set-Cookie: phpMyAdmin= header set by the handler)
//   - a phpmyadmin.css.php?...&v=5.2.1 asset link for version extraction
func loginPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <title>phpMyAdmin</title>
  <link rel="stylesheet" type="text/css" href="./phpmyadmin.css.php?nocache=123&amp;v=%s">
</head>
<body>
  <form method="post" id="login_form" action="index.php" name="login_form">
    <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield">
    <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield">
    <input type="submit" value="Go">
  </form>
</body>
</html>
`, MockVersion)
}

// setupPage returns the HTML body for the phpMyAdmin first-run setup page,
// served at /phpmyadmin/setup/. Matches real phpMyAdmin setup page structure:
// the title is "phpMyAdmin setup" (not "phpMyAdmin"), and the heading has NO
// version number. The shared phpmyadmin.css.php asset link is still present,
// so version extraction succeeds via the asset URL even on the setup page.
func setupPage() string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <title>phpMyAdmin setup</title>
  <link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?nocache=abc123&amp;v=%s">
</head>
<body>
  <h1>
    <span class="blue">php</span><span class="orange">MyAdmin</span>
    setup
  </h1>
  <div id="page">
    <form id="setupForm" method="post" action="config.php">
      <input type="hidden" name="token" value="abc123">
    </form>
  </div>
</body>
</html>
`, MockVersion)
}

// genericApachePage returns a generic Apache default page body, unrelated to
// phpMyAdmin, served at / for false-positive testing.
func genericApachePage() string {
	return `<!DOCTYPE html>
<html>
<head>
  <title>Apache2 Debian Default Page</title>
</head>
<body>
  <h1>It works!</h1>
</body>
</html>
`
}

func servePhpMyAdmin(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)
	w.Header().Set("Set-Cookie", MockSetupCookie+"; path=/; HttpOnly")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, loginPage())
}

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/phpmyadmin/", servePhpMyAdmin)
	mux.HandleFunc("/pma/", servePhpMyAdmin)
	mux.HandleFunc("/phpMyAdmin/", servePhpMyAdmin)

	mux.HandleFunc("/phpmyadmin/setup/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /phpmyadmin/setup/ from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, setupPage())
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		log.Printf("GET / from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, genericApachePage())
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("phpMyAdmin mock server listening on port %s", port)

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
