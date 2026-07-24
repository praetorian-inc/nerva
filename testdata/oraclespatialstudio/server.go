// Mock Oracle Spatial Studio server for integration testing.
//
// MODE env var controls what the container simulates:
//   "login"    - Spatial Studio login SPA only (port 4040)
//   "api"      - Spatial Studio REST API only (port 4040)
//   "full"     - Full Spatial Studio with login + API + OAuth (port 4040)
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "full"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "4040"
	}

	mux := http.NewServeMux()

	if mode == "login" || mode == "full" {
		mux.HandleFunc("/spatialstudio", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/spatialstudio" && r.URL.Path != "/spatialstudio/" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Server", "Jetty(9.4.51.v20230217)")
			fmt.Fprint(w, spatialStudioLoginPage)
		})
	}

	if mode == "api" || mode == "full" {
		mux.HandleFunc("/spatialstudio/api/v1/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Server", "Jetty(9.4.51.v20230217)")
			fmt.Fprint(w, `{"application":"spatialstudio","version":"23.3.0","status":"running"}`)
		})
	}

	if mode == "full" {
		mux.HandleFunc("/spatialstudio/oauth/v1/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Server", "Jetty(9.4.51.v20230217)")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized","message":"Authentication required"}`)
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>404 Not Found</body></html>")
			return
		}
		http.Redirect(w, r, "/spatialstudio", http.StatusFound)
	})

	addr := ":" + port
	fmt.Printf("Spatial Studio mock server starting (mode=%s) on %s\n", mode, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

const spatialStudioLoginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Oracle Spatial Studio</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <script type="text/javascript" src="oraclejet/js/libs/require/require.js"></script>
    <script type="text/javascript" src="oraclejet/js/libs/oj/v12.1.0/debug/ojcore.js"></script>
    <link rel="stylesheet" href="oraclejet/css/libs/oj/v12.1.0/alta/oj-alta.css">
</head>
<body>
    <div id="globalBody">
        <h1>Oracle Spatial Studio</h1>
        <p>Spatial analysis and visualization</p>
        <oj-module config="[[moduleConfig]]">
            <div id="loginContainer">
                <form name="loginForm" method="POST" action="j_security_check">
                    <oj-label for="username">Username</oj-label>
                    <oj-input-text id="username" name="j_username" required></oj-input-text>
                    <oj-label for="password">Password</oj-label>
                    <oj-input-password id="password" name="j_password" required></oj-input-password>
                    <oj-button id="loginBtn" chroming="callToAction">Sign In</oj-button>
                </form>
            </div>
        </oj-module>
        <p class="version">Version 23.3.0</p>
    </div>
</body>
</html>`
