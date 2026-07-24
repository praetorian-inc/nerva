// Mock Oracle MFT server for integration testing.
//
// MODE env var controls what the container simulates:
//   "console"  - MFT console login page only
//   "api"      - MFT REST API only
//   "full"     - Full MFT with console + REST API
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
		port = "7011"
	}

	mux := http.NewServeMux()

	if mode == "console" || mode == "full" {
		mux.HandleFunc("/mftconsole", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/mftconsole" || r.URL.Path == "/mftconsole/" {
				http.Redirect(w, r, "/mftconsole/faces/login", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		})
		mux.HandleFunc("/mftconsole/faces/login", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Server", "WebLogic Server")
			fmt.Fprint(w, mftLoginPage)
		})
	}

	if mode == "api" || mode == "full" {
		mux.HandleFunc("/mftapp/rest/v1/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Server", "WebLogic Server")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized","application":"mft","message":"Authentication required for MFT REST API"}`)
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>404 Not Found</body></html>")
			return
		}
		if mode == "console" || mode == "full" {
			http.Redirect(w, r, "/mftconsole", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	addr := ":" + port
	fmt.Printf("MFT mock server starting (mode=%s) on %s\n", mode, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

const mftLoginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Oracle Managed File Transfer</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
    <div id="loginContainer">
        <h1>Oracle Managed File Transfer</h1>
        <p>Fusion Middleware Console</p>
        <form name="loginForm" method="POST" action="j_security_check">
            <label for="j_username">User Name:</label>
            <input type="text" id="j_username" name="j_username">
            <label for="j_password">Password:</label>
            <input type="password" id="j_password" name="j_password">
            <input type="submit" value="Login">
        </form>
        <p class="footer">Oracle Fusion Middleware 12c (12.2.1.4.0)</p>
    </div>
</body>
</html>`
