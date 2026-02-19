package main

import (
	"fmt"
	"net"
	"os"
)

// SVN greeting format: ( success ( MIN_VERSION MAX_VERSION ( AUTH_MECHANISMS ) ( CAPABILITIES ) ) )
const svnGreeting = "( success ( 2 2 ( ANONYMOUS ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) ) )\n"

func main() {
	listener, err := net.Listen("tcp", ":3690")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("Mock SVN server listening on :3690")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// SVN sends greeting immediately upon connection (banner-grab)
	_, err := conn.Write([]byte(svnGreeting))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write greeting: %v\n", err)
		return
	}

	// Read any client response (optional, just to keep connection open briefly)
	buf := make([]byte, 1024)
	conn.Read(buf)
}
