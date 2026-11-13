package postgres

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestPostgresSSLRequestThenTLS10(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go servePostgresSSLThen10(c)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	service, err := (&POSTGRESPlugin{}).Run(conn, 2*time.Second, plugins.Target{
		Host:       "127.0.0.1",
		Address:    netip.MustParseAddrPort(tcpAddr.String()),
		Misconfigs: true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if service == nil {
		t.Fatal("nil service")
	}
	found := false
	for _, f := range service.SecurityFindings {
		if f.ID == "tls-weak-version-10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing tls-weak-version-10: %+v", service.SecurityFindings)
	}
}

func servePostgresSSLThen10(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	if n == 8 {
		_, _ = c.Write([]byte{'S'})
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		nbody := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, nbody)
		if _, err := io.ReadFull(c, body); err != nil {
			return
		}
		shBody := []byte{0x03, 0x01}
		shBody = append(shBody, make([]byte, 32)...)
		shBody = append(shBody, 0x00, 0x00, 0x2f, 0x00)
		hs := []byte{0x02, 0x00, 0x00, byte(len(shBody))}
		hs = append(hs, shBody...)
		rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
		_, _ = c.Write(append(rec, hs...))
		return
	}
	_, _ = c.Write(buildAuthMD5Packet())
}
