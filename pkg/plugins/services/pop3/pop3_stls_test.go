package pop3

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestPOP3STLSThenTLS10EmitsWeakVersionNotCleartext(t *testing.T) {
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
			go servePOP3STLSThen10(c)
		}
	}()

	tcpAddr := ln.Addr().(*net.TCPAddr)
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	service, err := (&POP3Plugin{}).Run(conn, 2*time.Second, plugins.Target{
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
	ids := map[string]bool{}
	for _, f := range service.SecurityFindings {
		ids[f.ID] = true
	}
	if ids["pop3-cleartext"] {
		t.Fatalf("STLS-then-1.0 emitted pop3-cleartext: %+v", service.SecurityFindings)
	}
	if !ids["tls-weak-version-10"] {
		t.Fatalf("missing tls-weak-version-10: %+v", service.SecurityFindings)
	}
}

func servePOP3STLSThen10(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write([]byte("+OK POP3 server ready\r\n"))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	if !strings.Contains(strings.ToUpper(string(buf[:n])), "STLS") {
		_, _ = c.Write([]byte("-ERR unknown command\r\n"))
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
	_, _ = c.Write([]byte("+OK Begin TLS\r\n"))
	writeTLS10ServerHello(c)
}

func writeTLS10ServerHello(c net.Conn) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(hdr[3:5]))
	body := make([]byte, n)
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
}
