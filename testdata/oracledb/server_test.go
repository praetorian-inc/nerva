package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	tests := []struct {
		in      string
		want    mode
		wantErr bool
	}{
		{"tns-only", modeTNSOnly, false},
		{"auth-required", modeAuthRequired, false},
		{"no-auth", modeNoAuth, false},
		{"", modeTNSOnly, false},
		{"garbage", 0, true},
	}
	for _, tt := range tests {
		got, err := parseMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseMode(%q) err=nil, want error", tt.in)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("parseMode(%q)=%v,%v want %v,nil", tt.in, got, err, tt.want)
		}
	}
}

func TestConnectField(t *testing.T) {
	desc := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=XE)(SID=ORCL)(CID=(PROGRAM=sqlplus)(HOST=x)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1521)))"
	if got := connectField(desc, "SERVICE_NAME"); got != "XE" {
		t.Errorf("SERVICE_NAME=%q want XE", got)
	}
	if got := connectField(desc, "SID"); got != "ORCL" {
		t.Errorf("SID=%q want ORCL", got)
	}
	if got := connectField(desc, "COMMAND"); got != "" {
		t.Errorf("COMMAND=%q want empty", got)
	}
}

func TestLooksLikeLogon(t *testing.T) {
	if looksLikeLogon([]byte{sqlnetSetProtocol, 1, 2, 3}) {
		t.Fatal("set-protocol must not look like logon")
	}
	if !looksLikeLogon([]byte("AUTH_PASSWORD")) {
		t.Fatal("AUTH_PASSWORD should look like logon")
	}
	if !looksLikeLogon([]byte{sqlnetUserOCIFunc, ociLogon, 0x00}) {
		t.Fatal("OCI logon should look like logon")
	}
	if !looksLikeLogon(utf16LE("AUTH_SESSKEY")) {
		t.Fatal("UTF-16 AUTH_SESSKEY should look like logon")
	}
}

func TestUnknownServiceRefusedOnEveryMode(t *testing.T) {
	for _, m := range []mode{modeTNSOnly, modeAuthRequired, modeNoAuth} {
		resp, accepted := handleConnect(connectBody("not-a-real-service"), m)
		if accepted {
			t.Errorf("mode %s accepted unknown service", m)
		}
		assertRefuse(t, resp, 12514)
	}
}

func TestTNSOnlyRefusesKnownService(t *testing.T) {
	resp, accepted := handleConnect(connectBody("XE"), modeTNSOnly)
	if accepted {
		t.Fatal("tns-only accepted XE")
	}
	assertRefuse(t, resp, 12514)
}

func TestAuthModesAcceptKnownService(t *testing.T) {
	for _, m := range []mode{modeAuthRequired, modeNoAuth} {
		resp, accepted := handleConnect(connectBody("XE"), m)
		if !accepted {
			t.Errorf("mode %s refused XE", m)
		}
		if len(resp) < 5 || resp[4] != tnsTypeAccept {
			t.Errorf("mode %s: want Accept, got type %d", m, packetType(resp))
		}
	}
}

func TestLogonAuthRequiredDenied(t *testing.T) {
	resp := handleData(dataPayload([]byte("AUTH_PASSWORD")), modeAuthRequired)
	if !strings.Contains(string(resp), "ORA-01017") {
		t.Fatalf("auth-required logon: want ORA-01017, got %q", resp)
	}
}

func TestLogonNoAuthSucceeds(t *testing.T) {
	resp := handleData(dataPayload([]byte("AUTH_PASSWORD")), modeNoAuth)
	if strings.Contains(string(resp), "ORA-01017") {
		t.Fatal("no-auth logon returned ORA-01017")
	}
	if !strings.Contains(string(resp), "AUTH_SESSION_ID") {
		t.Fatalf("no-auth logon: want AUTH_SESSION_ID, got %q", resp)
	}
	if strings.Contains(string(resp), "AUTH_SESSKEY") {
		t.Fatal("phase-2 success must not be an AUTH_SESSKEY challenge")
	}
}

func TestPhase1ChallengeBothModes(t *testing.T) {
	preauth := dataPayload([]byte{sqlnetUserOCIFunc, ociGetSessKey})
	for _, m := range []mode{modeAuthRequired, modeNoAuth} {
		resp := handleData(preauth, m)
		if !strings.Contains(string(resp), "AUTH_SESSKEY") {
			t.Errorf("mode %s phase-1: want AUTH_SESSKEY, got %q", m, resp)
		}
		if strings.Contains(string(resp), "AUTH_SESSION_ID") {
			t.Errorf("mode %s phase-1 must not return AUTH_SESSION_ID", m)
		}
		if strings.Contains(string(resp), "ORA-01017") {
			t.Errorf("mode %s phase-1 must not return ORA-01017", m)
		}
	}
}

func TestSetProtocolIsNotASession(t *testing.T) {
	resp := handleData(dataPayload([]byte{sqlnetSetProtocol, 0}), modeNoAuth)
	if strings.Contains(string(resp), "ORA-01017") {
		t.Fatal("set-protocol should not be a failed logon")
	}
	if strings.Contains(string(resp), "AUTH_SESSKEY") {
		t.Fatal("set-protocol should not establish a session")
	}
}

func TestLiveTNSOnly(t *testing.T) {
	addr := startMock(t, modeTNSOnly)
	resp := roundTrip(t, addr, buildConnectPacket("XE"))
	assertRefuse(t, resp, 12514)
}

func TestLiveNoAuthSession(t *testing.T) {
	addr := startMock(t, modeNoAuth)

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := c.Write(buildConnectPacket("FREEPDB1")); err != nil {
		t.Fatal(err)
	}
	accept := readOne(t, c)
	if packetType(accept) != tnsTypeAccept {
		t.Fatalf("want Accept, got type %d body %q", packetType(accept), accept)
	}

	if _, err := c.Write(buildData([]byte("AUTH_USER\x00AUTH_PASSWORD\x00"))); err != nil {
		t.Fatal(err)
	}
	logon := readOne(t, c)
	if strings.Contains(string(logon), "ORA-01017") {
		t.Fatalf("no-auth live logon denied: %q", logon)
	}
	if !strings.Contains(string(logon), "AUTH_SESSION_ID") {
		t.Fatalf("no-auth live logon missing AUTH_SESSION_ID: %q", logon)
	}
}

func TestLiveAuthRequiredLogonDenied(t *testing.T) {
	addr := startMock(t, modeAuthRequired)

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := c.Write(buildConnectPacket("ORCL")); err != nil {
		t.Fatal(err)
	}
	accept := readOne(t, c)
	if packetType(accept) != tnsTypeAccept {
		t.Fatalf("want Accept, got type %d", packetType(accept))
	}

	if _, err := c.Write(buildData([]byte("AUTH_PASSWORD"))); err != nil {
		t.Fatal(err)
	}
	logon := readOne(t, c)
	if !strings.Contains(string(logon), "ORA-01017") {
		t.Fatalf("auth-required live logon: want ORA-01017, got %q", logon)
	}
}

func TestDockerComposePostures(t *testing.T) {
	if os.Getenv("ORACLEDB_DOCKER") == "" {
		t.Skip("set ORACLEDB_DOCKER=1 after docker compose up")
	}

	t.Run("tns-only-15213", func(t *testing.T) {
		resp := roundTrip(t, "127.0.0.1:15213", buildConnectPacket("XE"))
		assertRefuse(t, resp, 12514)
	})

	t.Run("auth-required-15212", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:15212", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(buildConnectPacket("XE")); err != nil {
			t.Fatal(err)
		}
		if packetType(readOne(t, c)) != tnsTypeAccept {
			t.Fatal("want Accept for XE")
		}
		if _, err := c.Write(buildData([]byte("AUTH_PASSWORD"))); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(readOne(t, c)), "ORA-01017") {
			t.Fatal("want ORA-01017")
		}
	})

	t.Run("no-auth-15211", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", "127.0.0.1:15211", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write(buildConnectPacket("XE")); err != nil {
			t.Fatal(err)
		}
		if packetType(readOne(t, c)) != tnsTypeAccept {
			t.Fatal("want Accept for XE")
		}
		if _, err := c.Write(buildData([]byte("AUTH_PASSWORD"))); err != nil {
			t.Fatal(err)
		}
		got := readOne(t, c)
		if strings.Contains(string(got), "ORA-01017") {
			t.Fatal("no-auth must not return ORA-01017")
		}
		if !strings.Contains(string(got), "AUTH_SESSION_ID") {
			t.Fatalf("want AUTH_SESSION_ID, got %q", got)
		}
	})
}

func TestRefuseCarriesListenerMarkers(t *testing.T) {
	resp, _ := handleConnect(connectBody("nope"), modeTNSOnly)
	s := string(resp)
	if !strings.Contains(s, "VSNNUM=352321536") {
		t.Errorf("missing VSNNUM: %s", s)
	}
	if !strings.Contains(s, "ERROR_STACK=") {
		t.Errorf("missing ERROR_STACK: %s", s)
	}
	if !strings.Contains(s, "(ERR=12514)") {
		t.Errorf("missing ERR=12514: %s", s)
	}
}

func startMock(t *testing.T, m mode) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(c, m)
		}
	}()
	return ln.Addr().String()
}

func roundTrip(t *testing.T, addr string, req []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	return readOne(t, c)
}

func readOne(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var hdr [8]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatal(err)
	}
	n := int(binary.BigEndian.Uint16(hdr[0:2]))
	if n < 8 {
		t.Fatalf("short TNS length %d", n)
	}
	out := make([]byte, n)
	copy(out, hdr[:])
	if _, err := io.ReadFull(c, out[8:]); err != nil {
		t.Fatal(err)
	}
	return out
}

func packetType(pkt []byte) byte {
	if len(pkt) < 5 {
		return 0
	}
	return pkt[4]
}

func assertRefuse(t *testing.T, pkt []byte, errCode int) {
	t.Helper()
	if packetType(pkt) != tnsTypeRefuse {
		t.Fatalf("want Refuse, got type %d pkt=%q", packetType(pkt), pkt)
	}
	want := "(ERR=" + strconv.Itoa(errCode) + ")"
	if !strings.Contains(string(pkt), want) {
		t.Fatalf("refuse missing %s: %s", want, pkt)
	}
}

// connectBody is the TNS Connect body (no 8-byte header) with offset 58.
func connectBody(service string) []byte {
	pkt := buildConnectPacket(service)
	return pkt[8:]
}

func dataPayload(ttc []byte) []byte {
	p := make([]byte, 2+len(ttc))
	copy(p[2:], ttc)
	return p
}

// buildConnectPacket builds a TNS Connect from the published 8+50-byte layout
// (connect-data offset 58), independent of any Nerva helper.
func buildConnectPacket(service string) []byte {
	desc := "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=" + service +
		")(CID=(PROGRAM=)(HOST=)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=127.0.0.1)(PORT=1521)))"
	const offset = 58
	pkt := make([]byte, offset+len(desc))
	binary.BigEndian.PutUint16(pkt[0:2], uint16(len(pkt)))
	pkt[4] = tnsTypeConnect
	binary.BigEndian.PutUint16(pkt[8:10], 0x013c)
	binary.BigEndian.PutUint16(pkt[10:12], 0x012c)
	binary.BigEndian.PutUint16(pkt[14:16], 0x8000)
	binary.BigEndian.PutUint16(pkt[16:18], 0x7fff)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(len(desc)))
	binary.BigEndian.PutUint16(pkt[26:28], offset)
	copy(pkt[offset:], desc)
	return pkt
}
