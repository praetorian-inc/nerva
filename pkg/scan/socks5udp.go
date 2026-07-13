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

package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// resolveUnspecifiedRelayIP substitutes an unspecified (0.0.0.0/::) BND.ADDR
// with the control connection's actual resolved remote address. Some SOCKS5
// servers reply with 0.0.0.0 to mean "use the address you connected to"
// rather than announcing a routable address explicitly.
//
// This must use ctrl's already-resolved remote address rather than
// re-parsing the original proxyAddr string: proxyAddr may be a hostname
// (e.g. --proxy socks5://proxy.example.com:1080), and net.ParseIP on a
// hostname silently returns nil. Left unfixed, relayAddr.IP would stay at
// 0.0.0.0, and on Linux connecting a UDP socket to 0.0.0.0 is silently
// treated as 127.0.0.1 - talking to the local machine instead of the real
// (possibly remote) proxy, with no error to signal the mistake.
func resolveUnspecifiedRelayIP(relayIP net.IP, ctrlRemoteAddr net.Addr) net.IP {
	if !relayIP.IsUnspecified() {
		return relayIP
	}
	if tcpAddr, ok := ctrlRemoteAddr.(*net.TCPAddr); ok {
		return tcpAddr.IP
	}
	return relayIP
}

// dialSOCKS5UDP performs a full SOCKS5 UDP ASSOCIATE handshake (RFC 1928
// section 4 and 7) against proxyAddr and returns a net.Conn that relays
// datagrams to targetAddr through the proxy.
//
// golang.org/x/net/proxy (used elsewhere in this package for TCP) does not
// implement the UDP ASSOCIATE command at all: its Dialer.validateTarget
// rejects any network other than "tcp"/"tcp4"/"tcp6" before ever contacting
// the proxy. That made the previous DialUDP fail unconditionally, regardless
// of whether the configured proxy actually supported UDP. This function
// implements the handshake and datagram framing directly instead.
func dialSOCKS5UDP(ctx context.Context, dialer *net.Dialer, proxyAddr, user, pass string, timeout time.Duration, targetAddr string) (net.Conn, error) {
	ctrl, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			ctrl.Close()
		}
	}()

	if timeout > 0 {
		_ = ctrl.SetDeadline(time.Now().Add(timeout))
	}

	if err := socks5Handshake(ctrl, user, pass); err != nil {
		return nil, err
	}

	// UDP ASSOCIATE request. We don't yet know which local address/port we
	// will send from, so per RFC 1928 section 6 we send 0.0.0.0:0 and let
	// the proxy accept datagrams from any source port we later use.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		return nil, fmt.Errorf("failed to send UDP ASSOCIATE request: %w", err)
	}

	relayAddr, err := readSOCKS5Reply(ctrl)
	if err != nil {
		return nil, err
	}

	relayAddr.IP = resolveUnspecifiedRelayIP(relayAddr.IP, ctrl.RemoteAddr())

	udpConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP relay socket: %w", err)
	}

	// The handshake deadline was only meant to bound the negotiation above;
	// callers manage their own read/write deadlines on the returned conn.
	_ = ctrl.SetDeadline(time.Time{})

	targetHost, targetPortStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}
	targetPort, err := strconv.ParseUint(targetPortStr, 10, 16)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("invalid target port %q: %w", targetPortStr, err)
	}

	// Resolve targetHost once now rather than in RemoteAddr(): targetHost
	// can be a domain name (socks5h:// defers resolution to the proxy, see
	// ResolveTargets), and at least one caller (the tftp plugin) uses
	// RemoteAddr() as an actual destination for a follow-up packet, so
	// RemoteAddr() must not silently return a nil IP for that case.
	targetIP := net.ParseIP(targetHost)
	if targetIP == nil {
		if ips, lookupErr := net.LookupIP(targetHost); lookupErr == nil && len(ips) > 0 {
			targetIP = ips[0]
		}
	}

	ok = true
	return &socks5UDPConn{
		ctrl:       ctrl,
		udp:        udpConn,
		targetHost: targetHost,
		targetPort: uint16(targetPort),
		targetIP:   targetIP,
	}, nil
}

// socks5Handshake performs the SOCKS5 method negotiation (RFC 1928 section
// 3) and, if the proxy requires it, username/password authentication
// (RFC 1929).
func socks5Handshake(ctrl net.Conn, user, pass string) error {
	methods := []byte{0x00} // no auth
	if user != "" {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := ctrl.Write(greeting); err != nil {
		return fmt.Errorf("failed to send SOCKS5 greeting: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 method selection: %w", err)
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("unexpected SOCKS version %d in method selection", resp[0])
	}

	switch resp[1] {
	case 0x00:
		return nil
	case 0x02:
		if user == "" {
			return fmt.Errorf("proxy requires username/password authentication")
		}
		if len(user) > 255 || len(pass) > 255 {
			// RFC 1929 ULEN/PLEN are single bytes; byte(len(user)) would
			// silently wrap and corrupt the framing instead of erroring.
			return fmt.Errorf("username/password too long for SOCKS5 auth (max 255 bytes each)")
		}
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)
		if _, err := ctrl.Write(authReq); err != nil {
			return fmt.Errorf("failed to send SOCKS5 auth: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(ctrl, authResp); err != nil {
			return fmt.Errorf("failed to read SOCKS5 auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("SOCKS5 authentication failed (status %d)", authResp[1])
		}
		return nil
	case 0xff:
		return fmt.Errorf("proxy rejected all authentication methods")
	default:
		return fmt.Errorf("unsupported SOCKS5 auth method %d", resp[1])
	}
}

// readSOCKS5Reply reads a SOCKS5 reply (RFC 1928 section 6) and returns the
// BND.ADDR/BND.PORT it carries.
func readSOCKS5Reply(r io.Reader) (*net.UDPAddr, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, fmt.Errorf("failed to read SOCKS5 reply header: %w", err)
	}
	if head[0] != 0x05 {
		return nil, fmt.Errorf("unexpected SOCKS version %d in reply", head[0])
	}
	if head[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 UDP ASSOCIATE failed: %s", socks5ReplyError(head[1]))
	}

	ip, err := readSOCKS5Addr(r, head[3])
	if err != nil {
		return nil, err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return nil, fmt.Errorf("failed to read bind port: %w", err)
	}

	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(portBuf))}, nil
}

func readSOCKS5Addr(r io.Reader, atyp byte) (net.IP, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 bind address: %w", err)
		}
		return net.IP(b), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 bind address: %w", err)
		}
		return net.IP(b), nil
	case 0x03: // domain name
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, fmt.Errorf("failed to read bind domain length: %w", err)
		}
		nameBuf := make([]byte, lb[0])
		if _, err := io.ReadFull(r, nameBuf); err != nil {
			return nil, fmt.Errorf("failed to read bind domain: %w", err)
		}
		ips, err := net.LookupIP(string(nameBuf))
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("failed to resolve bind domain %q: %w", string(nameBuf), err)
		}
		return ips[0], nil
	default:
		return nil, fmt.Errorf("unsupported address type %d in SOCKS5 reply", atyp)
	}
}

func socks5ReplyError(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown error code %d", code)
	}
}

// buildSOCKS5UDPHeader builds the RSV/FRAG/ATYP/DST.ADDR/DST.PORT header
// (RFC 1928 section 7) that must precede every UDP datagram sent through a
// SOCKS5 relay.
func buildSOCKS5UDPHeader(host string, port uint16) ([]byte, error) {
	header := []byte{0x00, 0x00, 0x00} // RSV, RSV, FRAG=0 (no fragmentation)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = append(header, 0x01)
			header = append(header, ip4...)
		} else {
			header = append(header, 0x04)
			header = append(header, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long: %q", host)
		}
		header = append(header, 0x03, byte(len(host)))
		header = append(header, []byte(host)...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)
	return append(header, portBuf...), nil
}

// parseSOCKS5UDPPacket strips the RSV/FRAG/ATYP/DST.ADDR/DST.PORT header
// from a datagram received over a SOCKS5 UDP relay, returning the embedded
// source/destination address and the payload.
func parseSOCKS5UDPPacket(packet []byte) (*net.UDPAddr, []byte, error) {
	if len(packet) < 4 {
		return nil, nil, fmt.Errorf("UDP datagram too short for SOCKS5 header")
	}
	if packet[2] != 0x00 {
		return nil, nil, fmt.Errorf("fragmented SOCKS5 UDP datagrams are not supported")
	}

	atyp := packet[3]
	i := 4
	var ip net.IP
	switch atyp {
	case 0x01:
		if len(packet) < i+4 {
			return nil, nil, fmt.Errorf("truncated IPv4 address in SOCKS5 UDP header")
		}
		ip = net.IP(packet[i : i+4])
		i += 4
	case 0x04:
		if len(packet) < i+16 {
			return nil, nil, fmt.Errorf("truncated IPv6 address in SOCKS5 UDP header")
		}
		ip = net.IP(packet[i : i+16])
		i += 16
	case 0x03:
		if len(packet) < i+1 {
			return nil, nil, fmt.Errorf("truncated domain length in SOCKS5 UDP header")
		}
		domainLen := int(packet[i])
		i++
		if len(packet) < i+domainLen {
			return nil, nil, fmt.Errorf("truncated domain in SOCKS5 UDP header")
		}
		ips, err := net.LookupIP(string(packet[i : i+domainLen]))
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("failed to resolve domain in SOCKS5 UDP header: %w", err)
		}
		ip = ips[0]
		i += domainLen
	default:
		return nil, nil, fmt.Errorf("unsupported address type %d in SOCKS5 UDP header", atyp)
	}

	if len(packet) < i+2 {
		return nil, nil, fmt.Errorf("truncated port in SOCKS5 UDP header")
	}
	port := int(binary.BigEndian.Uint16(packet[i : i+2]))
	i += 2

	return &net.UDPAddr{IP: ip, Port: port}, packet[i:], nil
}

// socks5UDPConn implements net.Conn on top of a SOCKS5 UDP ASSOCIATE
// session: a UDP socket carrying framed datagrams to/from the relay, backed
// by a TCP control connection that must stay open for the association to
// remain valid (closing it tears down the relay on the proxy side).
type socks5UDPConn struct {
	ctrl       net.Conn
	udp        *net.UDPConn
	targetHost string
	targetPort uint16
	targetIP   net.IP // resolved once in dialSOCKS5UDP; may be nil if targetHost couldn't be resolved

	closeOnce sync.Once
	closeErr  error
}

func (c *socks5UDPConn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+320) // room for the largest possible header
	for {
		n, err := c.udp.Read(buf)
		if err != nil {
			return 0, err
		}
		_, payload, err := parseSOCKS5UDPPacket(buf[:n])
		if err != nil {
			// Malformed or fragmented datagram; wait for the next one
			// instead of failing the whole read.
			continue
		}
		return copy(b, payload), nil
	}
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	header, err := buildSOCKS5UDPHeader(c.targetHost, c.targetPort)
	if err != nil {
		return 0, err
	}
	if _, err := c.udp.Write(append(header, b...)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	c.closeOnce.Do(func() {
		udpErr := c.udp.Close()
		ctrlErr := c.ctrl.Close()
		c.closeErr = udpErr
		if c.closeErr == nil {
			c.closeErr = ctrlErr
		}
	})
	return c.closeErr
}

func (c *socks5UDPConn) LocalAddr() net.Addr { return c.udp.LocalAddr() }

func (c *socks5UDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: c.targetIP, Port: int(c.targetPort)}
}

func (c *socks5UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }
