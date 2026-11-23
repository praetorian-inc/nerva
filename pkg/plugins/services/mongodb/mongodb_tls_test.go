// Copyright 2026 Praetorian Security, Inc.
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

package mongodb_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/services/mongodb"
	"github.com/praetorian-inc/nerva/pkg/scan"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mongo.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSOnlyMongoDB starts a mock MongoDB that, like net.tls.mode=requireTLS,
// only speaks the wire protocol inside TLS. It returns the listening port.
func startTLSOnlyMongoDB(t *testing.T, addr string) uint16 {
	t.Helper()
	listener, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}})
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go mongodb.HandleMongoDBConnForTest(conn, true)
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

// TestScanFindsMongoDBBehindTLS runs the real scan path against a TLS-only
// MongoDB. Before the TLS plugin existed the scan returned no service.
//
// It listens on the default MongoDB port so the scan takes the fast lane, and
// is skipped when that port is already in use.
func TestScanFindsMongoDBBehindTLS(t *testing.T) {
	port := startTLSOnlyMongoDB(t, "127.0.0.1:27017")
	cfg := &scan.Config{DefaultTimeout: 2 * time.Second}
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
	}

	services, err := cfg.SimpleScanTarget(target)
	if err != nil {
		t.Fatalf("SimpleScanTarget returned error: %v", err)
	}
	var found *plugins.Service
	for _, s := range services {
		if s.Protocol == "mongodb" {
			found = s
		}
	}
	if found == nil {
		t.Fatalf("no mongodb service found behind TLS, got %d services", len(services))
	}
	if !found.TLS {
		t.Errorf("service.TLS = false, want true")
	}
	if found.Transport != "tcptls" {
		t.Errorf("service.Transport = %q, want tcptls", found.Transport)
	}
}

func TestMongoDBTLSPluginRun(t *testing.T) {
	port := startTLSOnlyMongoDB(t, "127.0.0.1:0")
	conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := plugins.Target{Host: "127.0.0.1", Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)}

	svc, err := (&mongodb.MONGODBTLSPlugin{}).Run(conn, 2*time.Second, target)
	if err != nil || svc == nil {
		t.Fatalf("Run() = %v, %v, want a service", svc, err)
	}
	if !svc.TLS || svc.Transport != "tcptls" {
		t.Errorf("TLS=%v Transport=%q, want true/tcptls", svc.TLS, svc.Transport)
	}
}

func TestMongoDBTLSPluginMetadata(t *testing.T) {
	tcp := &mongodb.MONGODBPlugin{}
	tlsP := &mongodb.MONGODBTLSPlugin{}
	if tlsP.Name() != tcp.Name() || tlsP.Name() != "mongodb" {
		t.Errorf("Name() = %q, want mongodb", tlsP.Name())
	}
	if tlsP.Type() != plugins.TCPTLS || tcp.Type() != plugins.TCP {
		t.Errorf("Type() tls=%v tcp=%v", tlsP.Type(), tcp.Type())
	}
	if !tlsP.PortPriority(27017) || tlsP.PortPriority(27018) {
		t.Errorf("PortPriority should match 27017 only")
	}
}
