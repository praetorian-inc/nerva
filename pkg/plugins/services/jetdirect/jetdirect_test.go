package jetdirect

import (
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn is a net.Conn that returns pre-defined sequential responses and
// captures written bytes. Used to test functions that interact with the wire
// protocol without requiring a real network connection.
type mockConn struct {
	net.Conn
	readData  [][]byte
	readIndex int
	written   [][]byte
}

func (m *mockConn) Read(b []byte) (int, error) {
	if m.readIndex >= len(m.readData) {
		return 0, io.EOF
	}
	n := copy(b, m.readData[m.readIndex])
	m.readIndex++
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.written = append(m.written, append([]byte{}, b...))
	return len(b), nil
}

func (m *mockConn) SetDeadline(t time.Time) error     { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }

func TestDetectPJL(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     bool
		wantID   string
	}{
		{
			"HP LaserJet",
			[]byte("@PJL INFO ID\r\n\"HP LaserJet 4250\"\r\n"),
			true,
			"HP LaserJet 4250",
		},
		{
			"Brother with firmware",
			[]byte("@PJL INFO ID\r\n\"Brother HL-L2360D series:84U-F75:Ver.b.26\"\r\n"),
			true,
			"Brother HL-L2360D series:84U-F75:Ver.b.26",
		},
		{
			"Ricoh",
			[]byte("@PJL INFO ID\r\n\"RICOH Aficio MP C3503\"\r\n"),
			true,
			"RICOH Aficio MP C3503",
		},
		{
			"No PJL marker",
			[]byte("Some random response\r\n"),
			false,
			"",
		},
		{
			"Empty response",
			[]byte{},
			false,
			"",
		},
		{
			"PJL but no ID",
			[]byte("@PJL INFO STATUS\r\nCODE=10001\r\n"),
			false,
			"",
		},
		{
			"HP unquoted response",
			[]byte("@PJL INFO ID\r\nhp LaserJet 4200\r\n"),
			true,
			"hp LaserJet 4200",
		},
		{
			"Unquoted with trailing whitespace",
			[]byte("@PJL INFO ID\r\nBrother HL-2270DW  \r\n"),
			true,
			"Brother HL-2270DW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, id := detectPJL(tt.response)
			assert.Equal(t, tt.want, detected, "Detection mismatch")
			assert.Equal(t, tt.wantID, id, "ID mismatch")
		})
	}
}

func TestExtractVendorModel(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		wantVendor string
		wantModel  string
	}{
		{"HP LaserJet", "HP LaserJet 4250", "hp", "LaserJet 4250"},
		{"Brother with serial", "Brother HL-L2360D series:84U-F75:Ver.b.26", "brother", "HL-L2360D series"},
		{"Ricoh", "RICOH Aficio MP C3503", "ricoh", "Aficio MP C3503"},
		{"Canon", "Canon iR-ADV C5235", "canon", "iR-ADV C5235"},
		{"Xerox", "Xerox WorkCentre 7855", "xerox", "WorkCentre 7855"},
		{"Lexmark", "Lexmark MS812de", "lexmark", "MS812de"},
		{"Epson", "EPSON AL-M400DN", "epson", "AL-M400DN"},
		{"Samsung", "Samsung CLX-9301", "samsung", "CLX-9301"},
		{"Sharp", "SHARP MX-3070N", "sharp", "MX-3070N"},
		{"Oki", "OKI C844", "oki", "C844"},
		{"Dell", "Dell Color Laser 3110cn", "dell", "Color Laser 3110cn"},
		{"Toshiba", "TOSHIBA e-STUDIO5560C", "toshiba", "e-STUDIO5560C"},
		{"Zebra", "Zebra ZT410", "zebra", "ZT410"},
		{"Pantum", "Pantum M6800FDW", "pantum", "M6800FDW"},
		{"Unknown vendor", "SomeUnknown Printer Model", "", "SomeUnknown Printer Model"},
		{"Empty string", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, model := extractVendorModel(tt.id)
			assert.Equal(t, tt.wantVendor, vendor, "Vendor mismatch")
			assert.Equal(t, tt.wantModel, model, "Model mismatch")
		})
	}
}

func TestExtractFirmware(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		wantFirmware string
	}{
		{"Brother firmware", "Brother HL-L2360D series:84U-F75:Ver.b.26", "b.26"},
		{"No firmware", "HP LaserJet 4250", ""},
		{"Empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fw := extractFirmware(tt.id)
			assert.Equal(t, tt.wantFirmware, fw)
		})
	}
}

func TestBuildJetDirectCPE(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		model    string
		firmware string
		wantCPE  string
	}{
		{"HP with wildcard", "hp", "LaserJet 4250", "", "cpe:2.3:h:hp:laserjet_4250:*:*:*:*:*:*:*:*"},
		{"Brother with firmware", "brother", "HL-L2360D series", "b.26", "cpe:2.3:h:brother:hl_l2360d:b.26:*:*:*:*:*:*:*"},
		{"No vendor", "", "Model", "", ""},
		{"No model", "hp", "", "", ""},
		{"Both empty", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildJetDirectCPE(tt.vendor, tt.model, tt.firmware)
			assert.Equal(t, tt.wantCPE, cpe)
		})
	}
}

func TestJetDirect(t *testing.T) {
	// Note: There is no standard JetDirect Docker image.
	// This test uses a mock PJL server if available, or is skipped.
	// For live testing, use: fingerprintx -t <printer-ip>:9100 --json
	t.Skip("No standard JetDirect Docker image available; use live printer testing")
}

func TestNormalizeModel(t *testing.T) {
	tests := []struct {
		name  string
		model string
		want  string
	}{
		{"spaces become underscores", "LaserJet 4250", "laserjet_4250"},
		{"series suffix stripped", "HL-L2360D series", "hl_l2360d"},
		{"hyphens become underscores", "WorkCentre 7855", "workcentre_7855"},
		{"empty string", "", ""},
		{"already lowercase no spaces", "ml1710", "ml1710"},
		{"mixed case with hyphen and space", "Aficio MP-C3503", "aficio_mp_c3503"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeModel(tt.model)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestEnrichStatus(t *testing.T) {
	timeout := 5 * time.Second

	tests := []struct {
		name       string
		responses  [][]byte
		wantStatus string
	}{
		{
			name:       "DISPLAY Ready",
			responses:  [][]byte{[]byte("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\n")},
			wantStatus: "Ready",
		},
		{
			name:       "DISPLAY Sleeping with status code",
			responses:  [][]byte{[]byte("CODE=10001\r\nDISPLAY=\"Sleeping\"\r\n")},
			wantStatus: "Sleeping",
		},
		{
			name:       "empty response returns empty string",
			responses:  [][]byte{{}},
			wantStatus: "",
		},
		{
			name:       "no DISPLAY field returns empty string",
			responses:  [][]byte{[]byte("@PJL INFO STATUS\r\nCODE=10001\r\n")},
			wantStatus: "",
		},
		{
			name:       "EOF from connection returns empty string",
			responses:  [][]byte{},
			wantStatus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.responses}
			got := enrichStatus(conn, timeout)
			assert.Equal(t, tt.wantStatus, got)
		})
	}
}

func TestEnrichFilesystemAccess(t *testing.T) {
	timeout := 5 * time.Second

	tests := []struct {
		name      string
		responses [][]byte
		wantFS    bool
	}{
		{
			name:      "TYPE=DIR indicates filesystem access",
			responses: [][]byte{[]byte("@PJL FSDIRLIST\r\nNAME=\"0:\\\" COUNT=1\r\nENTRY NAME=\"CONFIG.INI\" TYPE=FILE SIZE=128\r\n")},
			wantFS:    true,
		},
		{
			name:      "ENTRY keyword alone indicates filesystem access",
			responses: [][]byte{[]byte("ENTRY NAME=\"AUTORUN.INF\"\r\n")},
			wantFS:    true,
		},
		{
			name:      "TYPE= anywhere in response indicates filesystem access",
			responses: [][]byte{[]byte("@PJL FSDIRLIST\r\nTYPE=DIR\r\n")},
			wantFS:    true,
		},
		{
			name:      "empty response returns false",
			responses: [][]byte{{}},
			wantFS:    false,
		},
		{
			name:      "EOF from connection returns false",
			responses: [][]byte{},
			wantFS:    false,
		},
		{
			name:      "response without filesystem markers returns false",
			responses: [][]byte{[]byte("@PJL FSDIRLIST\r\nFILESYS ERROR=33\r\n")},
			wantFS:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.responses}
			got := enrichFilesystemAccess(conn, timeout)
			assert.Equal(t, tt.wantFS, got)
		})
	}
}

func TestEnrichFirmwareFromConfig(t *testing.T) {
	timeout := 5 * time.Second

	tests := []struct {
		name         string
		responses    [][]byte
		wantFirmware string
	}{
		{
			name:         "HP firmware datecode",
			responses:    [][]byte{[]byte("@PJL INFO CONFIG\r\nFIRMWARE DATECODE=20150327\r\nPAGES=12345\r\n")},
			wantFirmware: "20150327",
		},
		{
			name:         "firmware version format",
			responses:    [][]byte{[]byte("FIRMWARE=V4.2.1\r\n")},
			wantFirmware: "V4.2.1",
		},
		{
			name:         "empty response",
			responses:    [][]byte{{}},
			wantFirmware: "",
		},
		{
			name:         "no firmware in config",
			responses:    [][]byte{[]byte("@PJL INFO CONFIG\r\nPAPERSIZE=LETTER\r\n")},
			wantFirmware: "",
		},
		{
			name:         "EOF",
			responses:    [][]byte{},
			wantFirmware: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.responses}
			got := enrichFirmwareFromConfig(conn, timeout)
			assert.Equal(t, tt.wantFirmware, got)
		})
	}
}

func TestRunPlugin(t *testing.T) {
	plugin := &JetDirectPlugin{}
	timeout := 5 * time.Second
	target := plugins.Target{
		Host:    "192.168.1.100",
		Address: netip.AddrPortFrom(netip.MustParseAddr("192.168.1.100"), 9100),
	}

	t.Run("full flow returns detected service with enrichment", func(t *testing.T) {
		conn := &mockConn{
			readData: [][]byte{
				// Phase 1: PJL INFO ID response
				[]byte("@PJL INFO ID\r\n\"HP LaserJet 4250\"\r\n"),
				// Phase 2 firmware fallback: PJL INFO CONFIG response (no firmware found)
				[]byte("@PJL INFO CONFIG\r\nPAPERSIZE=LETTER\r\n"),
				// Phase 2a: PJL INFO STATUS response
				[]byte("@PJL INFO STATUS\r\nCODE=10001\r\nDISPLAY=\"Ready\"\r\n"),
				// Phase 2b: FSDIRLIST response
				[]byte("@PJL FSDIRLIST\r\nENTRY NAME=\"ROOT\" TYPE=DIR\r\n"),
			},
		}

		svc, err := plugin.Run(conn, timeout, target)

		require.NoError(t, err)
		require.NotNil(t, svc)

		assert.Equal(t, "192.168.1.100", svc.IP)
		assert.Equal(t, 9100, svc.Port)
		assert.Equal(t, "jetdirect", svc.Protocol)
		assert.Equal(t, "tcp", svc.Transport)

		var meta plugins.ServiceJetDirect
		require.NoError(t, json.Unmarshal(svc.Raw, &meta))
		assert.Equal(t, "hp", meta.Manufacturer)
		assert.Equal(t, "LaserJet 4250", meta.Model)
		assert.Equal(t, "HP LaserJet 4250", meta.RawID)
		assert.Equal(t, "Ready", meta.Status)
		assert.True(t, meta.FilesystemAccess)
		assert.NotEmpty(t, meta.CPEs)
		assert.Contains(t, meta.CPEs[0], "cpe:2.3:h:hp:laserjet_4250")
	})

	t.Run("non-PJL response returns nil service and nil error", func(t *testing.T) {
		conn := &mockConn{
			readData: [][]byte{
				[]byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"),
			},
		}

		svc, err := plugin.Run(conn, timeout, target)

		assert.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("connection error on first read returns nil service and error", func(t *testing.T) {
		// Empty readData causes io.EOF on first Read. pluginutils.Recv treats
		// io.EOF as a ReadError (non-timeout, non-ECONNREFUSED), so Run returns
		// nil service and a non-nil error.
		conn := &mockConn{
			readData: [][]byte{},
		}

		svc, err := plugin.Run(conn, timeout, target)

		assert.Error(t, err)
		assert.Nil(t, svc)
	})

	t.Run("Brother printer detected with firmware version", func(t *testing.T) {
		conn := &mockConn{
			readData: [][]byte{
				[]byte("@PJL INFO ID\r\n\"Brother HL-L2360D series:84U-F75:Ver.b.26\"\r\n"),
				[]byte("@PJL INFO STATUS\r\nDISPLAY=\"Sleeping\"\r\n"),
				[]byte("@PJL FSDIRLIST\r\nFILESYS ERROR=33\r\n"),
			},
		}

		svc, err := plugin.Run(conn, timeout, target)

		require.NoError(t, err)
		require.NotNil(t, svc)

		var meta plugins.ServiceJetDirect
		require.NoError(t, json.Unmarshal(svc.Raw, &meta))
		assert.Equal(t, "brother", meta.Manufacturer)
		assert.Equal(t, "HL-L2360D series", meta.Model)
		assert.Equal(t, "b.26", meta.Firmware)
		assert.Equal(t, "Sleeping", meta.Status)
		assert.False(t, meta.FilesystemAccess)
		assert.Equal(t, "b.26", svc.Version)
	})

	t.Run("unknown vendor sets empty manufacturer", func(t *testing.T) {
		conn := &mockConn{
			readData: [][]byte{
				[]byte("@PJL INFO ID\r\n\"SomePrinter X100\"\r\n"),
				[]byte{},
				[]byte{},
			},
		}

		svc, err := plugin.Run(conn, timeout, target)

		require.NoError(t, err)
		require.NotNil(t, svc)

		var meta plugins.ServiceJetDirect
		require.NoError(t, json.Unmarshal(svc.Raw, &meta))
		assert.Equal(t, "", meta.Manufacturer)
		assert.Equal(t, "SomePrinter X100", meta.Model)
		// No CPE when vendor is unknown
		assert.Empty(t, meta.CPEs)
	})
}
