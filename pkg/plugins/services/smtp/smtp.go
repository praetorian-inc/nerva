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

package smtp

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type SMTPPlugin struct{}
type TLSPlugin struct{}

const SMTP = "smtp"
const SMTPS = "smtps"

type Data struct {
	Banner      string
	AuthMethods []string
}

func init() {
	plugins.RegisterPlugin(&SMTPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

func (p *SMTPPlugin) PortPriority(port uint16) bool {
	return port == 25 || port == 587 || port == 465 || port == 2525
}

func handleSMTPConn(response []byte) (bool, bool) {
	// Checks for an expected response on CONNECTION ESTABLISHMENT
	// RFC 5321 Section 4.3.2
	validResponses := []string{"220", "421", "500", "501", "554"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// Received a valid response code on connection
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// Received a valid error response code on connection
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func handleSMTPHelo(response []byte) (bool, bool) {
	// Checks for an expected response from the HELO command
	// RFC 5321 Section 4.3.2
	validResponses := []string{"250", "421", "500", "501", "502", "504", "550"}
	isSMTP := false
	isSMTPErr := false
	for i := 0; i < len(validResponses); i++ {
		if bytes.Equal(response[0:3], []byte(validResponses[i])) {
			// HELO command received a valid response code
			isSMTP = true
			if bytes.Equal(response[0:1], []byte("4")) || bytes.Equal(response[0:1], []byte("5")) {
				// HELO command received a valid error response code
				isSMTPErr = true
			}
			break
		}
	}
	return isSMTP, isSMTPErr
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 465
}

func DetectSMTP(conn net.Conn, tls bool, timeout time.Duration) (Data, bool, error) {
	protocol := SMTP
	if tls {
		protocol = SMTPS
	}

	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError := handleSMTPConn(response)
	if !isSMTP && !smtpError {
		return Data{}, true, &utils.InvalidResponseError{Service: protocol}
	}

	banner := make([]byte, len(response))
	copy(banner, response)

	// Send the EHLO message
	smtpEhloCommand := []byte("EHLO example.com\r\n")
	response, err = utils.SendRecv(conn, smtpEhloCommand, timeout)
	if err != nil {
		return Data{}, false, err
	}
	if len(response) == 0 {
		return Data{}, true, &utils.ServerNotEnable{}
	}

	isSMTP, smtpError = handleSMTPHelo(response)
	if !isSMTP {
		return Data{}, true, &utils.InvalidResponseErrorInfo{
			Service: protocol,
			Info:    "invalid SMTP Helo response",
		}
	}

	// a valid smtperror means it is smtp
	if smtpError {
		data := Data{
			Banner: string(banner),
		}

		return data, true, nil
	}

	if isSMTP {
		data := Data{
			Banner:      string(banner),
			AuthMethods: strings.Split(strings.ReplaceAll(string(response), "-", " "), " "),
		}

		return data, true, nil
	}

	return Data{}, true, &utils.InvalidResponseError{Service: protocol}
}

// checkOpenRelay sends MAIL FROM and RCPT TO with non-local addresses to test
// whether the server will relay mail. Returns true if the server accepts relay.
func checkOpenRelay(conn net.Conn, timeout time.Duration) bool {
	// Send MAIL FROM with external address
	resp, err := utils.SendRecv(conn, []byte("MAIL FROM:<test@example.com>\r\n"), timeout)
	if err != nil || len(resp) < 3 || !bytes.Equal(resp[0:3], []byte("250")) {
		// MAIL FROM rejected or error — no transaction to reset
		return false
	}

	// Send RCPT TO with a different external domain
	resp, err = utils.SendRecv(conn, []byte("RCPT TO:<test@example.org>\r\n"), timeout)

	// Always clean up
	_, _ = utils.SendRecv(conn, []byte("RSET\r\n"), timeout)

	if err != nil || len(resp) < 3 {
		return false
	}
	// 250 = accepted relay → open relay confirmed
	// 251 = "User not local; will forward" (RFC 5321 §3.3) → also confirms open relay
	return bytes.Equal(resp[0:3], []byte("250")) || bytes.Equal(resp[0:3], []byte("251"))
}

func (p *SMTPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, check, err := DetectSMTP(conn, false, timeout)
	if err == nil && check {
		payload := plugins.ServiceSMTP{
			Banner:      data.Banner,
			AuthMethods: data.AuthMethods,
		}
		service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
		if target.Misconfigs {
			if len(data.AuthMethods) > 0 {
				hasAuth := false
				for _, method := range data.AuthMethods {
					if strings.EqualFold(strings.TrimRight(method, "\r\n"), "AUTH") {
						hasAuth = true
						break
					}
				}
				if !hasAuth {
					service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
						ID:          "smtp-no-auth",
						Severity:    plugins.SeverityLow,
						Description: "SMTP server does not advertise AUTH capability in EHLO response",
						Evidence:    "EHLO response lacks AUTH capability",
					})
				}
				if checkOpenRelay(conn, timeout) {
					service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
						ID:          "smtp-open-relay",
						Severity:    plugins.SeverityHigh,
						Description: "SMTP server accepts mail relay between non-local addresses",
						Evidence:    "Server accepted RCPT TO:<test@example.org> after MAIL FROM:<test@example.com>",
					})
				}
			}
			if ehloHasToken(data.AuthMethods, "STARTTLS") && smtpSTARTTLSCommand(conn, timeout) {
				var dial func() (net.Conn, error)
				if addr := conn.RemoteAddr(); addr != nil {
					a := addr.String()
					dial = func() (net.Conn, error) { return dialSMTPReadyForTLS(target, a, timeout) }
				}
				cfg := &tls.Config{InsecureSkipVerify: true, ServerName: target.Host} // #nosec G402 -- scanner
				tconn := tls.Client(conn, cfg)
				var findings []plugins.SecurityFinding
				tlsOK := false
				if err := tconn.Handshake(); err == nil {
					findings = plugins.CheckTLS(&plugins.RawDialConn{Conn: tconn, Dial: dial})
					tlsOK = true
				} else if dial != nil {
					findings = plugins.ProbeTLSMisconfigs(dial, target.Host)
					tlsOK = len(findings) > 0
				}
				cleartext := plugins.SecurityFinding{
					ID:          "smtp-cleartext",
					Severity:    plugins.SeverityLow,
					Description: "SMTP transmits data including credentials in cleartext",
					Evidence:    data.Banner,
				}
				if tlsOK {
					service.SecurityFindings = append(append([]plugins.SecurityFinding{cleartext}, service.SecurityFindings...), findings...)
				} else {
					service.SecurityFindings = append([]plugins.SecurityFinding{cleartext}, service.SecurityFindings...)
				}
			} else {
				service.SecurityFindings = append([]plugins.SecurityFinding{{
					ID:          "smtp-cleartext",
					Severity:    plugins.SeverityLow,
					Description: "SMTP transmits data including credentials in cleartext",
					Evidence:    data.Banner,
				}}, service.SecurityFindings...)
			}
		}
		return service, nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, check, err := DetectSMTP(conn, false, timeout)
	if err == nil && check {
		payload := plugins.ServiceSMTP{
			Banner:      data.Banner,
			AuthMethods: data.AuthMethods,
		}
		service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCP)
		if target.Misconfigs {
			service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
		}
		return service, nil
	} else if err != nil && check {
		return nil, nil
	}
	return nil, err
}

func (p *SMTPPlugin) Name() string {
	return SMTP
}
func (p *SMTPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Name() string {
	return SMTPS
}
func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *SMTPPlugin) Priority() int {
	return 60
}

func (p *TLSPlugin) Priority() int {
	return 61
}

func ehloHasToken(methods []string, token string) bool {
	joined := strings.ToUpper(strings.Join(methods, " "))
	return strings.Contains(joined, strings.ToUpper(token))
}

func smtpSTARTTLSCommand(conn net.Conn, timeout time.Duration) bool {
	resp, err := utils.SendRecv(conn, []byte("STARTTLS\r\n"), timeout)
	if err != nil || len(resp) < 3 {
		return false
	}
	return bytes.Equal(resp[0:3], []byte("220"))
}

func dialSMTPReadyForTLS(target plugins.Target, addr string, timeout time.Duration) (net.Conn, error) {
	c, err := target.FollowupTCP(addr, timeout)
	if err != nil {
		return nil, err
	}
	if _, err := smtpRecvReply(c, timeout); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := smtpSendRecvReply(c, []byte("EHLO example.com\r\n"), timeout); err != nil {
		c.Close()
		return nil, err
	}
	resp, err := smtpSendRecvReply(c, []byte("STARTTLS\r\n"), timeout)
	if err != nil {
		c.Close()
		return nil, err
	}
	if len(resp) < 3 || !bytes.Equal(resp[0:3], []byte("220")) {
		c.Close()
		return nil, &utils.InvalidResponseErrorInfo{Service: SMTP, Info: "STARTTLS rejected"}
	}
	return c, nil
}

func smtpSendRecvReply(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	if err := utils.Send(conn, data, timeout); err != nil {
		return nil, err
	}
	return smtpRecvReply(conn, timeout)
}

func smtpRecvReply(conn net.Conn, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	var all []byte
	for time.Now().Before(deadline) {
		chunk, err := utils.Recv(conn, time.Until(deadline))
		if err != nil {
			if len(all) > 0 {
				return all, nil
			}
			return nil, err
		}
		if len(chunk) == 0 {
			break
		}
		all = append(all, chunk...)
		if smtpReplyComplete(all) {
			return all, nil
		}
	}
	return all, nil
}

func smtpReplyComplete(b []byte) bool {
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if len(line) >= 4 && line[0] >= '2' && line[0] <= '5' && line[3] == ' ' {
			return true
		}
	}
	return false
}
