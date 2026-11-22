// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package starttls

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/square/certigo/starttls/mysql"
	pq "github.com/square/certigo/starttls/psql"
)

// Protocols are the names of supported protocols
var Protocols = []string{"mysql", "postgres", "psql", "smtp", "ldap", "ftp", "imap"}

// MaxStartTLSAttempts is the maximum number of physical connections a
// StartTLS session will make. A plain TLS connection is always a single
// attempt: retrying is only meaningful for protocol upgrades that can be
// rejected or whose TLS handshake can be restarted on a fresh connection.
const MaxStartTLSAttempts = 2

const (
	stageDial         = "dial"
	stageStartTLS     = "starttls"
	stageTLSHandshake = "tls_handshake"
	stageSMTPHello    = "smtp_hello"
	stageTimeout      = "timeout"
	stageProtocol     = "protocol"
	stageConfig       = "config"
	stageConnect      = "connect"
)

type connectResult struct {
	state *tls.ConnectionState
	err   error
}

// ConnectError records which stage of a connection attempt failed. Error()
// preserves the original error text for callers that print it, while
// ErrorStage lets a retry or report consumer bind the failure to the same
// connection generation as the target and certificate chain.
type ConnectError struct {
	Stage string
	Err   error
}

func (e *ConnectError) Error() string {
	if e == nil || e.Err == nil {
		return "connection error"
	}
	return e.Err.Error()
}

func (e *ConnectError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ErrorStage returns the connection stage recorded in err, or the empty string
// if err did not come from a staged connection attempt.
func ErrorStage(err error) string {
	var connectErr *ConnectError
	if errors.As(err, &connectErr) {
		return connectErr.Stage
	}
	return ""
}

// Config describes one logical connection attempt. It is copied by NewSession
// so callers can freely reuse or mutate their copy after starting a session.
type Config struct {
	StartTLSType string
	ServerName   string
	ConnectTo    string
	Identity     string
	ClientCert   string
	ClientKey    string
	Proxy        *url.URL
	Timeout      time.Duration
}

// Result is the complete result of one logical connection. Only the state and
// certificate request information from the final successful physical
// connection are published; Attempts and FailureStage describe the history of
// that same session without exposing a failed connection's certificate chain.
type Result struct {
	State                  *tls.ConnectionState
	CertificateRequestInfo *tls.CertificateRequestInfo
	Protocol               string
	Target                 string
	Host                   string
	Attempts               int
	Generation             uint64
	FailureStage           string
}

// Session owns the immutable target, protocol, TLS identity and retry budget
// for one logical StartTLS connection. Calling Connect again on the same
// session starts a fresh connection generation; it never resumes or reuses a
// previous TLS handshake, certificate chain or client-certificate request.
type Session struct {
	config Config
}

// NewSession freezes the connection inputs. In particular, the proxy URL is
// copied so later mutation by the caller cannot change an in-flight attempt.
func NewSession(config Config) *Session {
	if config.Proxy != nil {
		proxyCopy := *config.Proxy
		if config.Proxy.User != nil {
			userCopy := *config.Proxy.User
			proxyCopy.User = &userCopy
		}
		config.Proxy = &proxyCopy
	}
	return &Session{config: config}
}

// Connect establishes one logical connection using config.
func Connect(config Config) (*Result, error) {
	return NewSession(config).Connect()
}

var connectionGeneration atomic.Uint64

func nextConnectionGeneration() uint64 {
	return connectionGeneration.Add(1)
}

// Connect establishes a fresh connection and returns only a complete
// connection state. StartTLS protocol rejections and TLS handshake failures
// are retried once on a new connection; dial, timeout, configuration and
// unknown-protocol failures are not retried.
func (s *Session) Connect() (*Result, error) {
	config := s.config
	protocol := config.StartTLSType
	target := config.ConnectTo
	host := HostnameFromConnectTarget(target)
	deadline := time.Now().Add(config.Timeout)

	attemptLimit := 1
	if protocol != "" {
		attemptLimit = MaxStartTLSAttempts
	}

	result := &Result{
		Protocol: protocol,
		Target:   target,
		Host:     host,
	}
	var firstFailureStage string

	// Build the immutable TLS configuration once. Each physical attempt gets
	// a clone with its own client-certificate request callback, so SNI,
	// client identity and cipher policy stay locked while no request
	// information can leak between generations.
	baseTLSConfig, _, err := tlsConfigForConnect(config.ServerName, config.ConnectTo, config.ClientCert, config.ClientKey)
	if err != nil {
		result.Attempts = 1
		result.Generation = nextConnectionGeneration()
		result.FailureStage = stageConfig
		return result, &ConnectError{Stage: stageConfig, Err: err}
	}

	for attempt := 1; attempt <= attemptLimit; attempt++ {
		result.Attempts = attempt
		result.Generation = nextConnectionGeneration()

		remaining := time.Until(deadline)
		if remaining <= 0 {
			result.FailureStage = stageTimeout
			return result, &ConnectError{
				Stage: stageTimeout,
				Err:   fmt.Errorf("error connecting: %w", errors.New("timed out")),
			}
		}

		state, cri, err := connectOnce(config, baseTLSConfig, remaining)
		if err == nil {
			result.State = state
			result.CertificateRequestInfo = cri
			result.FailureStage = firstFailureStage
			return result, nil
		}

		stage := ErrorStage(err)
		if stage == "" {
			stage = stageConnect
		}
		if firstFailureStage == "" {
			firstFailureStage = stage
		}
		result.State = nil
		result.CertificateRequestInfo = nil
		result.FailureStage = stage

		// Configuration errors are not connection attempts by the remote
		// server. Keep the historical, unwrapped error text for them.
		if stage == stageConfig {
			return result, err
		}

		if attempt == attemptLimit || !retryableStage(stage) {
			return result, &ConnectError{
				Stage: stage,
				Err:   fmt.Errorf("error connecting: %w", err),
			}
		}
	}

	// The loop always returns. Keep a defensive error for the compiler.
	return result, &ConnectError{Stage: stageConnect, Err: errors.New("error connecting")}
}

// GetConnectionState is a convenience wrapper around Connect for callers that
// only need the final TLS state and client-certificate request information.
func (s *Session) GetConnectionState() (*tls.ConnectionState, *tls.CertificateRequestInfo, error) {
	result, err := s.Connect()
	if err != nil {
		return nil, nil, err
	}
	return result.State, result.CertificateRequestInfo, nil
}

func retryableStage(stage string) bool {
	return stage == stageStartTLS || stage == stageTLSHandshake
}

func stageForDialError(err error) string {
	return stageForNetworkError(err, stageDial)
}

func stageForNetworkError(err error, fallback string) string {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return stageTimeout
	}
	return fallback
}

func connectOnce(config Config, baseTLSConfig *tls.Config, timeout time.Duration) (*tls.ConnectionState, *tls.CertificateRequestInfo, error) {
	if baseTLSConfig == nil {
		return nil, nil, &ConnectError{Stage: stageConfig, Err: errors.New("missing TLS configuration")}
	}
	tlsConfig, cri := newAttemptTLSConfig(baseTLSConfig)

	var dialer Dialer = &net.Dialer{
		Timeout:  timeout,
		Deadline: time.Now().Add(timeout),
	}

	var err error
	if config.Proxy != nil {
		dialer, err = wrapDialerWithProxy(dialer, config.Proxy, tlsConfig)
		if err != nil {
			return nil, nil, &ConnectError{Stage: stageConfig, Err: err}
		}
	}

	// Two slots are deliberate: when the timeout wins the race, the connection
	// goroutine can still finish and publish its result without blocking
	// forever. The result channel is private to this attempt, so an older
	// connection can never be consumed by a newer one.
	res := make(chan connectResult, 2)
	timer := time.AfterFunc(timeout, func() {
		res <- connectResult{err: &ConnectError{Stage: stageTimeout, Err: errors.New("timed out")}}
	})
	defer timer.Stop()

	go func() {
		res <- connectWithConfig(config, tlsConfig, dialer, timeout)
	}()

	attemptResult := <-res
	if attemptResult.err != nil {
		return nil, nil, attemptResult.err
	}
	if attemptResult.state == nil {
		return nil, nil, &ConnectError{Stage: stageConnect, Err: errors.New("connection state unavailable")}
	}

	var captured *tls.CertificateRequestInfo
	if cri != nil {
		captured = *cri
	}
	if captured != nil && attemptResult.state.Version < tls.VersionTLS12 {
		// Sending supported signature schemes was added in TLS 1.2,
		// but Go lies to us in the GetClientCertificate callback and
		// gives us fake "supported schemes" even for older versions.
		// We clear the result here, otherwise it's a bit misleading.
		captured.SignatureSchemes = nil
	}

	return attemptResult.state, captured, nil
}

func connectWithConfig(config Config, tlsConfig *tls.Config, dialer Dialer, timeout time.Duration) connectResult {
	switch config.StartTLSType {
	case "":
		addr := withDefaultPort(config.ConnectTo, 443)
		conn, err := dialWithDialer(dialer, timeout, "tcp", addr, tlsConfig)
		if err != nil {
			return connectResult{err: err}
		}
		defer func() { _ = conn.Close() }()
		state := conn.ConnectionState()
		return connectResult{state: &state}
	case "ldap":
		addr := withDefaultPort(config.ConnectTo, 389)
		nc, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForDialError(err), Err: err}}
		}
		l := ldap.NewConn(nc, false)
		l.Start()
		defer func() { _ = l.Close() }()

		err = l.StartTLS(tlsConfig)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForNetworkError(err, stageStartTLS), Err: err}}
		}
		s, ok := l.TLSConnectionState()
		if !ok {
			return connectResult{err: &ConnectError{Stage: stageStartTLS, Err: fmt.Errorf("LDAP connection isn't TLS after StartTLS")}}
		}
		state := s
		return connectResult{state: &state}
	case "mysql":
		addr := withDefaultPort(config.ConnectTo, 3306)
		state, err := mysql.DumpTLSWithConfig(
			fmt.Sprintf("%s@tcp(%s)/?tls=true&timeout=%s", config.Identity, addr, timeout.String()),
			tlsConfig,
		)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForNetworkError(err, stageStartTLS), Err: err}}
		}
		return connectResult{state: state}
	case "postgres", "psql":
		// Setting sslmode to "require" skips verification.
		addr := withDefaultPort(config.ConnectTo, 5432)
		uri := fmt.Sprintf("postgres://%s@%s/?sslmode=require&connect_timeout=%d", config.Identity, addr, timeout/time.Second)
		if config.ClientCert != "" {
			uri += fmt.Sprintf("&sslcert=%s", config.ClientCert)
		}
		if config.ClientKey != "" {
			uri += fmt.Sprintf("&sslkey=%s", config.ClientKey)
		}
		state, err := pq.DumpTLSWithConfig(uri, tlsConfig)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForNetworkError(err, stageStartTLS), Err: err}}
		}
		return connectResult{state: state}
	case "smtp":
		// Go's net/smtp doesn't support timeouts, so if we hit a timeout we might
		// leak a Go routine (at least until we hit a lower-level TCP timeout or such).
		// This is not an issue for Certigo since it's just a short-lived CLI utility.
		addr := withDefaultPort(config.ConnectTo, 25)
		client, err := smtp.Dial(addr)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForDialError(err), Err: err}}
		}
		defer func() { _ = client.Close() }()

		err = client.Hello(config.Identity)
		if err != nil {
			return connectResult{err: &ConnectError{Stage: stageForNetworkError(err, stageSMTPHello), Err: err}}
		}
		err = client.StartTLS(tlsConfig)
		if err != nil {
			if stageForNetworkError(err, stageTLSHandshake) == stageTimeout {
				return connectResult{err: &ConnectError{Stage: stageTimeout, Err: err}}
			}
			var protoErr *textproto.Error
			if errors.As(err, &protoErr) {
				return connectResult{err: &ConnectError{Stage: stageStartTLS, Err: err}}
			}
			// net/smtp performs a fresh EHLO after the TLS handshake inside
			// StartTLS. If the handshake itself completed and the server only
			// dropped the post-upgrade continuation, the certificate state
			// still belongs to the current complete TLS connection.
			if state, ok := client.TLSConnectionState(); ok && state.HandshakeComplete {
				return connectResult{state: &state}
			}
			return connectResult{err: &ConnectError{Stage: stageTLSHandshake, Err: err}}
		}
		state, ok := client.TLSConnectionState()
		if !ok {
			return connectResult{err: &ConnectError{Stage: stageStartTLS, Err: errors.New("SMTP connection isn't TLS after StartTLS")}}
		}
		return connectResult{state: &state}
	case "ftp":
		addr := withDefaultPort(config.ConnectTo, 21)
		state, err := dumpTLSConnStateFromFTP(dialer, addr, tlsConfig)
		if err != nil && ErrorStage(err) == "" {
			err = &ConnectError{Stage: stageStartTLS, Err: err}
		}
		return connectResult{state: state, err: err}
	case "imap":
		addr := withDefaultPort(config.ConnectTo, 143)
		state, err := dumpTLSConnStateFromIMAP(dialer, addr, tlsConfig)
		if err != nil && ErrorStage(err) == "" {
			err = &ConnectError{Stage: stageStartTLS, Err: err}
		}
		return connectResult{state: state, err: err}
	default:
		return connectResult{err: &ConnectError{Stage: stageProtocol, Err: fmt.Errorf("unknown StartTLS protocol: %s", config.StartTLSType)}}
	}
}

func tlsConfigForConnect(connectName, connectTo, clientCert, clientKey string) (*tls.Config, **tls.CertificateRequestInfo, error) {
	var hostname string
	if connectName != "" {
		hostname = connectName
	} else {
		hostname = HostnameFromConnectTarget(connectTo)
	}

	// SNI must be a DNS hostname, never an IP literal (RFC 6066, Section 3).
	// Go's TLS client also refuses to send one, so leave ServerName empty.
	if net.ParseIP(hostname) != nil {
		hostname = ""
	}

	conf := &tls.Config{
		// We verify later manually so we can print results
		InsecureSkipVerify: true,
		ServerName:         hostname,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       allSupportedCipherSuiteIDs(),
	}

	var err error
	var cert tls.Certificate

	if clientCert != "" {
		keyFile := clientCert
		if clientKey != "" {
			keyFile = clientKey
		}

		cert, err = tls.LoadX509KeyPair(clientCert, keyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read client certificate/key: %s", err)
		}

		// Required even if we set fallback, because of bug in Go 1.8.0 (fixed in 1.8.1)
		conf.Certificates = []tls.Certificate{cert}
	}

	cri := setGetClientCertificateCallback(conf, &cert)
	return conf, cri, nil
}

// HostnameFromConnectTarget extracts the hostname or IP address from a
// connect target of the form "host", "host:port", "[v6addr]" or
// "[v6addr]:port". It is used both to derive the default SNI server name and
// the default name to verify the server's certificate against.
func HostnameFromConnectTarget(connectTo string) string {
	if host, _, err := net.SplitHostPort(connectTo); err == nil {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	// Strip brackets from a bracketed IPv6 literal without a port.
	if strings.HasPrefix(connectTo, "[") && strings.HasSuffix(connectTo, "]") {
		return connectTo[1 : len(connectTo)-1]
	}
	return connectTo
}

func setGetClientCertificateCallback(conf *tls.Config, cert *tls.Certificate) **tls.CertificateRequestInfo {
	var captured *tls.CertificateRequestInfo

	conf.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		captured = snapshotCertificateRequestInfo(cri)
		return cert, nil
	}

	return &captured
}

// newAttemptTLSConfig clones the frozen session configuration and installs a
// callback whose captured client-certificate request belongs to exactly this
// physical attempt. The client certificate itself still comes from the shared
// base configuration.
func newAttemptTLSConfig(base *tls.Config) (*tls.Config, **tls.CertificateRequestInfo) {
	config := base.Clone()
	certs := config.Certificates
	var captured *tls.CertificateRequestInfo
	var emptyCert tls.Certificate

	config.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		captured = snapshotCertificateRequestInfo(cri)
		if len(certs) > 0 {
			return &certs[0], nil
		}
		return &emptyCert, nil
	}

	return config, &captured
}

func snapshotCertificateRequestInfo(cri *tls.CertificateRequestInfo) *tls.CertificateRequestInfo {
	if cri == nil {
		return nil
	}
	// Snapshot the request rather than retaining a pointer into the
	// handshake's temporary state. The snapshot belongs to this physical
	// connection only and cannot be overwritten by a later attempt.
	criCopy := *cri
	criCopy.AcceptableCAs = append([][]byte(nil), cri.AcceptableCAs...)
	for i, ca := range cri.AcceptableCAs {
		criCopy.AcceptableCAs[i] = append([]byte(nil), ca...)
	}
	criCopy.SignatureSchemes = append([]tls.SignatureScheme(nil), cri.SignatureSchemes...)
	return &criCopy
}

// withDefaultPort takes an address and a port, and returns the address
// as-is if there's a port, or address:port if there isn't.
func withDefaultPort(addr string, portN uint16) string {
	port := strconv.Itoa(int(portN))
	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		// IPv6 without a port
		return net.JoinHostPort(addr[1:len(addr)-1], port)
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if net.ParseIP(addr) != nil {
		// Bare IPv6 literal without a port.
		return net.JoinHostPort(addr, port)
	}
	if strings.ContainsAny(addr, ":") {
		// There are two cases when an address could contain a `:`
		// If it's an IPv6 address without a port, it's handled above
		// Otherwise, it's any kind of address with a port
		return addr
	}
	// No colon means no port.
	return net.JoinHostPort(addr, port)
}

// GetConnectionState connects to a TLS server, returning the connection state.
// startTLSType can be one of the protocols in Protocols, or the empty string,
// which does a normal TLS connection. connectTo specifies the address to
// connect to. connectName sets SNI. identity sets DB username or SMTP EHLO.
// connectCert and connectKey are client cert/key.
func GetConnectionState(startTLSType, connectName, connectTo, identity, clientCert, clientKey string, connectProxy *url.URL, timeout time.Duration) (*tls.ConnectionState, *tls.CertificateRequestInfo, error) {
	result, err := NewSession(Config{
		StartTLSType: startTLSType,
		ServerName:   connectName,
		ConnectTo:    connectTo,
		Identity:     identity,
		ClientCert:   clientCert,
		ClientKey:    clientKey,
		Proxy:        connectProxy,
		Timeout:      timeout,
	}).Connect()
	if err != nil {
		return nil, nil, err
	}
	return result.State, result.CertificateRequestInfo, nil
}
