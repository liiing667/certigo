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

package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"

	"github.com/square/certigo/cli/terminal"
	"github.com/square/certigo/lib"
	"github.com/square/certigo/starttls"
)

var (
	app     = kingpin.New("certigo", "A command-line utility to examine and validate certificates to help with debugging SSL/TLS issues.")
	verbose = app.Flag("verbose", "Print verbose").Short('v').Bool()

	dump         = app.Command("dump", "Display information about a certificate from a file or stdin.")
	dumpFiles    = dump.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFiles()
	dumpType     = dump.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	dumpPassword = dump.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	dumpPem      = dump.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	dumpJSON     = dump.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
	dumpFirst    = dump.Flag("first", "Only display the first certificate. This flag can be paired with --json or --pem.").Short('l').Bool()

	connect                   = app.Command("connect", "Connect to a server and print its certificate(s).")
	connectTo                 = connect.Arg("server[:port]", "Hostname or IP to connect to, with optional port.").Required().String()
	connectName               = connect.Flag("name", "Override the server name sent in Server Name Indication (SNI). Only affects the TLS handshake, not certificate verification.").Short('n').String()
	connectCaPath             = connect.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	connectCert               = connect.Flag("cert", "Client certificate chain for connecting to server (PEM).").ExistingFile()
	connectKey                = connect.Flag("key", "Private key for client certificate, if not in same file (PEM).").ExistingFile()
	connectStartTLS           = connect.Flag("start-tls", fmt.Sprintf("Enable StartTLS protocol; one of: %v.", starttls.Protocols)).Short('t').PlaceHolder("PROTOCOL").Enum(starttls.Protocols...)
	connectIdentity           = connect.Flag("identity", "With --start-tls, sets the DB user or SMTP EHLO name").Default("certigo").String()
	connectProxy              = connect.Flag("proxy", "Optional URI for HTTP(s) CONNECT proxy to dial connections with").URL()
	connectTimeout            = connect.Flag("timeout", "Timeout for connecting to remote server (can be '5m', '1s', etc).").Default("5s").Duration()
	connectPem                = connect.Flag("pem", "Write output as PEM blocks instead of human-readable format.").Short('m').Bool()
	connectJSON               = connect.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
	connectFirst              = connect.Flag("first", "Only display the first certificate. This flag can be paired with --json or --pem.").Short('l').Bool()
	connectVerify             = connect.Flag("verify", "Verify certificate chain and exit non-zero if verification fails.").Bool()
	connectVerifyExpectedName = connect.Flag("expected-name", "Name expected in the server TLS certificate (DNS name, IP address, or SPIFFE ID). Defaults to the hostname or IP to connect to, independent of SNI.").String()
	connectInsecure           = connect.Flag("insecure", "Skip certificate chain verification entirely. The certificate chain is still printed.").Bool()

	verify         = app.Command("verify", "Verify a certificate chain from file/stdin against a name.")
	verifyFile     = verify.Arg("file", "Certificate file to dump (or stdin if not specified).").ExistingFile()
	verifyType     = verify.Flag("format", "Format of given input (PEM, DER, JCEKS, PKCS12; heuristic if missing).").Short('f').String()
	verifyPassword = verify.Flag("password", "Password for PKCS12/JCEKS key stores (reads from TTY if missing).").Short('p').String()
	verifyName     = verify.Flag("name", "Server name to verify certificate against.").Short('n').Required().String()
	verifyCaPath   = verify.Flag("ca", "Path to CA bundle (system default if unspecified).").ExistingFile()
	verifyJSON     = verify.Flag("json", "Write output as machine-readable JSON format.").Short('j').Bool()
)

// connectAttempt is an immutable snapshot of one connect invocation.
//
// kingpin keeps flag values in package-level variables, and it does not reset
// them between Parse calls. A connection attempt therefore must not read those
// variables once it has started: a retry or a second Run call could otherwise
// combine the certificate chain from one target with the verification name
// from another. Freezing the values here also makes the target host and
// protocol explicit before the connection is established; connectWithRetry
// assigns a fresh generation to each physical attempt.
type connectAttempt struct {
	protocol     string
	target       string
	host         string
	serverName   string
	identity     string
	clientCert   string
	clientKey    string
	proxy        *url.URL
	timeout      time.Duration
	expectedName string
	caPath       string
	insecure     bool
	verify       bool
	pem          bool
	json         bool
	first        bool
}

var connectAttemptGeneration atomic.Uint64
var runMu sync.Mutex

// resetFlags restores every kingpin value to its default before a new Run.
// Without this, a failed connection followed by a retry would silently reuse
// the previous invocation's target, StartTLS protocol, SNI override, expected
// name, timeout, or insecure setting.
func resetFlags() {
	*verbose = false

	*dumpFiles = nil
	*dumpType = ""
	*dumpPassword = ""
	*dumpPem = false
	*dumpJSON = false
	*dumpFirst = false

	*connectTo = ""
	*connectName = ""
	*connectCaPath = ""
	*connectCert = ""
	*connectKey = ""
	*connectStartTLS = ""
	*connectIdentity = "certigo"
	*connectProxy = nil
	*connectTimeout = 5 * time.Second
	*connectPem = false
	*connectJSON = false
	*connectFirst = false
	*connectVerify = false
	*connectVerifyExpectedName = ""
	*connectInsecure = false

	*verifyFile = ""
	*verifyType = ""
	*verifyPassword = ""
	*verifyName = ""
	*verifyCaPath = ""
	*verifyJSON = false
}

// snapshotConnectAttempt freezes all connect inputs for one generation. The
// target host is derived from the address that will actually be dialed, not
// from the SNI override, so certificate verification always belongs to the
// same connection as the reported certificate chain.
func snapshotConnectAttempt() connectAttempt {
	attempt := connectAttempt{
		protocol:     *connectStartTLS,
		target:       *connectTo,
		host:         starttls.HostnameFromConnectTarget(*connectTo),
		serverName:   *connectName,
		identity:     *connectIdentity,
		clientCert:   *connectCert,
		clientKey:    *connectKey,
		timeout:      *connectTimeout,
		expectedName: *connectVerifyExpectedName,
		caPath:       *connectCaPath,
		insecure:     *connectInsecure,
		verify:       *connectVerify,
		pem:          *connectPem,
		json:         *connectJSON,
		first:        *connectFirst,
	}
	if *connectProxy != nil {
		proxyCopy := **connectProxy
		attempt.proxy = &proxyCopy
	}
	return attempt
}

const maxStartTLSConnectionAttempts = 2

type connectOutcome struct {
	attempts     int
	generation   uint64
	failureStage string
	lastErr      error
}

func connectAttemptLimit(protocol string) int {
	if protocol == "" {
		// A plain TLS connection is a single user-visible attempt. Retrying it
		// would change timeout and error behavior without adding StartTLS
		// generation safety.
		return 1
	}
	return maxStartTLSConnectionAttempts
}

func retryableConnectStage(stage string) bool {
	// Only a TLS handshake failure is retryable. Dial, protocol negotiation,
	// authentication, timeout, and configuration failures belong to this
	// generation and must be reported as-is.
	return stage == "tls_handshake"
}

func timeoutConnectError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if starttls.ErrorStage(err) == "timeout" {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "timeout") || strings.Contains(message, "timed out")
}

// connectWithRetry establishes one StartTLS generation. Every retry uses the
// already frozen target, protocol, SNI, and verification inputs from attempt,
// so a certificate chain from a later connection can never be paired with the
// hostname conclusion from an earlier one.
func connectWithRetry(attempt connectAttempt) (*tls.ConnectionState, *tls.CertificateRequestInfo, connectOutcome) {
	outcome := connectOutcome{}
	limit := connectAttemptLimit(attempt.protocol)
	deadline := time.Now().Add(attempt.timeout)

	for i := 1; i <= limit; i++ {
		outcome.attempts = i
		// Each physical connection gets its own frozen generation. The final
		// report can then identify the exact connection whose chain it shows.
		outcome.generation = connectAttemptGeneration.Add(1)

		// The command's timeout is a budget for the whole generation, not a
		// fresh budget for every retry. This preserves the historical
		// "never take longer than timeout" behavior.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			outcome.failureStage = "timeout"
			outcome.lastErr = errors.New("error connecting: timed out")
			return nil, nil, outcome
		}

		state, cri, err := starttls.GetConnectionState(
			attempt.protocol, attempt.serverName, attempt.target, attempt.identity,
			attempt.clientCert, attempt.clientKey, attempt.proxy, remaining)
		if err == nil {
			outcome.lastErr = nil
			return state, cri, outcome
		}

		outcome.lastErr = err
		if timeoutConnectError(err) {
			// Timeout output is part of the CLI's stable public behavior and
			// must not be doubled by a retry.
			outcome.failureStage = "timeout"
			return nil, nil, outcome
		}
		stage := starttls.ErrorStage(err)
		if stage == "" {
			stage = "connect"
		}
		outcome.failureStage = stage

		if i == limit || !retryableConnectStage(stage) {
			return nil, nil, outcome
		}
	}

	return nil, nil, outcome
}

func connectionReport(attempt connectAttempt, outcome connectOutcome) *lib.ConnectionReport {
	// A normal single-attempt success keeps the historical output unchanged.
	// Emit the generation report only when it carries retry or failure
	// evidence that a consumer needs in order to audit the connection.
	if outcome.attempts <= 1 && outcome.failureStage == "" {
		return nil
	}
	return &lib.ConnectionReport{
		Attempts:     outcome.attempts,
		Generation:   outcome.generation,
		Target:       attempt.target,
		Host:         attempt.host,
		Protocol:     attempt.protocol,
		FailureStage: outcome.failureStage,
	}
}

// version overrides what --version prints. Leave it empty to print the
// module version that Go stamps into the binary at build time. Builds
// without git metadata, such as from a source tarball, can set it with
// -ldflags "-X github.com/square/certigo/cli.version=1.2.3".
var version string

// appVersion returns the version for --version, without the leading "v"
// of a Go module version.
func appVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "(devel)"
}

func Run(args []string, tty terminal.Terminal) int {
	// kingpin's Application and all flag values are package-global. Serialize
	// Run calls so a concurrent retry cannot parse flags into another
	// invocation's connection generation.
	runMu.Lock()
	defer runMu.Unlock()

	resetFlags()

	terminalWidth := tty.DetermineWidth()
	stdout := tty.Output()
	errOut := tty.Error()

	printErr := func(format string, args ...interface{}) int {
		_, err := fmt.Fprintf(errOut, format, args...)
		if err != nil {
			// If we can't write the error, we bail with a different return code... not much good
			// we can do at this point
			return 3
		}
		return 2
	}
	app.HelpFlag.Short('h')
	app.Version(appVersion())

	// Alias starttls to start-tls
	connect.Flag("starttls", "").Hidden().EnumVar(connectStartTLS, starttls.Protocols...)
	// Use long help because many useful flags are under subcommands
	app.UsageTemplate(kingpin.LongHelpTemplate)

	result := lib.SimpleResult{}
	command, err := app.Parse(args)
	if err != nil {
		return printErr("%s, try --help\n", err)
	}
	switch command {
	case dump.FullCommand(): // Dump certificate
		if dumpPassword != nil && *dumpPassword != "" {
			tty.SetDefaultPassword(*dumpPassword)
		}

		files, err := inputFiles(*dumpFiles)
		if err != nil {
			return printErr("error: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		}
		defer func() {
			for _, file := range files {
				_ = file.Close()
			}
		}()

		if *dumpPem {
			dumped := 0
			err = lib.ReadAsPEMFromFiles(files, *dumpType, tty.ReadPassword, func(block *pem.Block, format string) error {
				if *dumpFirst && dumped > 0 {
					return nil
				}

				block.Headers = nil
				dumped++
				return pem.Encode(stdout, block)
			})
		} else {
			err = lib.ReadAsX509FromFiles(files, *dumpType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
				if err != nil {
					//nolint:staticcheck // See errorFromErrors
					return fmt.Errorf("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
				} else {
					result.Certificates = append(result.Certificates, cert)
					result.Formats = append(result.Formats, format)
				}
				return nil
			})

			certList := result.Certificates
			formatList := result.Formats
			if *dumpFirst && len(certList) > 0 {
				certList = certList[:1]
				formatList = formatList[:1]
				result.Certificates = certList
				result.Formats = formatList
			}

			if *dumpJSON {
				blob, _ := json.Marshal(result)
				_, _ = fmt.Println(string(blob))
			} else {
				for i, cert := range result.Certificates {
					_, _ = fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
					_, _ = fmt.Fprintf(stdout, "Input Format: %s\n", result.Formats[i])
					_, _ = fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
				}
			}
		}
		if err != nil {
			return printErr("error: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		} else if len(result.Certificates) == 0 && !*dumpPem {
			printErr("warning: no certificates found in input\n")
		}

	case connect.FullCommand(): // Get certs by connecting to a server
		attempt := snapshotConnectAttempt()
		if attempt.protocol == "" && attempt.identity != "certigo" {
			return printErr("error: --identity can only be used with --start-tls")
		}
		if attempt.insecure && (attempt.verify || attempt.expectedName != "" || attempt.caPath != "") {
			return printErr("error: --insecure cannot be combined with --verify, --expected-name, or --ca\n")
		}
		connState, cri, outcome := connectWithRetry(attempt)
		if outcome.lastErr != nil {
			if outcome.attempts > 1 && outcome.failureStage != "timeout" {
				_, _ = fmt.Fprintf(errOut, "connection attempts: %d, last failure stage: %s, generation: %d\n",
					outcome.attempts, outcome.failureStage, outcome.generation)
			}
			return printErr("%s\n", strings.TrimSuffix(outcome.lastErr.Error(), "\n"))
		}
		result.TLSConnectionState = connState
		result.CertificateRequestInfo = cri
		for _, cert := range connState.PeerCertificates {
			if attempt.pem {
				err := pem.Encode(stdout, lib.EncodeX509ToPEM(cert, nil))
				if err != nil {
					return printErr("could not encode PEM: %s\n", err)
				}
			} else {
				result.Certificates = append(result.Certificates, cert)
			}
		}

		if !attempt.insecure {
			// Determine what name the server's certificate should match. This
			// is deliberately decoupled from SNI (--name): it defaults to the
			// hostname or IP we dialed, and can be overridden explicitly with
			// --expected-name (DNS name, IP address, or SPIFFE ID). Both the
			// chain and the name come from this same attempt snapshot.
			expectedNameInCertificate := attempt.expectedName
			if expectedNameInCertificate == "" {
				expectedNameInCertificate = attempt.host
			}
			verifyResult := lib.VerifyChain(connState.PeerCertificates, connState.OCSPResponse, expectedNameInCertificate, attempt.caPath)
			result.VerifyResult = &verifyResult
			if verifyResult.Error != "" {
				outcome.failureStage = "verify"
			}
		}
		result.Connection = connectionReport(attempt, outcome)
		if result.Connection != nil && result.VerifyResult != nil {
			result.VerifyResult.ConnectionAttempts = outcome.attempts
			result.VerifyResult.ConnectionGeneration = outcome.generation
			result.VerifyResult.Target = attempt.target
			result.VerifyResult.FailureStage = outcome.failureStage
		}

		certList := result.Certificates
		if attempt.first && len(certList) > 0 {
			certList = certList[:1]
			result.Certificates = certList
		}

		if attempt.json {
			blob, _ := json.Marshal(result)
			_, _ = fmt.Println(string(blob))
		} else if !attempt.pem {
			_, _ = fmt.Fprintf(
				stdout, "%s\n\n",
				lib.EncodeTLSInfoToText(result.TLSConnectionState, result.CertificateRequestInfo))

			for i, cert := range result.Certificates {
				_, _ = fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
				_, _ = fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, *verbose))
			}
			lib.PrintConnectionReport(stdout, result.Connection)
			if result.VerifyResult != nil {
				lib.PrintVerifyResult(stdout, *result.VerifyResult)
			}
		}

		if attempt.verify && result.VerifyResult != nil && len(result.VerifyResult.Error) > 0 {
			return 1
		}
	case verify.FullCommand():
		if verifyPassword != nil && *verifyPassword != "" {
			tty.SetDefaultPassword(*verifyPassword)
		}

		file, err := inputFile(*verifyFile)
		if err != nil {
			return printErr("%s\n", err.Error())
		}
		defer func() { _ = file.Close() }()

		var chain []*x509.Certificate
		err = lib.ReadAsX509FromFiles([]*os.File{file}, *verifyType, tty.ReadPassword, func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return err
			} else {
				chain = append(chain, cert)
			}
			return nil
		})
		if err != nil {
			return printErr("error parsing block: %s\n", strings.TrimSuffix(err.Error(), "\n"))
		}

		verifyResult := lib.VerifyChain(chain, nil, *verifyName, *verifyCaPath)
		if *verifyJSON {
			blob, _ := json.Marshal(verifyResult)
			_, _ = fmt.Println(string(blob))
		} else {
			lib.PrintVerifyResult(stdout, verifyResult)
		}
		if verifyResult.Error != "" {
			return 1
		}
	}
	return 0
}

func inputFile(fileName string) (*os.File, error) {
	if fileName == "" {
		return os.Stdin, nil
	}

	rawFile, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %s", err)
	}
	return rawFile, nil
}

func inputFiles(fileNames []string) ([]*os.File, error) {
	var files []*os.File
	if fileNames != nil {
		for _, filename := range fileNames {
			rawFile, err := os.Open(filename)
			if err != nil {
				return nil, fmt.Errorf("unable to open file: %s", err)
			}
			files = append(files, rawFile)
		}
	} else {
		files = append(files, os.Stdin)
	}
	return files, nil
}
