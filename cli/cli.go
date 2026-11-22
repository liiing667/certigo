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
	"io"
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
// variables once it has started: a retry, a concurrent Run call, or a later
// invocation could otherwise combine the certificate chain from one target
// with the hostname, SNI, or verification name from another. Freezing the
// values here also makes the target host and protocol explicit before the
// connection is established.
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
	verbose      bool
}

var connectAttemptGeneration atomic.Uint64
var runMu sync.Mutex
var outputMu sync.Mutex

// resetFlags restores every kingpin value to its default before a new Run.
// Without this, a failed connection followed by a later invocation would
// silently reuse the previous target, StartTLS protocol, SNI override,
// expected name, timeout, or insecure setting.
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
		verbose:      *verbose,
	}
	if *connectProxy != nil {
		proxyCopy := **connectProxy
		if proxyCopy.User != nil {
			userCopy := *proxyCopy.User
			proxyCopy.User = &userCopy
		}
		attempt.proxy = &proxyCopy
	}
	return attempt
}

const maxStartTLSConnectionAttempts = starttls.MaxStartTLSAttempts

type connectOutcome struct {
	attempts     int
	generation   uint64
	failureStage string
	lastErr      error
}

//nolint:unused // Kept as a small, testable statement of the retry policy.
func connectAttemptLimit(protocol string) int {
	if protocol == "" {
		// A plain TLS connection is a single user-visible attempt. Retrying it
		// would change timeout and error behavior without adding StartTLS
		// generation safety.
		return 1
	}
	return maxStartTLSConnectionAttempts
}

//nolint:unused // Kept as a small, testable statement of the retry policy.
func retryableConnectStage(stage string) bool {
	// StartTLS protocol rejection and TLS handshake failure are retryable.
	// Dial, hello, timeout, configuration, and unknown-protocol failures
	// belong to this generation and are reported as-is.
	return stage == "starttls" || stage == "tls_handshake"
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

// connectWithRetry establishes one StartTLS generation. The starttls.Session
// performs each physical attempt with a fresh TLS configuration, so a
// certificate request or certificate chain from a failed connection can never
// be paired with the successful connection's target or hostname.
func connectWithRetry(attempt connectAttempt) (*tls.ConnectionState, *tls.CertificateRequestInfo, connectOutcome) {
	outcome := connectOutcome{}

	result, err := starttls.NewSession(starttls.Config{
		StartTLSType: attempt.protocol,
		ServerName:   attempt.serverName,
		ConnectTo:    attempt.target,
		Identity:     attempt.identity,
		ClientCert:   attempt.clientCert,
		ClientKey:    attempt.clientKey,
		Proxy:        attempt.proxy,
		Timeout:      attempt.timeout,
	}).Connect()

	if result != nil {
		outcome.attempts = result.Attempts
		outcome.generation = result.Generation
		outcome.failureStage = result.FailureStage
	}
	if outcome.attempts == 0 {
		outcome.attempts = 1
	}
	if outcome.generation == 0 {
		outcome.generation = connectAttemptGeneration.Add(1)
	}

	if err != nil {
		outcome.lastErr = err
		if outcome.failureStage == "" {
			outcome.failureStage = starttls.ErrorStage(err)
			if outcome.failureStage == "" {
				outcome.failureStage = "connect"
			}
		}
		return nil, nil, outcome
	}

	if result == nil || result.State == nil {
		outcome.lastErr = errors.New("error connecting: no connection result")
		outcome.failureStage = "connect"
		return nil, nil, outcome
	}

	return result.State, result.CertificateRequestInfo, outcome
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
	// parsing and flag resets. Connect commands release the lock immediately
	// after snapshotting their inputs, so concurrent connections use their own
	// frozen target, protocol, SNI, and verification settings.
	runMu.Lock()
	locked := true
	defer func() {
		if locked {
			runMu.Unlock()
		}
	}()

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
				outputMu.Lock()
				_, _ = fmt.Println(string(blob))
				outputMu.Unlock()
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
		locked = false
		runMu.Unlock()
		return runConnectAttempt(attempt, stdout, errOut, terminalWidth)
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
			outputMu.Lock()
			_, _ = fmt.Println(string(blob))
			outputMu.Unlock()
		} else {
			lib.PrintVerifyResult(stdout, verifyResult)
		}
		if verifyResult.Error != "" {
			return 1
		}
	}
	return 0
}

func runConnectAttempt(attempt connectAttempt, stdout, errOut io.Writer, terminalWidth int) int {
	printErr := func(format string, args ...interface{}) int {
		_, err := fmt.Fprintf(errOut, format, args...)
		if err != nil {
			return 3
		}
		return 2
	}

	if attempt.protocol == "" && attempt.identity != "certigo" {
		return printErr("error: --identity can only be used with --start-tls")
	}
	if attempt.insecure && (attempt.verify || attempt.expectedName != "" || attempt.caPath != "") {
		return printErr("error: --insecure cannot be combined with --verify, --expected-name, or --ca\n")
	}

	connState, cri, outcome := connectWithRetry(attempt)
	if outcome.lastErr != nil {
		if outcome.attempts > 1 && !timeoutConnectError(outcome.lastErr) && outcome.failureStage != "timeout" {
			_, _ = fmt.Fprintf(errOut, "connection attempts: %d, last failure stage: %s, generation: %d\n",
				outcome.attempts, outcome.failureStage, outcome.generation)
		}
		return printErr("%s\n", strings.TrimSuffix(outcome.lastErr.Error(), "\n"))
	}

	result := lib.SimpleResult{
		TLSConnectionState:     connState,
		CertificateRequestInfo: cri,
	}
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

	var verifyResult *lib.SimpleVerification
	if !attempt.insecure {
		expectedNameInCertificate := attempt.expectedName
		if expectedNameInCertificate == "" {
			// Verify against the hostname or IP that was actually dialed,
			// independent of the SNI override (--name).
			expectedNameInCertificate = attempt.host
		}
		verified := lib.VerifyChain(connState.PeerCertificates, connState.OCSPResponse, expectedNameInCertificate, attempt.caPath)
		verifyResult = &verified
		result.VerifyResult = verifyResult
		if verifyResult.Error != "" {
			outcome.failureStage = "verify"
		}
	}

	result.Connection = connectionReport(attempt, outcome)
	if result.Connection != nil && verifyResult != nil {
		verifyResult.ConnectionAttempts = outcome.attempts
		verifyResult.ConnectionGeneration = outcome.generation
		verifyResult.Target = attempt.target
		verifyResult.FailureStage = outcome.failureStage
	}

	if attempt.first && len(result.Certificates) > 0 {
		result.Certificates = result.Certificates[:1]
	}

	if attempt.json {
		blob, _ := json.Marshal(result)
		outputMu.Lock()
		_, _ = fmt.Println(string(blob))
		outputMu.Unlock()
	} else if !attempt.pem {
		_, _ = fmt.Fprintf(
			stdout, "%s\n\n",
			lib.EncodeTLSInfoToText(result.TLSConnectionState, result.CertificateRequestInfo))

		for i, cert := range result.Certificates {
			_, _ = fmt.Fprintf(stdout, "** CERTIFICATE %d **\n", i+1)
			_, _ = fmt.Fprintf(stdout, "%s\n\n", lib.EncodeX509ToText(cert, terminalWidth, attempt.verbose))
		}
		lib.PrintConnectionReport(stdout, result.Connection)
		if result.VerifyResult != nil {
			lib.PrintVerifyResult(stdout, *result.VerifyResult)
		}
	}

	if attempt.verify && result.VerifyResult != nil && len(result.VerifyResult.Error) > 0 {
		return 1
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
