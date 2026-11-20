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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/square/certigo/cli/terminal"
)

// resetConnectFlags restores the package-level connect flag variables to
// their defaults. kingpin does not reset flag values between Parse calls, so
// without this, values would leak from one Run invocation into the next.
func resetConnectFlags() {
	*verbose = false
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
}

// runConnect runs the connect command with a clean flag state.
func runConnect(t *testing.T, args ...string) (int, *terminal.TestTerminal) {
	t.Helper()
	resetConnectFlags()
	testTerminal := &terminal.TestTerminal{Width: 80}
	return Run(append([]string{"connect"}, args...), testTerminal), testTerminal
}

// recvSNI returns the SNI server name seen by the fixture server, failing the
// test if no connection arrives.
func recvSNI(t *testing.T, snis chan string) string {
	t.Helper()
	select {
	case sni := <-snis:
		return sni
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for TLS connection to fixture server")
		return ""
	}
}

// certstrap init --curve P-256 --cn "Localhost Root" --expires "20 years"
var localhostRoot = []byte(`-----BEGIN CERTIFICATE-----
MIIBZzCCAQygAwIBAgIBATAKBggqhkjOPQQDAjAZMRcwFQYDVQQDEw5Mb2NhbGhv
c3QgUm9vdDAeFw0yMjA1MzEyMTIyNTRaFw00MjA1MzEyMTMyNTJaMBkxFzAVBgNV
BAMTDkxvY2FsaG9zdCBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFU5m
vrrtaf20iV8PtR9Vtri/AaOAFIDZGB24mXq8bAtqrpYJTmw4W9FXjuhF9I/hk4kb
VwkUJ/RPSQDo4WAYz6NFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFKmuTXHQnGbvxH+YrwLza85GBUT1MAoGCCqGSM49BAMC
A0kAMEYCIQDzxBz6YMWQv6kn+14Gsp+QB0q8AU+lP/Z0GJMl/SCs+QIhAPAWMOjc
mW2/VQQ+IRyDXj92xdJQ+953pBYY/inVjTBA
-----END CERTIFICATE-----`)

// certstrap request-cert --common-name localhost --curve P-256 --ip 127.0.0.1
// certstrap sign localhost --CA Localhost_Root --expires "20 years"
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIRAJ0DJ0Fq0oq1WrJVGOX8cyMwCgYIKoZIzj0EAwIwGTEX
MBUGA1UEAxMOTG9jYWxob3N0IFJvb3QwHhcNMjIwNTMxMjEyNDM4WhcNNDIwNTMx
MjEzMjUxWjAUMRIwEAYDVQQDEwlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATM99XdCMWptOjjx1INxFJSLhcqrFGIzXSfNNpL0EpPhsjkl2rLYBo7
mNvUBz2pSTMkHA8emmVeBGr748DsMQHGo4GDMIGAMA4GA1UdDwEB/wQEAwIDuDAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFEtGby8/yZBA
gfDySvtlSxqFqfZNMB8GA1UdIwQYMBaAFKmuTXHQnGbvxH+YrwLza85GBUT1MA8G
A1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIhAKoEpWBCX6HU4QQMU7B/
gPQR8oSxPa61OkaKz4He0ekjAiAVN8VtVouHHeWoq892Gbl508fST5wYKeLUdg2u
+v9Syg==
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoAW3yvL3JJBzaAdG
aPJ9zriULhC+a9ODMQTM1vWBGVahRANCAATM99XdCMWptOjjx1INxFJSLhcqrFGI
zXSfNNpL0EpPhsjkl2rLYBo7mNvUBz2pSTMkHA8emmVeBGr748DsMQHG
-----END PRIVATE KEY-----`)

const testCert string = `
-----BEGIN CERTIFICATE-----
MIIE1DCCArygAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwPzELMAkGA1UEBhMCVVMx
FzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMRcwFQYDVQQDDA5JbnRlcm1lZGlhZXRD
QTAeFw0xNzA3MTkxNjUwMjBaFw0xNzA3MjkxNjUwMjBaMDUxCzAJBgNVBAYTAlVT
MRcwFQYDVQQKDA50ZXN0MS5hY21lLmNvbTENMAsGA1UEAwwEYmxvZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKm8P47lABp4+rz2nN+QYrxedbaFVWoF
FuoSkqcHsafMwbMrN+kI6wJVtlbwviDvxWFJ92q0H71QNFybTsmof3KUN/kYCp7P
+LKhBrN0ttWI5q6v5eDrjN0VdtVdnlZOYmJFbvETOgfK/qXKNRRM8HYW0tdqrtEw
CR5dIu53xVUSViBdwXpuy2c5W2mFn1gxTpdW+3hbZsL1pHrU9qPWLtTgl/KY8kjs
I7KW1cIcinE4SJomhB5L/4emhxKGY+kEa2+fN9IPjjvKSMOw9kiBKk1GHZcIY5EA
O3TIfUk3fysPzi5qA0su/bNtPQy1uXgXS10xUlV7pqRPvHjiNzgFkXUCAwEAAaOB
4zCB4DAJBgNVHRMEAjAAMB0GA1UdDgQWBBRVQ91jSOONzVr1VGBdJOlPN+3XxTBg
BgNVHSMEWTBXgBQ13bfx50rDZO3y2CZdHPgleFUEoKE7pDkwNzELMAkGA1UEBhMC
VVMxFzAVBgNVBAoMDnRlc3QxLmFjbWUuY29tMQ8wDQYDVQQDDAZSb290Q0GCAhAA
MA4GA1UdDwEB/wQEAwIDqDATBgNVHSUEDDAKBggrBgEFBQcDATAtBgNVHREEJjAk
hiJzcGlmZmU6Ly9kZXYuYWNtZS5jb20vcGF0aC9zZXJ2aWNlMA0GCSqGSIb3DQEB
CwUAA4ICAQBp2+rtUxt1VmNM/vi6PwoSoYzWFmQ2nc4OM7bsOG4uppU54wRYZ+T7
c42EcrpyBgWn+rWHT1Hi6SNcmloKHydaUTZ4pq3IlKKnBNqwivU5BzIxYLDrhR/U
wd9s1tgmLvADqkQa1XjjSFn5Auoj1R640ry4qpw8IOusdm6wVhru4ssRnHX4E2uR
jQe7b3ws38aZhjtL78Ip0BB4yPxWJRp/WmEoT33QP+cZhA4IYWECxNODr6DSJeq2
VNu/6JACGrNfM2Sjt4Wxz+nIa3cKDNCA6PR8StTUTcoQ6ZBzpn+n/Q1xSRIOJz6N
hgfkyb9O7HAMdAP+TxehjqG3gh5Ky2DgYMCIZOztVzsuOb1DGJe/kGUKeRJLl2/O
QwkctwUOcVIxckNu6OvclriFzvoXObqO77XeCI2V1Vef0wGTWlWNOdbFa4708Y7f
5UdwInYQUi87RFDnc1SDU4Jrsv4KzZiv9FCfDg8pCBIdWpWT7DAuI0d7i7PZ+iFt
ZZ6sb/YDkyiDXU4ar/dja0FDE2r7jsN9D+FfW49+iDvXr4ELQyhZpW3Zr1Ojwm58
CJzjZwbRYiVwPBRsKmiYfO1E7esvw3CmjK5chfz8c40f6/APDro9ZmYNBRv2CnJy
t/DtcM/GpAhBbLP9Tk7kPB41v5fRIxVDo50Iz/qvkr37pQ4RsejSFg==
-----END CERTIFICATE-----
`

const expectedVerbose string = `** CERTIFICATE 1 **
Input Format: PEM
Serial: 4096
Valid: 2017-07-19 16:50 UTC to 2017-07-29 16:50 UTC
Signature: SHA256-RSA
Subject Info:
	Country: US
	Organization: test1.acme.com
	CommonName: blog
Issuer Info:
	Country: US
	Organization: test1.acme.com
	CommonName: IntermediaetCA
Subject Key ID: 55:43:DD:63:48:E3:8D:CD:5A:F5:54:60:5D:24:E9:4F:37:ED:D7:C5
Authority Key ID: 35:DD:B7:F1:E7:4A:C3:64:ED:F2:D8:26:5D:1C:F8:25:78:55:04:A0
Basic Constraints: CA:false
Key Usage:
	Digital Signature
	Key Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
URI Names:
	spiffe://dev.acme.com/path/service

`

// The ciphersuite negotiated can vary, so allow all ciphersuites in the connection result below.
var cipherSuiteRegex = regexp.MustCompile("(?m)^Cipher Suite: .*$")
var cipherSuiteRepl = "Cipher Suite: XXX"

const expectedConnect string = `** TLS Connection **
Version: TLS 1.3
Cipher Suite: XXX

** CERTIFICATE 1 **
Serial: 208705168425672442866264119814836220707
Valid: 2022-05-31 21:24 UTC to 2042-05-31 21:32 UTC
Signature: ECDSA-SHA256
Subject Info:
	CommonName: localhost
Issuer Info:
	CommonName: Localhost Root
Subject Key ID: 4B:46:6F:2F:3F:C9:90:40:81:F0:F2:4A:FB:65:4B:1A:85:A9:F6:4D
Authority Key ID: A9:AE:4D:71:D0:9C:66:EF:C4:7F:98:AF:02:F3:6B:CE:46:05:44:F5
Key Usage:
	Digital Signature
	Key Encipherment
	Data Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
	Client Auth
IP Addresses:
	127.0.0.1

Found 1 valid certificate chain(s):
[0] CN=localhost
	=> CN=Localhost Root [self-signed]
** TLS Connection **
Version: TLS 1.3
Cipher Suite: XXX

** CERTIFICATE 1 **
Serial: 208705168425672442866264119814836220707
Valid: 2022-05-31 21:24 UTC to 2042-05-31 21:32 UTC
Signature: ECDSA-SHA256
Subject Info:
	CommonName: localhost
Issuer Info:
	CommonName: Localhost Root
Subject Key ID: 4B:46:6F:2F:3F:C9:90:40:81:F0:F2:4A:FB:65:4B:1A:85:A9:F6:4D
Authority Key ID: A9:AE:4D:71:D0:9C:66:EF:C4:7F:98:AF:02:F3:6B:CE:46:05:44:F5
Key Usage:
	Digital Signature
	Key Encipherment
	Data Encipherment
	Key Agreement
Extended Key Usage:
	Server Auth
	Client Auth
IP Addresses:
	127.0.0.1

Found 1 valid certificate chain(s):
[0] CN=localhost
	=> CN=Localhost Root [self-signed]
`

// Test basic dump functionality:  Dump a cert
func TestDump(t *testing.T) {
	tmpfile, err := os.CreateTemp("", t.Name())
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.Write([]byte(testCert))
	require.NoError(t, err)

	args := []string{"dump", "--verbose", "--format", "PEM", tmpfile.Name()}
	testTerminal := terminal.TestTerminal{Width: 80}

	assert.EqualValues(t, 0, Run(args, &testTerminal), "process should exit 0")
	assert.Empty(t, testTerminal.ErrorBuf.Bytes(), "no error output expected")
	assert.EqualValues(t, expectedVerbose, testTerminal.OutputBuf.String())
}

func TestDumpMissingFile(t *testing.T) {
	testTerminal := terminal.TestTerminal{Width: 80}
	args := []string{"dump", "this-is-a-file-that-definitely-does-not-exist1111.pem"}
	assert.EqualValues(t, 2, Run(args, &testTerminal), "process should exit 0")
	const expected = "path 'this-is-a-file-that-definitely-does-not-exist1111.pem' does not exist, try --help\n"
	assert.Equal(t, expected, testTerminal.ErrorBuf.String())
	assert.Empty(t, testTerminal.OutputBuf.Bytes())
}

func TestConnect(t *testing.T) {
	rootPath, err := os.CreateTemp("", t.Name())
	require.NoError(t, err)
	defer os.Remove(rootPath.Name())

	_, err = rootPath.Write([]byte(localhostRoot))
	require.NoError(t, err)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(t, err)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	ts.TLS.Certificates = []tls.Certificate{cert}

	args := []string{"connect", "--verbose", "--ca", rootPath.Name(), "--verify", "--expected-name", "127.0.0.1", ts.URL[len("https://"):]}
	testTerminal := terminal.TestTerminal{Width: 80}
	Run(args, &testTerminal)
	assert.EqualValues(t, 0, Run(args, &testTerminal), "process should exit 0")
	assert.Empty(t, testTerminal.ErrorBuf.Bytes(), "no error output expected")

	out := cipherSuiteRegex.ReplaceAllLiteralString(testTerminal.OutputBuf.String(), cipherSuiteRepl)
	assert.EqualValues(t, expectedConnect, out)
}

// localhostTLSFixture starts a local TLS server presenting localhostCert and
// returns its address, the path of a CA bundle verifying it, and a channel
// reporting the SNI server name of each incoming connection.
func localhostTLSFixture(t *testing.T) (addr string, caPath string, snis chan string) {
	t.Helper()

	rootPath, err := os.CreateTemp("", t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(rootPath.Name()) })
	_, err = rootPath.Write([]byte(localhostRoot))
	require.NoError(t, err)
	require.NoError(t, rootPath.Close())

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	require.NoError(t, err)

	snis = make(chan string, 1)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			snis <- hello.ServerName
			return nil, nil
		},
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return ts.URL[len("https://"):], rootPath.Name(), snis
}

// SNI (--name) only affects the TLS handshake; certificate verification still
// runs against --expected-name (or, by default, the connect target).
func TestConnectSNIDecoupledFromVerification(t *testing.T) {
	addr, caPath, snis := localhostTLSFixture(t)

	code, tty := runConnect(t, "--ca", caPath, "--verify",
		"--name", "example.com", "--expected-name", "127.0.0.1", addr)
	assert.EqualValues(t, 0, code, "process should exit 0")
	assert.Empty(t, tty.ErrorBuf.Bytes(), "no error output expected")
	assert.Contains(t, tty.OutputBuf.String(), "Found 1 valid certificate chain(s)")
	assert.Equal(t, "example.com", recvSNI(t, snis), "server should see the overridden SNI")
}

// When connecting to an IP literal without --expected-name, the certificate is
// verified against the IP SANs of the certificate.
func TestConnectDefaultsExpectedNameToTargetIP(t *testing.T) {
	addr, caPath, snis := localhostTLSFixture(t)

	code, tty := runConnect(t, "--ca", caPath, "--verify", addr)
	assert.EqualValues(t, 0, code, "process should exit 0")
	assert.Empty(t, tty.ErrorBuf.Bytes(), "no error output expected")
	assert.Contains(t, tty.OutputBuf.String(), "Found 1 valid certificate chain(s)")
	assert.Empty(t, recvSNI(t, snis), "no SNI should be sent for an IP literal target")
}

// A wrong --expected-name must fail verification, and --verify must turn that
// into a non-zero exit code.
func TestConnectExpectedNameMismatch(t *testing.T) {
	addr, caPath, _ := localhostTLSFixture(t)

	code, tty := runConnect(t, "--ca", caPath, "--verify", "--expected-name", "wrong.example.com", addr)
	assert.EqualValues(t, 1, code, "process should exit 1")
	assert.Contains(t, tty.OutputBuf.String(), "Failed to verify certificate chain:")
}

// --insecure skips verification entirely but still prints the certificate chain.
func TestConnectInsecure(t *testing.T) {
	addr, _, _ := localhostTLSFixture(t)

	// No --ca: the chain would not verify, but --insecure skips verification.
	code, tty := runConnect(t, "--insecure", addr)
	assert.EqualValues(t, 0, code, "process should exit 0")
	assert.Empty(t, tty.ErrorBuf.Bytes(), "no error output expected")
	out := tty.OutputBuf.String()
	assert.Contains(t, out, "** CERTIFICATE 1 **")
	assert.NotContains(t, out, "certificate chain", "no verification output expected")
}

func TestConnectInsecureConflictsWithVerifyFlags(t *testing.T) {
	caPath, err := os.CreateTemp("", t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(caPath.Name()) })
	require.NoError(t, caPath.Close())

	for _, extra := range [][]string{
		{"--verify"},
		{"--expected-name", "example.com"},
		{"--ca", caPath.Name()},
	} {
		args := append([]string{"--insecure"}, append(extra, "localhost:443")...)
		code, tty := runConnect(t, args...)
		assert.EqualValues(t, 2, code, "process should exit 2 for args %v", args)
		assert.Contains(t, tty.ErrorBuf.String(), "--insecure cannot be combined")
	}
}

// generateSPIFFEFixture creates a CA and a server certificate carrying the
// given SPIFFE ID as its single URI SAN, returning the CA in PEM form and the
// server key pair.
func generateSPIFFEFixture(t *testing.T, spiffeID string) (caPEM []byte, serverCert tls.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	spiffeURI, err := url.Parse(spiffeID)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "spiffe-server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		URIs:         []*url.URL{spiffeURI},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	require.NoError(t, err)
	serverCert, err = tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}),
	)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), serverCert
}

// The expected name can be a SPIFFE ID, matched against the certificate's URI SAN.
func TestConnectExpectedNameSPIFFE(t *testing.T) {
	caPEM, serverCert := generateSPIFFEFixture(t, "spiffe://example.test/service")

	caPath, err := os.CreateTemp("", t.Name())
	require.NoError(t, err)
	t.Cleanup(func() { os.Remove(caPath.Name()) })
	_, err = caPath.Write(caPEM)
	require.NoError(t, err)
	require.NoError(t, caPath.Close())

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	addr := ts.URL[len("https://"):]

	code, tty := runConnect(t, "--ca", caPath.Name(), "--verify",
		"--expected-name", "spiffe://example.test/service", addr)
	assert.EqualValues(t, 0, code, "process should exit 0")
	assert.Contains(t, tty.OutputBuf.String(), "Found 1 valid certificate chain(s)")

	code, tty = runConnect(t, "--ca", caPath.Name(), "--verify",
		"--expected-name", "spiffe://example.test/other-service", addr)
	assert.EqualValues(t, 1, code, "process should exit 1")
	assert.Contains(t, tty.OutputBuf.String(), "Failed to verify certificate chain:")
}

// A hostname target (not an IP literal) is used as the default SNI.
func TestConnectDefaultsSNIToTargetHostname(t *testing.T) {
	addr, caPath, snis := localhostTLSFixture(t)
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	code, tty := runConnect(t, "--ca", caPath, "--expected-name", "127.0.0.1", net.JoinHostPort("localhost", port))
	assert.EqualValues(t, 0, code, "process should exit 0")
	assert.Empty(t, tty.ErrorBuf.Bytes(), "no error output expected")
	assert.Equal(t, "localhost", recvSNI(t, snis), "server should see the target hostname as SNI")
}

func TestAppVersion(t *testing.T) {
	assert.NotEmpty(t, appVersion())

	defer func(v string) { version = v }(version)
	version = "1.2.3"
	assert.Equal(t, "1.2.3", appVersion(), "the -X override should win over build info")
}
