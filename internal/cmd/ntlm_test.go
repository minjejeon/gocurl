package cmd_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/ameshkov/gocurl/internal/cmd"
	"github.com/ameshkov/gocurl/internal/config"
	"github.com/ameshkov/gocurl/internal/output"
	"github.com/mccutchen/go-httpbin/v2/httpbin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// testNTLMUser and testNTLMDomain are the credentials accepted by the
	// test NTLM server.
	testNTLMUser   = "alice"
	testNTLMDomain = "CORP"

	// testNTLMPassword is the password accepted by the test NTLM server.
	testNTLMPassword = "Passw0rd!"

	// testNTLMPasswordHash is the NT hash, i.e. MD4(UTF-16LE(password)), of
	// testNTLMPassword.  It is hardcoded so that the tests do not depend on an
	// MD4 implementation.
	testNTLMPasswordHash = "fc525c9683e8fe067095ba2ddc971889"
)

// ntlmVerifier implements the server side of the NTLMv2 handshake.  It keeps
// the server challenge per connection (identified by the remote address) and
// verifies the NTLMv2 response sent by the client.
type ntlmVerifier struct {
	mu         sync.Mutex
	challenges map[string][]byte
}

// newNTLMVerifier creates a new *ntlmVerifier.
func newNTLMVerifier() (v *ntlmVerifier) {
	return &ntlmVerifier{challenges: map[string][]byte{}}
}

// handle processes the value of the Authorization header received from
// remoteAddr.  It returns the challenge header value to send back if the
// header contains a NEGOTIATE message and ok if it contains a valid
// AUTHENTICATE message sent over the same connection.
func (v *ntlmVerifier) handle(remoteAddr, authorization string) (challenge string, ok bool) {
	scheme, token, _ := strings.Cut(authorization, " ")
	if scheme != "NTLM" {
		return "", false
	}

	msg, err := base64.StdEncoding.DecodeString(token)
	if err != nil || len(msg) < 12 || !bytes.HasPrefix(msg, []byte("NTLMSSP\x00")) {
		return "", false
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	switch binary.LittleEndian.Uint32(msg[8:]) {
	case 1:
		serverChallenge := make([]byte, 8)
		_, _ = rand.Read(serverChallenge)
		v.challenges[remoteAddr] = serverChallenge

		return "NTLM " + base64.StdEncoding.EncodeToString(newTestChallengeMessage(serverChallenge)), false
	case 3:
		serverChallenge, found := v.challenges[remoteAddr]
		if !found {
			// AUTHENTICATE received on a different connection.
			return "", false
		}

		delete(v.challenges, remoteAddr)

		return "", verifyTestAuthenticateMessage(msg, serverChallenge)
	default:
		return "", false
	}
}

// newTestChallengeMessage creates an NTLM CHALLENGE (type 2) message.
func newTestChallengeMessage(serverChallenge []byte) (msg []byte) {
	const (
		flagUnicode     = 0x00000001
		flagNTLM        = 0x00000200
		flagExtSecurity = 0x00080000
		flagTargetInfo  = 0x00800000
		headerLen       = 48
	)

	// AV_PAIR list: MsvAvNbDomainName followed by MsvAvEOL.
	domain := toUTF16(testNTLMDomain)
	targetInfo := binary.LittleEndian.AppendUint16(nil, 2)
	targetInfo = binary.LittleEndian.AppendUint16(targetInfo, uint16(len(domain)))
	targetInfo = append(targetInfo, domain...)
	targetInfo = append(targetInfo, 0, 0, 0, 0)

	msg = append([]byte("NTLMSSP\x00"), 2, 0, 0, 0)
	// TargetName: empty.
	msg = appendSecBuf(msg, 0, headerLen)
	msg = binary.LittleEndian.AppendUint32(msg, flagUnicode|flagNTLM|flagExtSecurity|flagTargetInfo)
	msg = append(msg, serverChallenge...)
	// Reserved.
	msg = append(msg, make([]byte, 8)...)
	msg = appendSecBuf(msg, len(targetInfo), headerLen)

	return append(msg, targetInfo...)
}

// verifyTestAuthenticateMessage checks the NTLMv2 response in the NTLM
// AUTHENTICATE (type 3) message against the test credentials.
func verifyTestAuthenticateMessage(msg, serverChallenge []byte) (ok bool) {
	ntResponse, ok1 := readSecBuf(msg, 20)
	domain, ok2 := readSecBuf(msg, 28)
	user, ok3 := readSecBuf(msg, 36)
	if !ok1 || !ok2 || !ok3 || len(ntResponse) <= 16 {
		return false
	}

	if !bytes.Equal(domain, toUTF16(testNTLMDomain)) || !bytes.Equal(user, toUTF16(testNTLMUser)) {
		return false
	}

	ntHash, _ := hex.DecodeString(testNTLMPasswordHash)
	ntowfv2 := hmacMD5(ntHash, toUTF16(strings.ToUpper(testNTLMUser)+testNTLMDomain))
	proof := hmacMD5(ntowfv2, serverChallenge, ntResponse[16:])

	return hmac.Equal(proof, ntResponse[:16])
}

// appendSecBuf appends an NTLM security buffer descriptor to b.
func appendSecBuf(b []byte, l, offset int) (res []byte) {
	res = binary.LittleEndian.AppendUint16(b, uint16(l))
	res = binary.LittleEndian.AppendUint16(res, uint16(l))

	return binary.LittleEndian.AppendUint32(res, uint32(offset))
}

// readSecBuf reads the data referenced by the security buffer descriptor
// located at pos in msg.
func readSecBuf(msg []byte, pos int) (data []byte, ok bool) {
	if len(msg) < pos+8 {
		return nil, false
	}

	l := int(binary.LittleEndian.Uint16(msg[pos:]))
	offset := int(binary.LittleEndian.Uint32(msg[pos+4:]))
	if offset+l > len(msg) {
		return nil, false
	}

	return msg[offset : offset+l], true
}

// toUTF16 encodes s as UTF-16LE.
func toUTF16(s string) (b []byte) {
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}

	return b
}

// hmacMD5 calculates HMAC-MD5 of the concatenated data.
func hmacMD5(key []byte, data ...[]byte) (sum []byte) {
	h := hmac.New(md5.New, key)
	for _, d := range data {
		_, _ = h.Write(d)
	}

	return h.Sum(nil)
}

// createTestNTLMServer creates a test server that requires NTLM
// authentication and echoes the request body back once authenticated.  If
// useTLS is true, the server uses HTTPS and offers HTTP/2.
func createTestNTLMServer(useTLS bool) (server *httptest.Server) {
	v := newNTLMVerifier()

	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge, ok := v.handle(r.RemoteAddr, r.Header.Get("Authorization"))
		if !ok {
			if challenge == "" {
				challenge = "NTLM"
			}

			w.Header().Set("WWW-Authenticate", challenge)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))

			return
		}

		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, "authenticated %s %s %s", r.Proto, r.Method, body)
	}))

	if useTLS {
		server.EnableHTTP2 = true
		server.StartTLS()
	} else {
		server.Start()
	}

	return server
}

// createTestNTLMProxy creates a test CONNECT proxy that requires NTLM
// authentication.
func createTestNTLMProxy() (proxy *httptest.Server) {
	v := newNTLMVerifier()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Only CONNECT is supported", http.StatusMethodNotAllowed)

			return
		}

		challenge, ok := v.handle(r.RemoteAddr, r.Header.Get("Proxy-Authorization"))
		if !ok {
			if challenge == "" {
				challenge = "NTLM"
			}

			w.Header().Set("Proxy-Authenticate", challenge)
			http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)

			return
		}

		//nolint:gosec // G704: This is test code, r.Host comes from test setup
		targetConn, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)

			return
		}
		defer func() { _ = targetConn.Close() }()

		clientConn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = clientConn.Close() }()

		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}

		done := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(targetConn, clientConn)
			done <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(clientConn, targetConn)
			done <- struct{}{}
		}()
		<-done
	}))
}

// runTestCommand parses args, runs the command, and returns the written data
// and the error returned by cmd.Run.
func runTestCommand(t *testing.T, args ...string) (data string, err error) {
	t.Helper()

	cfg, err := config.ParseConfig(args)
	require.NoError(t, err)

	dataBuffer := &bytes.Buffer{}
	out := output.NewOutputWithWriters(dataBuffer, &bytes.Buffer{}, cfg.Verbose, cfg.OutputJSON)
	err = cmd.Run(cfg, out)

	return dataBuffer.String(), err
}

// TestRunNTLM tests NTLM authentication with the server.
func TestRunNTLM(t *testing.T) {
	server := createTestNTLMServer(false)
	defer server.Close()

	user := testNTLMDomain + `\` + testNTLMUser

	t.Run("get", func(t *testing.T) {
		data, err := runTestCommand(t, "--ntlm", "-u", user+":"+testNTLMPassword, server.URL)
		require.NoError(t, err)
		assert.Equal(t, "authenticated HTTP/1.1 GET ", data)
	})

	t.Run("post", func(t *testing.T) {
		data, err := runTestCommand(
			t,
			"--ntlm",
			"-u", user+":"+testNTLMPassword,
			"-d", "key=value",
			server.URL,
		)
		require.NoError(t, err)
		assert.Equal(t, "authenticated HTTP/1.1 POST key=value", data)
	})

	t.Run("multiple_urls", func(t *testing.T) {
		data, err := runTestCommand(t, "--ntlm", "-u", user+":"+testNTLMPassword, server.URL, server.URL)
		require.NoError(t, err)
		assert.Equal(t, "authenticated HTTP/1.1 GET authenticated HTTP/1.1 GET ", data)
	})

	t.Run("wrong_password", func(t *testing.T) {
		data, err := runTestCommand(t, "--ntlm", "-u", user+":wrong", server.URL)
		require.NoError(t, err)
		assert.Equal(t, "unauthorized", data)
	})

	t.Run("no_ntlm", func(t *testing.T) {
		data, err := runTestCommand(t, "-u", user+":"+testNTLMPassword, server.URL)
		require.NoError(t, err)
		assert.Equal(t, "unauthorized", data)
	})
}

// TestRunNTLMHTTPS tests NTLM authentication over HTTPS with a server that
// supports HTTP/2.  NTLM must force HTTP/1.1.
func TestRunNTLMHTTPS(t *testing.T) {
	server := createTestNTLMServer(true)
	defer server.Close()

	data, err := runTestCommand(
		t,
		"-k",
		"--ntlm",
		"-u", testNTLMDomain+`\`+testNTLMUser+":"+testNTLMPassword,
		"-d", "key=value",
		server.URL,
	)
	require.NoError(t, err)
	assert.Equal(t, "authenticated HTTP/1.1 POST key=value", data)
}

// TestRunNTLMNotRequired tests that --ntlm works with a server that does not
// require authentication.
func TestRunNTLMNotRequired(t *testing.T) {
	server := httptest.NewServer(httpbin.New().Handler())
	defer server.Close()

	data, err := runTestCommand(t, "--ntlm", "-u", "user:pass", "-d", "a=b", server.URL+"/post")
	require.NoError(t, err)
	assert.Contains(t, data, `"a": [`)
}

// TestRunBasicAuth tests that --user without --ntlm uses Basic
// authentication.
func TestRunBasicAuth(t *testing.T) {
	server := httptest.NewServer(httpbin.New().Handler())
	defer server.Close()

	data, err := runTestCommand(t, "-u", "user:pass", server.URL+"/basic-auth/user/pass")
	require.NoError(t, err)
	assert.Contains(t, data, `"authorized": true`)
}

// TestRunProxyNTLM tests NTLM authentication with an HTTP proxy.
func TestRunProxyNTLM(t *testing.T) {
	server := httptest.NewServer(httpbin.New().Handler())
	defer server.Close()

	proxy := createTestNTLMProxy()
	defer proxy.Close()

	user := testNTLMDomain + `\` + testNTLMUser

	t.Run("proxy_user", func(t *testing.T) {
		data, err := runTestCommand(
			t,
			"-x", proxy.URL,
			"--proxy-ntlm",
			"-U", user+":"+testNTLMPassword,
			server.URL+"/get",
		)
		require.NoError(t, err)
		assert.Contains(t, data, server.URL+"/get")
	})

	t.Run("proxy_url_credentials", func(t *testing.T) {
		proxyURL := strings.Replace(
			proxy.URL,
			"://",
			"://"+testNTLMDomain+"%5C"+testNTLMUser+":"+testNTLMPassword+"@",
			1,
		)
		data, err := runTestCommand(t, "-x", proxyURL, "--proxy-ntlm", server.URL+"/get")
		require.NoError(t, err)
		assert.Contains(t, data, server.URL+"/get")
	})

	t.Run("wrong_password", func(t *testing.T) {
		_, err := runTestCommand(t, "-x", proxy.URL, "--proxy-ntlm", "-U", user+":wrong", server.URL+"/get")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "407")
	})
}

// TestNTLMInvalidOptions tests validation of the NTLM-related options.
func TestNTLMInvalidOptions(t *testing.T) {
	testCases := []struct {
		name string
		args []string
		want string
	}{{
		name: "ntlm_without_user",
		args: []string{"--ntlm", "http://example.org"},
		want: "--ntlm requires --user",
	}, {
		name: "ntlm_http2",
		args: []string{"--ntlm", "-u", "u:p", "--http2", "http://example.org"},
		want: "--ntlm cannot be used with --http2",
	}, {
		name: "ntlm_http3",
		args: []string{"--ntlm", "-u", "u:p", "--http3", "http://example.org"},
		want: "--ntlm cannot be used with --http3",
	}, {
		name: "proxy_ntlm_without_proxy",
		args: []string{"--proxy-ntlm", "http://example.org"},
		want: "--proxy-ntlm requires --proxy",
	}, {
		name: "proxy_ntlm_socks",
		args: []string{"--proxy-ntlm", "-x", "socks5://u:p@127.0.0.1:1080", "http://example.org"},
		want: "--proxy-ntlm requires an HTTP or HTTPS proxy",
	}, {
		name: "proxy_ntlm_without_credentials",
		args: []string{"--proxy-ntlm", "-x", "http://127.0.0.1:3128", "http://example.org"},
		want: "--proxy-ntlm requires proxy credentials",
	}, {
		name: "proxy_user_without_proxy",
		args: []string{"-U", "u:p", "http://example.org"},
		want: "--proxy-user requires --proxy",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.ParseConfig(tc.args)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// TestNTLMForcesHTTP11 tests that --ntlm implies --http1.1.
func TestNTLMForcesHTTP11(t *testing.T) {
	cfg, err := config.ParseConfig([]string{"--ntlm", "-u", `CORP\alice:secret`, "https://example.org"})
	require.NoError(t, err)

	assert.True(t, cfg.ForceHTTP11)
	assert.Equal(t, `CORP\alice`, cfg.User)
	assert.Equal(t, "secret", cfg.Password)
	assert.NotContains(t, cfg.RawOptions.String(), "secret")
}
