package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/gocurl/internal/appversion"
	"github.com/ameshkov/gocurl/internal/client/ntlm"
	"golang.org/x/net/proxy"
)

// httpProxyDialer implements proxy.Dialer for HTTP and HTTPS proxies.
type httpProxyDialer struct {
	proxyURL       *url.URL
	forward        proxy.Dialer
	tlsConfig      *tls.Config
	connectTimeout time.Duration

	// ntlm enables NTLM proxy authentication instead of Basic.
	ntlm bool
}

// type check
var _ proxy.Dialer = (*httpProxyDialer)(nil)

// Dial implements the proxy.Dialer interface for *httpProxyDialer.
func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("HTTP proxy does not support %s", network)
	}

	// Use the forward dialer to connect to the proxy server
	proxyAddr := net.JoinHostPort(d.proxyURL.Hostname(), d.proxyURL.Port())
	proxyConn, err := d.forward.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	// For HTTPS proxies, establish a TLS connection first
	if d.proxyURL.Scheme == "https" {
		tlsConn := tls.Client(proxyConn, d.tlsConfig)
		// Set a deadline for the TLS handshake
		tlsTimeout := 30 * time.Second
		if d.connectTimeout > 0 {
			tlsTimeout = d.connectTimeout
		}
		if err = tlsConn.SetDeadline(time.Now().Add(tlsTimeout)); err != nil {
			log.OnCloserError(proxyConn, log.DEBUG)

			return nil, fmt.Errorf("failed to set TLS handshake deadline: %w", err)
		}
		// Perform the TLS handshake
		if err = tlsConn.Handshake(); err != nil {
			log.OnCloserError(proxyConn, log.DEBUG)

			return nil, fmt.Errorf("TLS handshake with HTTPS proxy failed: %w", err)
		}
		// Reset the deadline
		if err = tlsConn.SetDeadline(time.Time{}); err != nil {
			log.OnCloserError(tlsConn, log.DEBUG)

			return nil, fmt.Errorf("failed to reset TLS connection deadline: %w", err)
		}
		proxyConn = tlsConn
	}

	resp, err := d.connect(proxyConn, addr)
	if err != nil {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, err
	}
	defer log.OnCloserError(resp.Body, log.DEBUG)

	// Check if the connection was established successfully
	if resp.StatusCode != http.StatusOK {
		log.OnCloserError(proxyConn, log.DEBUG)

		return nil, fmt.Errorf("proxy connection failed: %s", resp.Status)
	}

	return proxyConn, nil
}

// connect sends the CONNECT request to the proxy, performing NTLM
// authentication if it is enabled, and returns the final proxy response.
func (d *httpProxyDialer) connect(proxyConn net.Conn, addr string) (resp *http.Response, err error) {
	r := bufio.NewReader(proxyConn)

	if !d.ntlm {
		var auth string
		if d.proxyURL.User != nil {
			username := d.proxyURL.User.Username()
			password, _ := d.proxyURL.User.Password()
			auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		}

		return sendConnect(proxyConn, r, addr, auth)
	}

	negotiate, err := ntlm.NegotiateHeader()
	if err != nil {
		return nil, err
	}

	resp, err = sendConnect(proxyConn, r, addr, negotiate)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		return resp, nil
	}

	challenge, ok, err := ntlm.Challenge(resp.Header.Values("Proxy-Authenticate"))
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("proxy did not send an NTLM challenge: %s", resp.Status)
	}

	// Read the response body completely to get to the next response.
	ntlm.DrainBody(resp)
	if resp.Close {
		return nil, fmt.Errorf("proxy closed the connection during the NTLM handshake")
	}

	password, _ := d.proxyURL.User.Password()
	authenticate, err := ntlm.AuthenticateHeader(challenge, d.proxyURL.User.Username(), password)
	if err != nil {
		return nil, err
	}

	return sendConnect(proxyConn, r, addr, authenticate)
}

// sendConnect writes the CONNECT request for addr to proxyConn and reads the
// response from r.  If auth is not empty, it is sent in the
// Proxy-Authorization header.
func sendConnect(proxyConn net.Conn, r *bufio.Reader, addr, auth string) (resp *http.Response, err error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}

	// Set User-Agent to gocurl.
	req.Header.Set("User-Agent", fmt.Sprintf("gocurl/%s", appversion.Version()))

	if auth != "" {
		req.Header.Set("Proxy-Authorization", auth)
	}

	// Write the request to the proxy
	if err = req.Write(proxyConn); err != nil {
		return nil, fmt.Errorf("failed to write CONNECT request to proxy: %w", err)
	}

	resp, err = http.ReadResponse(r, req)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from proxy: %w", err)
	}

	return resp, nil
}

// createHTTPProxyDialer creates a proxy.Dialer for HTTP or HTTPS proxies.
// connectTimeout is the timeout for the connection phase. If 0, uses default timeout.
func createHTTPProxyDialer(
	proxyURL *url.URL,
	ntlm bool,
	forward proxy.Dialer,
	connectTimeout time.Duration,
) (proxy.Dialer, error) {
	// Set default port if not specified
	if proxyURL.Port() == "" {
		switch proxyURL.Scheme {
		case "http":
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "80")
		case "https":
			proxyURL.Host = net.JoinHostPort(proxyURL.Hostname(), "443")
		}
	}

	// Create TLS config for HTTPS proxies
	var tlsConfig *tls.Config
	if proxyURL.Scheme == "https" {
		tlsConfig = &tls.Config{
			ServerName: proxyURL.Hostname(),
		}
	}

	return &httpProxyDialer{
		proxyURL:       proxyURL,
		forward:        forward,
		tlsConfig:      tlsConfig,
		connectTimeout: connectTimeout,
		ntlm:           ntlm,
	}, nil
}
