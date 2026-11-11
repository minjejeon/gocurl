// Package ntlm implements the NTLM HTTP authentication handshake (--ntlm and
// --proxy-ntlm arguments of the command-line tool).
//
// NTLM is a connection-oriented authentication scheme: the NEGOTIATE (type 1),
// CHALLENGE (type 2), and AUTHENTICATE (type 3) messages must be exchanged
// over the same TCP connection.  This is why the handshake requires HTTP/1.1
// with keep-alive enabled.
package ntlm

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"github.com/ameshkov/gocurl/internal/output"
)

// Scheme is the name of the NTLM authentication scheme used in HTTP headers.
const Scheme = "NTLM"

// maxDrainSize is the maximum number of bytes of the intermediate response
// body that will be read in order to keep the connection reusable.
const maxDrainSize = 1 << 20

// NegotiateHeader returns the value of the Authorization (or
// Proxy-Authorization) header that carries the NTLM NEGOTIATE message.
func NegotiateHeader() (v string, err error) {
	msg, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		return "", fmt.Errorf("creating NTLM negotiate message: %w", err)
	}

	return Scheme + " " + base64.StdEncoding.EncodeToString(msg), nil
}

// Challenge looks for the NTLM CHALLENGE message in the specified values of
// the WWW-Authenticate (or Proxy-Authenticate) header.  ok is false if there
// is no NTLM challenge there.
func Challenge(values []string) (challenge []byte, ok bool, err error) {
	for _, v := range values {
		scheme, token, _ := strings.Cut(strings.TrimSpace(v), " ")
		if !strings.EqualFold(scheme, Scheme) {
			continue
		}

		token = strings.TrimSpace(token)
		if token == "" {
			// The server only advertises NTLM, there is no challenge yet.
			continue
		}

		challenge, err = base64.StdEncoding.DecodeString(token)
		if err != nil {
			return nil, false, fmt.Errorf("decoding NTLM challenge: %w", err)
		}

		return challenge, true, nil
	}

	return nil, false, nil
}

// AuthenticateHeader returns the value of the Authorization (or
// Proxy-Authorization) header that carries the NTLM AUTHENTICATE message
// created in response to challenge.  username can be specified as
// DOMAIN\user, user@domain, or just user.
func AuthenticateHeader(challenge []byte, username, password string) (v string, err error) {
	msg, err := ntlmssp.NewAuthenticateMessage(challenge, username, password, nil)
	if err != nil {
		return "", fmt.Errorf("creating NTLM authenticate message: %w", err)
	}

	return Scheme + " " + base64.StdEncoding.EncodeToString(msg), nil
}

// DrainBody reads (up to a limit) and closes the response body so that the
// underlying connection can be reused for the next handshake step.
func DrainBody(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainSize))
	_ = resp.Body.Close()
}

// Transport is an http.RoundTripper that performs NTLM authentication with
// the origin server.  The base transport must use HTTP/1.1 and must be able to
// reuse the connection between subsequent requests.
type Transport struct {
	// Base is the underlying transport that sends the requests.
	Base http.RoundTripper

	// Out is used for debug logging.
	Out *output.Output

	// Username is the user name, can be specified as DOMAIN\user,
	// user@domain, or just user.
	Username string

	// Password is the user password.
	Password string
}

// type check
var _ http.RoundTripper = (*Transport)(nil)

// RoundTrip implements the http.RoundTripper interface for *Transport.  It
// sends the request with the NTLM NEGOTIATE message and if the server responds
// with a CHALLENGE, resends the request with the AUTHENTICATE message.
// Otherwise, the first response is returned as is.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	// The original request is never sent, only its clones are.
	if req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}

	negotiate, err := NegotiateHeader()
	if err != nil {
		return nil, err
	}

	t.Out.Debug("NTLM: sending the negotiate message (type 1)")

	firstReq, err := cloneRequest(req, negotiate)
	if err != nil {
		return nil, err
	}

	resp, err = t.Base.RoundTrip(firstReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Out.Debug("NTLM: the server responded with %s, no authentication required", resp.Status)

		return resp, nil
	}

	challenge, ok, err := Challenge(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		DrainBody(resp)

		return nil, err
	} else if !ok {
		t.Out.Debug("NTLM: the server did not send an NTLM challenge")

		return resp, nil
	}

	t.Out.Debug("NTLM: received the challenge message (type 2)")

	// Read the response body completely so that the connection is reused.
	DrainBody(resp)

	authenticate, err := AuthenticateHeader(challenge, t.Username, t.Password)
	if err != nil {
		return nil, err
	}

	t.Out.Debug("NTLM: sending the authenticate message (type 3)")

	authReq, err := cloneRequest(req, authenticate)
	if err != nil {
		return nil, err
	}

	return t.Base.RoundTrip(authReq)
}

// CloseIdleConnections closes the idle connections of the base transport if it
// supports that.
func (t *Transport) CloseIdleConnections() {
	type closeIdler interface {
		CloseIdleConnections()
	}

	if c, ok := t.Base.(closeIdler); ok {
		c.CloseIdleConnections()
	}
}

// cloneRequest clones req, sets a fresh copy of its body, and sets the
// Authorization header to the specified value.
func cloneRequest(req *http.Request, authorization string) (r *http.Request, err error) {
	r = req.Clone(req.Context())
	r.Header.Set("Authorization", authorization)

	if req.Body == nil || req.Body == http.NoBody {
		return r, nil
	}

	if req.GetBody == nil {
		return nil, fmt.Errorf("NTLM: request body cannot be resent")
	}

	r.Body, err = req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("NTLM: getting request body: %w", err)
	}

	return r, nil
}
