package connectip

import (
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// proxyHTTP2 answers an extended CONNECT request on a net/http server.
func proxyHTTP2(w http.ResponseWriter, body io.ReadCloser) (*Conn, error) {
	rc := http.NewResponseController(w)
	// A proxied connection outlives the timeouts that a server applies to requests.
	_ = rc.SetReadDeadline(time.Time{})
	// Resetting the stream goes through the write deadline too: without it, closing
	// a Conn whose writes the peer doesn't accept would never finish.
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("connect-ip: the ResponseWriter doesn't support write deadlines: %w", err)
	}

	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, fmt.Errorf("connect-ip: failed to send response: %w", err)
	}
	return newProxiedConn(newHTTP2Stream(&proxyBody{w: w, rc: rc, body: body}), nil), nil
}

// proxyBody is the proxy's end of an HTTP/2 stream.
// It stops using the ResponseWriter on CloseWrite and Reset, since
// a net/http handler is free to return as soon as the Conn is closed.
type proxyBody struct {
	w    http.ResponseWriter
	rc   *http.ResponseController
	body io.ReadCloser

	mu     sync.Mutex // held during a Write
	closed atomic.Bool
}

// Read reads the request body, which carries the capsules of the client.
func (b *proxyBody) Read(p []byte) (int, error) { return b.body.Read(p) }

// Write sends p on the response, and flushes it.
func (b *proxyBody) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := b.w.Write(p)
	if err != nil {
		return n, err
	}
	return n, b.rc.Flush()
}

// CloseWrite doesn't send anything: net/http ends the stream when the handler returns.
func (b *proxyBody) CloseWrite() error {
	b.closed.Store(true)
	return nil
}

// CloseRead closes the request body.
func (b *proxyBody) CloseRead() { b.body.Close() }

// Reset relies on net/http resetting the stream, with INTERNAL_ERROR,
// when a write deadline passes: there's no other way for a handler to do so.
func (b *proxyBody) Reset(http2.ErrCode) {
	if b.closed.Load() {
		return
	}
	_ = b.rc.SetWriteDeadline(time.Unix(1, 0))
	// The lock waits for a Write in progress, which the reset just failed.
	b.mu.Lock()
	b.closed.Store(true)
	b.mu.Unlock()
}
