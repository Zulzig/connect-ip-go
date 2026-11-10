package connectip

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// http2StreamID is the stream of the proxied connection: the first one a client opens.
	http2StreamID = 1
	// Initial values of RFC 9113, section 6.5.2.
	http2InitialWindow       = 65535
	http2InitialMaxFrameSize = 16384
	http2InitialTableSize    = 4096
	// http2MaxWindow is the largest flow control window of RFC 9113, section 6.9.1.
	http2MaxWindow = 1<<31 - 1

	defaultHTTP2ReceiveWindow = 4 << 20
	maxHTTP2HeaderListSize    = 1 << 16
	// maxQueuedHTTP2ControlFrames bounds the answers owed to a proxy that doesn't read them.
	maxQueuedHTTP2ControlFrames = 128

	// http2WriteFailureGrace is how long a failed write waits for the read loop to report why.
	http2WriteFailureGrace = time.Second
)

// HTTP2Config configures an [HTTP2ClientConn].
type HTTP2Config struct {
	// ReceiveWindow is the HTTP/2 flow control window of the proxied connection, in bytes.
	// It limits the throughput from the proxy to this window per round trip.
	// The default is 4 MiB. Values below 65535 and above 2^31-1 are raised, or lowered, to these.
	ReceiveWindow int64
}

// An HTTP2ClientConn is an HTTP/2 connection to a proxy, for networks that block UDP.
// It carries a single proxied connection, since it is its own HTTP/2 client:
// neither net/http nor golang.org/x/net/http2 can send the :protocol pseudo-header
// that Extended CONNECT (RFC 8441) needs, see https://go.dev/issue/53208.
//
// HTTP/2 runs over TCP, so a proxied connection is subject to TCP's retransmissions
// and head-of-line blocking. HTTP/3 should be preferred whenever it is available.
type HTTP2ClientConn struct {
	// Set by NewHTTP2ClientConn, and never changed.
	nc       net.Conn
	fr       *http2.Framer
	window   int64               // the receive window of the connection and of the stream
	settings chan struct{}       // closed when the first SETTINGS frame arrives
	response chan *http.Response // receives the response to Dial
	done     chan struct{}       // closed when the connection fails, after setting err

	// wmu serializes the frames, and is held while the network blocks a write.
	// The read loop must never wait for it: if both peers stopped reading
	// because their writes are blocked, none of these writes would finish.
	wmu sync.Mutex

	// mu guards the fields below. cond wakes up the goroutines that wait
	// for them to change: writeControlFrames, reserve and clientBody.Read.
	mu   sync.Mutex
	cond *sync.Cond
	err  error

	// The settings of the proxy that Dial waits for.
	sawSettings     bool
	extendedConnect bool
	noStreams       bool          // the proxy's SETTINGS_MAX_CONCURRENT_STREAMS is 0
	streamsAllowed  chan struct{} // closed when the proxy allows streams again, if Dial waits for it

	// The request and its response.
	dialing   bool // Dial was called
	dialed    bool // the request was sent
	responded bool

	// The control frames, and the pings that wait for their answer.
	control []func(*http2.Framer) error // frames owed to the proxy, written ahead of DATA frames
	pingID  uint64
	pings   map[[8]byte]chan struct{}

	// The send side of the stream, and its flow control.
	connSend    int64 // connection-level send window
	streamSend  int64 // stream-level send window
	initialSend int64 // the proxy's SETTINGS_INITIAL_WINDOW_SIZE
	maxFrame    int64 // the proxy's SETTINGS_MAX_FRAME_SIZE
	writing     bool  // a DATA frame is being written, and may be blocked in the network
	sendClosed  bool
	resetSent   bool

	// The receive side of the stream, and its flow control.
	recv         bytes.Buffer
	recvEnded    bool  // the proxy ended the stream
	recvClosed   bool  // the local side stopped reading
	recvUsed     int64 // bytes the proxy sent, until the writer takes their credit
	recvCredit   int64 // the part of recvUsed that was consumed, and can be credited
	creditQueued bool  // a WINDOW_UPDATE for recvCredit waits in control
}

// NewHTTP2ClientConn starts an HTTP/2 connection on conn, a TLS connection that negotiated
// the "h2" ALPN. The caller owns conn until calling Close, which closes it.
// Failures surface on [HTTP2ClientConn.Dial], or on the proxied connection after that.
func NewHTTP2ClientConn(conn net.Conn, conf *HTTP2Config) *HTTP2ClientConn {
	window := int64(defaultHTTP2ReceiveWindow)
	if conf != nil && conf.ReceiveWindow != 0 {
		window = min(max(conf.ReceiveWindow, http2InitialWindow), http2MaxWindow)
	}
	c := &HTTP2ClientConn{
		nc:          conn,
		fr:          http2.NewFramer(conn, conn),
		window:      window,
		settings:    make(chan struct{}),
		response:    make(chan *http.Response, 1),
		done:        make(chan struct{}),
		pings:       make(map[[8]byte]chan struct{}),
		connSend:    http2InitialWindow,
		streamSend:  http2InitialWindow,
		initialSend: http2InitialWindow,
		maxFrame:    http2InitialMaxFrameSize,
	}
	c.cond = sync.NewCond(&c.mu)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(http2InitialTableSize, nil)
	c.fr.MaxHeaderListSize = maxHTTP2HeaderListSize
	c.fr.SetMaxReadFrameSize(http2InitialMaxFrameSize)
	c.control = append(c.control, c.writePreface)
	go c.writeControlFrames()
	go c.readFrames()
	return c
}

// Dial sends the request and waits for the response. The response comes back
// whenever the proxy answered, for the caller to read the status of a refusal.
// While the proxy allows no streams (SETTINGS_MAX_CONCURRENT_STREAMS of 0),
// Dial waits for it to allow one, or for the context of the request to end.
// An HTTP2ClientConn can only be used for one call to Dial, even if it fails.
// Closing the returned Conn doesn't close the HTTP2ClientConn.
func (c *HTTP2ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}
	headers, err := encodeHTTP2Request(httpReq)
	if err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	if c.dialing {
		c.mu.Unlock()
		return nil, nil, errors.New("connect-ip: HTTP2ClientConn already used")
	}
	c.dialing = true
	c.mu.Unlock()

	ctx := httpReq.Context()
	select {
	case <-ctx.Done():
		return nil, nil, context.Cause(ctx)
	case <-c.done:
		return nil, nil, c.failure()
	case <-c.settings:
	}

	c.mu.Lock()
	for {
		if err := c.err; err != nil {
			c.mu.Unlock()
			return nil, nil, err
		}
		if !c.extendedConnect {
			c.mu.Unlock()
			return nil, nil, errors.New("connect-ip: server didn't enable Extended CONNECT")
		}
		if !c.noStreams {
			break
		}
		// RFC 9113, section 5.1.2: a proxy should only refuse new streams for a short while.
		if c.streamsAllowed == nil {
			c.streamsAllowed = make(chan struct{})
		}
		allowed := c.streamsAllowed
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, context.Cause(ctx)
		case <-c.done:
			return nil, nil, c.failure()
		case <-allowed:
		}
		c.mu.Lock()
	}
	err = c.queueControlFrame(func(fr *http2.Framer) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      http2StreamID,
			BlockFragment: headers,
			EndHeaders:    true,
		})
	})
	if err != nil {
		c.mu.Unlock()
		return nil, nil, err
	}
	c.dialed = true
	c.mu.Unlock()

	rsp, err := c.waitForResponse(ctx)
	if err != nil {
		return nil, nil, err
	}
	rsp.Request = httpReq
	switch rsp.StatusCode {
	case http.StatusNoContent, http.StatusResetContent, http.StatusPartialContent:
		// RFC 9297, section 3.2: these responses can't use the Capsule Protocol, so this one is malformed.
		c.reset(http2.ErrCodeProtocol)
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d, which can't carry capsules", rsp.StatusCode)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		c.reset(http2.ErrCodeCancel)
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(newHTTP2Stream(&clientBody{c: c}), nil), rsp, nil
}

// waitForResponse waits for the response to the request, and resets the stream if ctx ends first.
func (c *HTTP2ClientConn) waitForResponse(ctx context.Context) (*http.Response, error) {
	select {
	case rsp := <-c.response:
		return rsp, nil
	case <-ctx.Done():
		c.reset(http2.ErrCodeCancel)
		return nil, context.Cause(ctx)
	case <-c.done:
		// The proxy might have closed the connection right after refusing the request.
		select {
		case rsp := <-c.response:
			return rsp, nil
		default:
			return nil, c.failure()
		}
	}
}

// Ping checks that the proxy answers. It is the way to detect a dead path:
// TCP can take many minutes to give up, and its keep-alives stop while data is unacknowledged.
func (c *HTTP2ClientConn) Ping(ctx context.Context) error {
	ack := make(chan struct{})
	var id [8]byte

	c.mu.Lock()
	if err := c.err; err != nil {
		c.mu.Unlock()
		return err
	}
	c.pingID++
	binary.BigEndian.PutUint64(id[:], c.pingID)
	// A Ping that times out leaves its frame behind: the limit of the queue keeps them from piling up
	// on a writer that stalled. Whether to give up on the connection then is the caller's call.
	if err := c.queueControlFrame(func(fr *http2.Framer) error { return fr.WritePing(false, id) }); err != nil {
		c.mu.Unlock()
		return err
	}
	c.pings[id] = ack
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.pings, id)
		c.mu.Unlock()
	}()
	select {
	case <-ack:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-c.done:
		return c.failure()
	}
}

// Close closes the underlying connection, which ends the proxied connection.
func (c *HTTP2ClientConn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

// failure returns why the connection failed, or nil if it didn't.
func (c *HTTP2ClientConn) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// fail records err as the reason the connection failed, unless it already failed, and closes it.
func (c *HTTP2ClientConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
		close(c.done)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	c.nc.Close()
}

// failLocked is fail for a caller that holds mu. Closing a TLS connection writes,
// which a proxy that doesn't read would block: it happens on another goroutine.
func (c *HTTP2ClientConn) failLocked(err error) {
	if c.err != nil {
		return
	}
	c.err = err
	close(c.done)
	c.cond.Broadcast()
	go c.nc.Close()
}

// failWrite ends the connection after a failed write, and returns its error.
// A peer closing the connection breaks writes, and what it sent before closing
// tells why, like the TLS alert refusing a client certificate, which arrives
// after the handshake: the read loop gets to report that first.
func (c *HTTP2ClientConn) failWrite(err error) error {
	timer := time.NewTimer(http2WriteFailureGrace)
	defer timer.Stop()
	select {
	case <-c.done:
	case <-timer.C:
	}
	c.fail(fmt.Errorf("connect-ip: writing to the proxy: %w", err))
	return c.failure()
}
