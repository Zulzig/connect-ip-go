package connectip

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

const fakeHTTP2Timeout = 5 * time.Second

var extendedConnectSetting = http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1}

// fakeHTTP2Proxy is the server end of an HTTP2ClientConn, one frame at a time.
// The connection is a net.Pipe, so that nothing is written until the other side reads.
type fakeHTTP2Proxy struct {
	t    *testing.T
	conn net.Conn
	fr   *http2.Framer
}

func newFakeHTTP2Proxy(t *testing.T, conf *HTTP2Config) (*fakeHTTP2Proxy, *HTTP2ClientConn) {
	t.Helper()
	clientSide, proxySide := net.Pipe()
	t.Cleanup(func() { proxySide.Close() })
	require.NoError(t, proxySide.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))
	p := &fakeHTTP2Proxy{t: t, conn: proxySide, fr: http2.NewFramer(proxySide, proxySide)}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(http2InitialTableSize, nil)
	c := NewHTTP2ClientConn(clientSide, conf)
	t.Cleanup(func() { c.Close() })

	preface := make([]byte, len(http2.ClientPreface))
	_, err := io.ReadFull(proxySide, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface))
	return p, c
}

// handshake reads the settings of the client, and sends these settings.
func (p *fakeHTTP2Proxy) handshake(settings ...http2.Setting) {
	p.t.Helper()
	f, err := p.fr.ReadFrame()
	require.NoError(p.t, err)
	require.IsType(p.t, &http2.SettingsFrame{}, f)
	require.NoError(p.t, p.fr.WriteSettings(settings...))
}

// next reads the frames of the client until accept returns true.
// Frames are only valid during the call to accept.
func (p *fakeHTTP2Proxy) next(accept func(http2.Frame) bool) {
	p.t.Helper()
	for {
		f, err := p.fr.ReadFrame()
		require.NoError(p.t, err)
		if accept(f) {
			return
		}
	}
}

func nextFrame[T http2.Frame](p *fakeHTTP2Proxy) T {
	p.t.Helper()
	var frame T
	p.next(func(f http2.Frame) bool {
		var ok bool
		frame, ok = f.(T)
		return ok
	})
	return frame
}

func (p *fakeHTTP2Proxy) writeResponse(status string, endStream bool) {
	p.t.Helper()
	p.writeHeaders(endStream, hpack.HeaderField{Name: ":status", Value: status})
}

// writeHeaders sends a HEADERS frame with fields on the stream of the client.
func (p *fakeHTTP2Proxy) writeHeaders(endStream bool, fields ...hpack.HeaderField) {
	p.t.Helper()
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	for _, field := range fields {
		require.NoError(p.t, enc.WriteField(field))
	}
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      http2StreamID,
		BlockFragment: block.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}))
}

// drain discards what the client writes, so that it can finish writing.
func (p *fakeHTTP2Proxy) drain() {
	go func() { io.Copy(io.Discard, p.conn) }()
}

// waitForFailure waits for c to fail, and returns why.
func (c *HTTP2ClientConn) waitForFailure(t *testing.T) error {
	t.Helper()
	select {
	case <-c.done:
		return c.failure()
	case <-time.After(fakeHTTP2Timeout):
		t.Fatal("the connection didn't fail")
		return nil
	}
}

func newHTTP2TestRequest(t *testing.T, ctx context.Context) *Request {
	t.Helper()
	req, err := NewRequest(ctx, uritemplate.MustNew("https://proxy.example:443/connect-ip?epoch=1"))
	require.NoError(t, err)
	return req
}

type http2DialResult struct {
	conn *Conn
	rsp  *http.Response
	err  error
}

func dialAsync(t *testing.T, ctx context.Context, c *HTTP2ClientConn) <-chan http2DialResult {
	t.Helper()
	req := newHTTP2TestRequest(t, ctx)
	result := make(chan http2DialResult, 1)
	go func() {
		conn, rsp, err := c.Dial(req)
		result <- http2DialResult{conn, rsp, err}
	}()
	return result
}

// establish goes through the handshake and a successful Dial.
func (p *fakeHTTP2Proxy) establish(c *HTTP2ClientConn, settings ...http2.Setting) *Conn {
	p.t.Helper()
	result := dialAsync(p.t, p.t.Context(), c)
	p.handshake(append(settings, extendedConnectSetting)...)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("200", false)
	r := <-result
	require.NoError(p.t, r.err)
	p.t.Cleanup(func() {
		p.drain()
		r.conn.Close()
	})
	return r.conn
}

// skipDial lets the proxy send DATA without anything reading it, unlike a Conn.
func (c *HTTP2ClientConn) skipDial() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dialed = true
	c.responded = true
}
