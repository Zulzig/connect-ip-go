package connectip

import (
	"context"
	"errors"
	"fmt"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"
)

// TestHTTP2ClientReceiveWindowLimits checks the receive window that HTTP2Config.ReceiveWindow gives.
func TestHTTP2ClientReceiveWindowLimits(t *testing.T) {
	for name, tc := range map[string]struct {
		conf *HTTP2Config
		want int64
	}{
		"default": {nil, defaultHTTP2ReceiveWindow},
		"unset":   {&HTTP2Config{}, defaultHTTP2ReceiveWindow},
		"too low": {&HTTP2Config{ReceiveWindow: 1}, http2InitialWindow},
		"too big": {&HTTP2Config{ReceiveWindow: 1 << 40}, http2MaxWindow},
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newFakeHTTP2Proxy(t, tc.conf)
			require.Equal(t, tc.want, c.window)
		})
	}
}

func TestHTTP2ClientWithoutExtendedConnect(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake()
	nextFrame[*http2.SettingsFrame](p) // the ACK
	r := <-result
	require.ErrorContains(t, r.err, "server didn't enable Extended CONNECT")
}

func TestHTTP2ClientDialWaitsForSettings(t *testing.T) {
	_, c := newFakeHTTP2Proxy(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	r := <-dialAsync(t, ctx, c)
	require.ErrorIs(t, r.err, context.DeadlineExceeded)
}

func TestHTTP2ClientDialCanceled(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	result := dialAsync(t, ctx, c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	cancel()
	require.ErrorIs(t, (<-result).err, context.Canceled)

	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeCancel, rst.ErrCode)
}

func TestHTTP2ClientDialOnce(t *testing.T) {
	t.Run("after a session", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		p.establish(c)
		r := <-dialAsync(t, t.Context(), c)
		require.ErrorContains(t, r.err, "already used")
	})
	t.Run("after a canceled call", func(t *testing.T) {
		_, c := newFakeHTTP2Proxy(t, nil)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		r := <-dialAsync(t, ctx, c)
		require.ErrorIs(t, r.err, context.Canceled)
		r = <-dialAsync(t, t.Context(), c)
		require.ErrorContains(t, r.err, "already used")
	})
}

func TestHTTP2ClientRefused(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("403", true)
	r := <-result
	require.ErrorContains(t, r.err, "server responded with 403")
	require.Nil(t, r.conn)
	require.Equal(t, http.StatusForbidden, r.rsp.StatusCode)
	require.Equal(t, "403 Forbidden", r.rsp.Status)
	require.NotNil(t, r.rsp.Request)
	require.Equal(t, http.NoBody, r.rsp.Body)

	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeCancel, rst.ErrCode)
}

// TestHTTP2ClientStatusWithoutCapsules checks that Dial rejects the statuses that can't carry capsules.
func TestHTTP2ClientStatusWithoutCapsules(t *testing.T) {
	// RFC 9297, section 3.2: a response that uses the Capsule Protocol can't have these statuses.
	for _, status := range []string{"204", "205", "206"} {
		t.Run(status, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			result := dialAsync(t, t.Context(), c)
			p.handshake(extendedConnectSetting)
			nextFrame[*http2.MetaHeadersFrame](p)
			p.writeResponse(status, false)
			r := <-result
			require.ErrorContains(t, r.err, "server responded with "+status+", which can't carry capsules")
			require.Nil(t, r.conn)
			require.Equal(t, status, fmt.Sprint(r.rsp.StatusCode))

			rst := nextFrame[*http2.RSTStreamFrame](p)
			require.Equal(t, http2.ErrCodeProtocol, rst.ErrCode)
		})
	}
}

// TestHTTP2ClientRefusedThenClosed checks that a refusal followed by the end of the connection
// still reaches Dial.
func TestHTTP2ClientRefusedThenClosed(t *testing.T) {
	// The refusal must not get lost in the failure of the connection that follows it.
	for range 20 {
		p, c := newFakeHTTP2Proxy(t, nil)
		req := newHTTP2TestRequest(t, t.Context())
		p.handshake(extendedConnectSetting)
		nextFrame[*http2.SettingsFrame](p)
		c.mu.Lock()
		c.dialed = true
		c.mu.Unlock()
		p.writeResponse("403", false)
		p.conn.Close()
		require.Error(t, c.waitForFailure(t))
		rsp, err := c.waitForResponse(req.httpRequest().Context())
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, rsp.StatusCode)
	}
}

// TestHTTP2ClientWaitsForStreams checks that Dial waits while the proxy allows no streams.
func TestHTTP2ClientWaitsForStreams(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 0})
	nextFrame[*http2.SettingsFrame](p) // the ACK
	c.waitForStreams(t)
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 1}))

	// The request only follows the ACK of the setting that allows it.
	f, err := p.fr.ReadFrame()
	require.NoError(t, err)
	require.IsType(t, &http2.SettingsFrame{}, f)
	require.True(t, f.(*http2.SettingsFrame).IsAck())
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("200", false)
	r := <-result
	require.NoError(t, r.err)
	require.NotNil(t, r.conn)
}

// TestHTTP2ClientStopsWaitingForStreams checks that the context of the request ends the wait for a stream.
func TestHTTP2ClientStopsWaitingForStreams(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	ctx, cancel := context.WithCancelCause(t.Context())
	result := dialAsync(t, ctx, c)
	p.handshake(extendedConnectSetting, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 0})
	nextFrame[*http2.SettingsFrame](p) // the ACK
	c.waitForStreams(t)
	cancel(errors.New("gave up"))
	require.ErrorContains(t, (<-result).err, "gave up")
	c.mu.Lock()
	defer c.mu.Unlock()
	require.False(t, c.dialed, "the request wasn't sent")
}

// waitForStreams waits for Dial to wait until the proxy allows streams.
func (c *HTTP2ClientConn) waitForStreams(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.streamsAllowed != nil
	}, fakeHTTP2Timeout, time.Millisecond)
}

// TestHTTP2ClientPing checks that Ping returns once the proxy acknowledges its PING frame.
func TestHTTP2ClientPing(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.handshake()
	nextFrame[*http2.SettingsFrame](p)

	errChan := make(chan error, 1)
	go func() { errChan <- c.Ping(t.Context()) }()
	ping := nextFrame[*http2.PingFrame](p)
	require.False(t, ping.IsAck())
	require.NoError(t, p.fr.WritePing(true, [8]byte{0xff})) // not an answer to this ping
	select {
	case <-errChan:
		t.Fatal("Ping returned")
	case <-time.After(10 * time.Millisecond):
	}
	require.NoError(t, p.fr.WritePing(true, ping.Data))
	require.NoError(t, <-errChan)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	p.drain()
	require.ErrorIs(t, c.Ping(ctx), context.DeadlineExceeded)
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Empty(t, c.pings)
}

func TestHTTP2ClientPingOnFailedConnection(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.drain()
	errChan := make(chan error, 1)
	go func() { errChan <- c.Ping(t.Context()) }()
	p.conn.Close()
	require.Error(t, <-errChan)
	require.Error(t, c.Ping(t.Context()))
}

// TestHTTP2ClientWriteFailure checks that a failed write ends the connection and the Conn.
func TestHTTP2ClientWriteFailure(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	p.conn.Close()
	_, err := (&clientBody{c: c}).Write([]byte("data"))
	require.Error(t, err)
	require.Error(t, c.waitForFailure(t))
	_, err = conn.ReadPacket(make([]byte, 1500))
	require.True(t, errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe), "%v", err)
}

// brokenWritesConn is a connection the peer closed: writes fail at once, and
// reads report what the peer sent last, once read is closed.
type brokenWritesConn struct {
	net.Conn
	read chan struct{}
}

func (c *brokenWritesConn) Read([]byte) (int, error) {
	<-c.read
	return 0, errors.New("remote error: tls: bad certificate")
}

func (c *brokenWritesConn) Write([]byte) (int, error) { return 0, errors.New("write: broken pipe") }

func (c *brokenWritesConn) Close() error { return nil }

// TestHTTP2ClientReportsWhyWritesBroke checks that a failed write reports what the proxy sent
// before closing, rather than the broken pipe.
func TestHTTP2ClientReportsWhyWritesBroke(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &brokenWritesConn{read: make(chan struct{})}
		c := NewHTTP2ClientConn(conn, nil)
		written := make(chan error, 1)
		go func() {
			_, err := (&clientBody{c: c}).Write([]byte("data"))
			written <- err
		}()
		// Both writers have failed: neither may report it yet.
		synctest.Wait()
		select {
		case <-c.done:
			t.Fatal("a failed write ended the connection before the read loop could say why")
		default:
		}
		close(conn.read)
		require.ErrorContains(t, <-written, "bad certificate")
		require.ErrorContains(t, c.failure(), "bad certificate")
	})
}

func TestHTTP2ClientWriteFailureIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &brokenWritesConn{read: make(chan struct{})}
		defer close(conn.read)
		c := NewHTTP2ClientConn(conn, nil)
		start := time.Now()
		<-c.done
		require.Equal(t, http2WriteFailureGrace, time.Since(start))
		require.ErrorContains(t, c.failure(), "broken pipe")
	})
}
