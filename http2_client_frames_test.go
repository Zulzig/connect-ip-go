package connectip

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"testing"
	"time"
)

func TestHTTP2ClientSettings(t *testing.T) {
	p, _ := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: 1 << 20})
	settings := nextFrame[*http2.SettingsFrame](p)
	window, ok := settings.Value(http2.SettingInitialWindowSize)
	require.True(t, ok)
	require.EqualValues(t, 1<<20, window)
	push, ok := settings.Value(http2.SettingEnablePush)
	require.True(t, ok)
	require.Zero(t, push)

	update := nextFrame[*http2.WindowUpdateFrame](p)
	require.Zero(t, update.StreamID)
	require.EqualValues(t, 1<<20-http2InitialWindow, update.Increment)
}

func TestHTTP2ClientGoAwayWithoutRejection(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	require.NoError(t, p.fr.WriteGoAway(http2StreamID, http2.ErrCodeNo, nil))
	require.NoError(t, p.fr.WritePing(false, [8]byte{})) // the client handled the GOAWAY
	require.NoError(t, c.failure())

	require.NoError(t, conn.sendCapsule(&routeAdvertisementCapsule{}))
	require.NotNil(t, nextFrame[*http2.DataFrame](p))
}

func TestHTTP2ClientAnswersProxy(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c, http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0})

	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	require.NoError(t, p.fr.WritePing(false, data))
	ping := nextFrame[*http2.PingFrame](p)
	require.True(t, ping.IsAck())
	require.Equal(t, data, ping.Data)
}

// TestHTTP2ClientControlFramesDoNotWaitForData checks that the read loop answers the proxy while a DATA write
// blocks, and that a proxy that never reads its answers ends the connection.
func TestHTTP2ClientControlFramesDoNotWaitForData(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	// The proxy doesn't read: the DATA frame blocks in the network.
	_, err := conn.str.Write(appendTestCapsule(nil, 0x41, "capsule"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		if !c.wmu.TryLock() {
			return true
		}
		c.wmu.Unlock()
		return false
	}, time.Second, time.Millisecond)

	// The read loop keeps going, however, or the proxy couldn't send this. If it
	// waited for the write, the proxy's own writes would block too: that's a deadlock.
	for range maxQueuedHTTP2ControlFrames {
		require.NoError(t, p.fr.WritePing(false, [8]byte{}))
	}
	// Until the control queue is full, with one frame in the hands of the writer: the proxy is abusing it.
	for range 2 {
		_ = p.fr.WritePing(false, [8]byte{})
	}
	require.ErrorContains(t, c.waitForFailure(t), "doesn't read its control frames")
}

// TestHTTP2ClientPingQueueIsBounded checks that Ping fails once the control queue is full,
// without ending the connection.
func TestHTTP2ClientPingQueueIsBounded(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.handshake()
	// The proxy reads nothing else: the SETTINGS ACK blocks the writer, and the PING frames queue up.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var err error
	for range maxQueuedHTTP2ControlFrames + 2 {
		if err = c.Ping(ctx); !errors.Is(err, context.Canceled) {
			break
		}
	}
	require.ErrorContains(t, err, "doesn't read its control frames")
	require.NoError(t, c.failure(), "whether to give up on the connection is the caller's call")
}

// TestHTTP2ClientControlQueueBoundsEveryFrame checks that the frames the client owes the proxy
// respect the limit too, and end the connection when they can't be sent.
func TestHTTP2ClientControlQueueBoundsEveryFrame(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.handshake()
	// The proxy reads nothing else: the SETTINGS ACK blocks the writer, and the PING frames fill the queue.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var err error
	for range maxQueuedHTTP2ControlFrames + 2 {
		if err = c.Ping(ctx); !errors.Is(err, context.Canceled) {
			break
		}
	}
	require.ErrorContains(t, err, "doesn't read its control frames")
	c.reset(http2.ErrCodeCancel)
	require.ErrorContains(t, c.waitForFailure(t), "doesn't read its control frames")
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Len(t, c.control, maxQueuedHTTP2ControlFrames)
}
