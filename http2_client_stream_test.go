package connectip

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// TestHTTP2ClientWindowOverflow checks that a send window beyond 2^31-1 ends the connection.
func TestHTTP2ClientWindowOverflow(t *testing.T) {
	flowControlError := http2.ConnectionError(http2.ErrCodeFlowControl)
	for name, send := range map[string]func(*fakeHTTP2Proxy){
		"connection": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(0, http2MaxWindow))
		},
		"stream": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(http2StreamID, http2MaxWindow))
		},
		"setting": func(p *fakeHTTP2Proxy) {
			require.NoError(p.t, p.fr.WriteWindowUpdate(http2StreamID, http2MaxWindow-http2InitialWindow))
			require.NoError(p.t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2InitialWindow + 1}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.drain()
			require.NoError(t, p.fr.WriteSettings())
			c.skipDial() // the stream has to exist for its window to be updated
			send(p)
			require.ErrorIs(t, c.waitForFailure(t), flowControlError)
		})
	}
}

func TestHTTP2ClientStreamReset(t *testing.T) {
	t.Run("during the request", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		result := dialAsync(t, t.Context(), c)
		p.handshake(extendedConnectSetting)
		nextFrame[*http2.MetaHeadersFrame](p)
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeRefusedStream))
		require.ErrorContains(t, (<-result).err, "REFUSED_STREAM")
	})

	t.Run("during the session", func(t *testing.T) {
		p, c := newFakeHTTP2Proxy(t, nil)
		conn := p.establish(c)
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeInternal))
		_, err := conn.ReadPacket(make([]byte, 1500))
		require.ErrorIs(t, err, net.ErrClosed)
		require.ErrorContains(t, c.failure(), "INTERNAL_ERROR")
	})

	t.Run("after the response", func(t *testing.T) {
		// This is how net/http ends a stream when its handler returns.
		p, c := newFakeHTTP2Proxy(t, nil)
		p.drain()
		require.NoError(t, p.fr.WriteSettings())
		c.skipDial()
		require.NoError(t, p.fr.WriteData(http2StreamID, true, []byte("data")))
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeNo))
		require.NoError(t, p.fr.WritePing(false, [8]byte{})) // the client handled the reset

		body := &clientBody{c: c}
		got, err := io.ReadAll(body)
		require.NoError(t, err)
		require.Equal(t, "data", string(got))
		require.NoError(t, c.failure())

		n, err := body.Write([]byte("data"))
		require.ErrorIs(t, err, net.ErrClosed)
		require.Zero(t, n)
	})
}

// TestHTTP2ClientRespectsFlowControl checks that the client doesn't send more than the stream window,
// and resumes when the proxy widens it.
func TestHTTP2ClientRespectsFlowControl(t *testing.T) {
	const window = 100
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingInitialWindowSize, Val: window})

	received := func(want int) {
		t.Helper()
		var got int
		for got < want {
			f := nextFrame[*http2.DataFrame](p)
			got += len(f.Data())
		}
		require.Equal(t, want, got)
	}
	nothingMore := func() {
		t.Helper()
		require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
		_, err := p.conn.Read(make([]byte, 1))
		require.ErrorIs(t, err, os.ErrDeadlineExceeded)
		require.NoError(t, p.conn.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))
	}

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 2*window)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	received(window)
	nothingMore()

	// The stream's window opens through the settings, and can even go negative.
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: window - 50}))
	nextFrame[*http2.SettingsFrame](p)
	nothingMore()
	require.NoError(t, p.fr.WriteWindowUpdate(http2StreamID, 60))
	received(10)
	nothingMore()

	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2InitialWindow}))
	received(len(data) - window - 10)
	c.mu.Lock()
	sent := http2InitialWindow - c.connSend
	c.mu.Unlock()
	require.EqualValues(t, len(data), sent)
}

// TestHTTP2ClientRespectsConnectionWindow checks that the connection window limits the client
// as well as the stream window.
func TestHTTP2ClientRespectsConnectionWindow(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 24})

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 2*http2InitialWindow)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	var got int
	for got < http2InitialWindow {
		got += len(nextFrame[*http2.DataFrame](p).Data())
	}
	require.Equal(t, http2InitialWindow, got)
	require.NoError(t, p.conn.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	_, err = p.conn.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, p.conn.SetDeadline(time.Now().Add(fakeHTTP2Timeout)))

	require.NoError(t, p.fr.WriteWindowUpdate(0, 1<<20))
	for got < len(data) {
		got += len(nextFrame[*http2.DataFrame](p).Data())
	}
	require.Equal(t, len(data), got)
}

func TestHTTP2ClientRespectsMaxFrameSize(t *testing.T) {
	const maxFrame = 1 << 15
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c, http2.Setting{ID: http2.SettingMaxFrameSize, Val: maxFrame})

	data := appendTestCapsule(nil, 0x41, string(make([]byte, 3*maxFrame)))
	_, err := conn.str.Write(data)
	require.NoError(t, err)
	require.Len(t, nextFrame[*http2.DataFrame](p).Data(), maxFrame)
}

// TestHTTP2ClientRespectsLoweredMaxFrameSize checks that DATA frames follow a SETTINGS_MAX_FRAME_SIZE
// that the proxy lowered after the reservation.
func TestHTTP2ClientRespectsLoweredMaxFrameSize(t *testing.T) {
	const maxFrame = 2 * http2InitialMaxFrameSize
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c, http2.Setting{ID: http2.SettingMaxFrameSize, Val: maxFrame})
	n, err := c.reserve(maxFrame)
	require.NoError(t, err)
	require.Equal(t, maxFrame, n)

	// The proxy lowers the limit after the reservation, and the acknowledgment goes out before the DATA.
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingMaxFrameSize, Val: http2InitialMaxFrameSize}))
	require.True(t, nextFrame[*http2.SettingsFrame](p).IsAck())
	done := make(chan error, 1)
	go func() {
		sent, err := c.writeData(make([]byte, n))
		if err == nil && sent != n {
			err = fmt.Errorf("sent %d bytes of %d", sent, n)
		}
		done <- err
	}()
	for range 2 {
		require.Len(t, nextFrame[*http2.DataFrame](p).Data(), http2InitialMaxFrameSize)
	}
	require.NoError(t, <-done)
}

func TestHTTP2ClientRespectsLoweredWindow(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c)
	n, err := c.reserve(http2InitialMaxFrameSize)
	require.NoError(t, err)
	require.Equal(t, http2InitialMaxFrameSize, n)

	// The proxy lowers the stream window after the reservation, and the acknowledgment
	// goes out before the DATA: the proxy only allows what's left of the new window.
	const lowered = 5000
	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: lowered}))
	require.True(t, nextFrame[*http2.SettingsFrame](p).IsAck())
	type result struct {
		sent int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		sent, err := c.writeData(make([]byte, n))
		done <- result{sent, err}
	}()
	require.Len(t, nextFrame[*http2.DataFrame](p).Data(), lowered)
	r := <-done
	require.NoError(t, r.err)
	require.Equal(t, lowered, r.sent)

	// The rest of the reservation went back to the connection window.
	c.mu.Lock()
	defer c.mu.Unlock()
	require.Zero(t, c.streamSend)
	require.EqualValues(t, http2InitialWindow-lowered, c.connSend)
}

func TestHTTP2ClientNoDataAfterReset(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.establish(c)
	n, err := c.reserve(10)
	require.NoError(t, err)
	// A reset between the reservation and the write: the write mustn't start, since
	// the reset couldn't interrupt it.
	c.reset(http2.ErrCodeCancel)
	sent, err := c.writeData(make([]byte, n))
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, sent)
	require.NoError(t, c.failure())
}

// TestHTTP2ClientResetInterruptsBlockedWrite checks that a reset doesn't wait for a DATA write
// that the network blocks.
func TestHTTP2ClientResetInterruptsBlockedWrite(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	// The proxy doesn't read: the DATA frame blocks in the network.
	_, err := conn.str.Write(appendTestCapsule(nil, 0x41, "capsule"))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.writing
	}, time.Second, time.Millisecond)

	// Resetting the stream can't wait for that write, and interrupting it ends the connection.
	conn.str.CancelWrite(0)
	err = c.waitForFailure(t)
	require.ErrorContains(t, err, "writing to the proxy")
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	select {
	case <-conn.str.(*http2Stream).flushed:
	case <-time.After(fakeHTTP2Timeout):
		t.Fatal("the flush loop didn't return")
	}
}

// nextCredit reads the credit that the client grants, which has to be the same on both levels.
func (p *fakeHTTP2Proxy) nextCredit() uint32 {
	p.t.Helper()
	connection := nextFrame[*http2.WindowUpdateFrame](p)
	require.Zero(p.t, connection.StreamID)
	stream := nextFrame[*http2.WindowUpdateFrame](p)
	require.Equal(p.t, uint32(http2StreamID), stream.StreamID)
	require.Equal(p.t, connection.Increment, stream.Increment)
	return stream.Increment
}

// TestHTTP2ClientCreditsWhatItReads checks that the client credits what it reads, in batches.
func TestHTTP2ClientCreditsWhatItReads(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.establish(c)

	const frames, frameLen = 3, http2InitialMaxFrameSize
	// One capsule of an unknown type, which Conn reads and ignores.
	const headerLen = 2 + 4
	header := quicvarint.AppendWithLen(quicvarint.Append(nil, 0x41), frames*frameLen-headerLen, 4)
	frame := make([]byte, frameLen)
	copy(frame, header)
	require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
	for range frames - 1 {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, make([]byte, frameLen)))
	}
	// The credit comes in batches of at least half the window.
	credit := p.nextCredit()
	require.GreaterOrEqual(t, credit, uint32(http2InitialWindow/2))
	require.LessOrEqual(t, credit, uint32(frames*frameLen))
}

// TestHTTP2ClientCreditsPadding checks that the client credits padding without waiting for a reader.
func TestHTTP2ClientCreditsPadding(t *testing.T) {
	// Flow control covers padding, which no reader is ever going to consume.
	const frameLen = 256 // with the Pad Length field
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.establish(c)
	frames := (http2InitialWindow/2)/frameLen + 1
	for range frames {
		require.NoError(t, p.fr.WriteDataPadded(http2StreamID, false, nil, make([]byte, frameLen-1)))
	}
	require.Equal(t, uint32(frames*frameLen), p.nextCredit())
}

// TestHTTP2ClientFlowControlViolation checks that data beyond the receive window ends the connection.
func TestHTTP2ClientFlowControlViolation(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	p.drain()
	require.NoError(t, p.fr.WriteSettings())
	c.skipDial()
	frame := make([]byte, http2InitialMaxFrameSize)
	for range http2InitialWindow / len(frame) {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
	}
	require.NoError(t, p.fr.WriteData(http2StreamID, false, frame[:http2InitialWindow%len(frame)]))
	require.NoError(t, p.fr.WriteData(http2StreamID, false, []byte{0}))
	require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(http2.ErrCodeFlowControl))
}

// TestHTTP2ClientDropsDataAfterCloseRead checks that after CloseRead, the client drops what the proxy
// sends, and credits it.
func TestHTTP2ClientDropsDataAfterCloseRead(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	require.NoError(t, p.fr.WriteSettings())
	nextFrame[*http2.SettingsFrame](p)
	c.skipDial()
	body := &clientBody{c: c}
	body.CloseRead()
	_, err := body.Read(make([]byte, 1))
	require.ErrorIs(t, err, net.ErrClosed)

	// Nobody reads it, but it's credited all the same: twice the window goes through.
	frame := make([]byte, http2InitialMaxFrameSize)
	var sent, credited int
	for sent < 2*http2InitialWindow {
		require.NoError(t, p.fr.WriteData(http2StreamID, false, frame))
		sent += len(frame)
		if sent-credited >= http2InitialWindow/2 {
			credited += int(p.nextCredit())
		}
	}
	require.Equal(t, sent, credited)
	require.NoError(t, c.failure())
}

// TestHTTP2ClientWindowOnlyWidensWithTransmittedCredit checks that credit the writer couldn't take
// doesn't widen the receive window, nor make the control queue grow.
func TestHTTP2ClientWindowOnlyWidensWithTransmittedCredit(t *testing.T) {
	// The proxy never reads: the first WINDOW_UPDATE blocks the writer. The credit for
	// the padding that follows can't reach it, so the padding counts against the window.
	const frameLen = 256 // with the Pad Length field
	p, c := newFakeHTTP2Proxy(t, &HTTP2Config{ReceiveWindow: http2InitialWindow})
	require.NoError(t, p.fr.WriteSettings())
	nextFrame[*http2.SettingsFrame](p)
	c.skipDial()
	for range 3 * http2InitialWindow / frameLen {
		if err := p.fr.WriteDataPadded(http2StreamID, false, nil, make([]byte, frameLen-1)); err != nil {
			break // the client closed the connection
		}
	}
	require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(http2.ErrCodeFlowControl))
	// A single WINDOW_UPDATE waits, whatever the proxy sent, behind the SETTINGS ACK
	// if the writer hasn't taken it yet.
	c.mu.Lock()
	defer c.mu.Unlock()
	require.LessOrEqual(t, len(c.control), 2)
}

func TestHTTP2ClientEndOfStream(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	p.drain()
	require.NoError(t, p.fr.WriteSettings())
	c.skipDial()
	require.NoError(t, p.fr.WriteData(http2StreamID, true, []byte("data")))

	got, err := io.ReadAll(&clientBody{c: c})
	require.NoError(t, err)
	require.Equal(t, "data", string(got))
}

// TestHTTP2ClientStreamViolations checks that the frames that break the state of the stream
// end the connection, with the matching error code.
func TestHTTP2ClientStreamViolations(t *testing.T) {
	endStream := func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteData(http2StreamID, true, nil)) }
	for name, tc := range map[string]struct {
		send func(*fakeHTTP2Proxy)
		want http2.ErrCode
	}{
		"trailers with a pseudo-header": {
			func(p *fakeHTTP2Proxy) { p.writeResponse("200", true) },
			http2.ErrCodeProtocol,
		},
		"trailers without END_STREAM": {
			func(p *fakeHTTP2Proxy) { p.writeHeaders(false, hpack.HeaderField{Name: "x-trailer", Value: "1"}) },
			http2.ErrCodeProtocol,
		},
		"DATA after END_STREAM": {
			func(p *fakeHTTP2Proxy) {
				endStream(p)
				require.NoError(p.t, p.fr.WriteData(http2StreamID, false, []byte{0}))
			},
			http2.ErrCodeStreamClosed,
		},
		"HEADERS after END_STREAM": {
			func(p *fakeHTTP2Proxy) {
				endStream(p)
				p.writeHeaders(true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
			},
			http2.ErrCodeStreamClosed,
		},
		"WINDOW_UPDATE on an idle stream": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteWindowUpdate(3, 1)) },
			http2.ErrCodeProtocol,
		},
		"RST_STREAM on an idle stream": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteRSTStream(3, http2.ErrCodeNo)) },
			http2.ErrCodeProtocol,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.establish(c)
			tc.send(p)
			require.ErrorIs(t, c.waitForFailure(t), http2.ConnectionError(tc.want))
		})
	}
}

// TestHTTP2ClientCloseSendsEndStream checks that closing the Conn ends the stream.
func TestHTTP2ClientCloseSendsEndStream(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	done := make(chan error, 1)
	go func() { done <- conn.Close() }()
	p.next(func(f http2.Frame) bool {
		data, ok := f.(*http2.DataFrame)
		return ok && data.StreamEnded()
	})
	require.NoError(t, <-done)
}

func TestHTTP2ClientConnReset(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	code := quic.StreamErrorCode(http3.ErrCodeExcessiveLoad)
	conn.str.CancelWrite(code)
	rst := nextFrame[*http2.RSTStreamFrame](p)
	require.Equal(t, http2.ErrCodeEnhanceYourCalm, rst.ErrCode)
	conn.str.CancelWrite(code)
	n, err := (&clientBody{c: c}).Write([]byte("data"))
	require.ErrorIs(t, err, net.ErrClosed)
	require.Zero(t, n)
}
