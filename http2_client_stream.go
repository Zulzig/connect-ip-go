package connectip

import (
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"time"
)

// handleData buffers the data of the stream for Read, within the receive window.
// Once the local side stopped reading, it drops the data and credits it right away.
func (c *HTTP2ClientConn) handleData(f *http2.DataFrame) error {
	if f.StreamID != http2StreamID || !c.responded {
		return fmt.Errorf("connect-ip: unexpected DATA from the proxy on stream %d", f.StreamID)
	}
	if c.recvEnded {
		return http2.ConnectionError(http2.ErrCodeStreamClosed)
	}
	// Flow control covers the whole frame, padding included.
	size := int64(f.Length)
	c.recvUsed += size
	if c.recvUsed > c.window {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	consumed := size
	if !c.recvClosed {
		data := f.Data()
		c.recv.Write(data)
		consumed -= int64(len(data))
	}
	if err := c.consume(consumed); err != nil {
		return err
	}
	if f.StreamEnded() {
		c.recvEnded = true
	}
	c.cond.Broadcast()
	return nil
}

// consume returns n bytes of flow control credit to the proxy.
// It batches them, so that a stream of small frames doesn't cause as many WINDOW_UPDATE frames,
// and queues a single WINDOW_UPDATE at a time, which takes the credit accrued while it waited.
// The window only widens when the writer takes the credit: a proxy that sends more than
// it was credited exceeds the window, and can't make the control queue grow.
func (c *HTTP2ClientConn) consume(n int64) error {
	c.recvCredit += n
	if c.creditQueued || c.recvCredit < c.window/2 {
		return nil
	}
	if err := c.queueControlFrame(c.writeWindowUpdate); err != nil {
		return err
	}
	c.creditQueued = true
	return nil
}

// writeWindowUpdate credits the proxy with what was consumed, on both the connection and the stream.
func (c *HTTP2ClientConn) writeWindowUpdate(fr *http2.Framer) error {
	c.mu.Lock()
	// recvCredit <= recvUsed <= window <= 2^31-1, which handleData enforces.
	credit := uint32(c.recvCredit)
	c.recvUsed -= c.recvCredit
	c.recvCredit = 0
	c.creditQueued = false
	c.mu.Unlock()
	if err := fr.WriteWindowUpdate(0, credit); err != nil {
		return err
	}
	return fr.WriteWindowUpdate(http2StreamID, credit)
}

// handleWindowUpdate widens the send window of the connection or the stream.
func (c *HTTP2ClientConn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	window := &c.streamSend
	if f.StreamID == 0 {
		window = &c.connSend
	} else if f.StreamID != http2StreamID || !c.dialed {
		// RFC 9113, section 5.1: a frame on an idle stream is a connection error.
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	*window += int64(f.Increment)
	if *window > http2MaxWindow {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	c.cond.Broadcast()
	return nil
}

// handleReset ends the connection when the proxy resets the stream, except with NO_ERROR
// after a complete response, which only stops the request.
func (c *HTTP2ClientConn) handleReset(f *http2.RSTStreamFrame) error {
	if f.StreamID != http2StreamID || !c.dialed {
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	// A server that finished its response can tell the client not to bother
	// sending the rest of the request. This isn't an error: RFC 9113, section 8.1.
	if !c.recvEnded || f.ErrCode != http2.ErrCodeNo {
		return fmt.Errorf("connect-ip: stream reset by the proxy: %s", f.ErrCode)
	}
	c.sendClosed = true
	c.cond.Broadcast()
	return nil
}

// reset aborts the stream with code, once.
func (c *HTTP2ClientConn) reset(code http2.ErrCode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.resetSent {
		return
	}
	c.resetSent = true
	c.sendClosed = true
	if c.writing {
		// The RST_STREAM would wait behind a DATA frame that the network doesn't
		// take: a proxy that stopped reading. Interrupting that write breaks the
		// framing, so it ends the connection, which this stream was the only use of.
		_ = c.nc.SetWriteDeadline(time.Now())
	}
	if err := c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteRSTStream(http2StreamID, code) }); err != nil {
		c.failLocked(err)
	}
}

// reserve waits for flow control to allow sending a frame of up to size bytes, and returns its size.
func (c *HTTP2ClientConn) reserve(size int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		switch {
		case c.err != nil:
			return 0, c.err
		case c.sendClosed:
			return 0, net.ErrClosed
		case c.connSend > 0 && c.streamSend > 0:
			n := min(int64(size), c.connSend, c.streamSend, c.maxFrame)
			c.connSend -= n
			c.streamSend -= n
			return int(n), nil
		}
		c.cond.Wait()
	}
}

// clientBody is the client's end of the HTTP/2 stream of an HTTP2ClientConn.
type clientBody struct {
	c *HTTP2ClientConn
}

var _ http2Body = &clientBody{}

// Read returns the data that the proxy sent on the stream, and credits it back to the proxy.
func (b *clientBody) Read(p []byte) (int, error) {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.recv.Len() == 0 {
		switch {
		case c.recvClosed:
			return 0, net.ErrClosed
		case c.recvEnded:
			return 0, io.EOF
		case c.err != nil:
			return 0, c.err
		}
		c.cond.Wait()
	}
	n, _ := c.recv.Read(p)
	if err := c.consume(int64(n)); err != nil {
		c.failLocked(err)
	}
	return n, nil
}

// Write sends p in DATA frames, as fast as flow control allows.
func (b *clientBody) Write(p []byte) (int, error) {
	c := b.c
	var written int
	for written < len(p) {
		n, err := c.reserve(len(p) - written)
		if err != nil {
			return written, err
		}
		sent, err := c.writeData(p[written : written+n])
		written += sent
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// writeData sends frame, which flow control allowed, in DATA frames, and returns how much it sent.
func (c *HTTP2ClientConn) writeData(frame []byte) (int, error) {
	// Under the same lock as reset, which interrupts a DATA write only if it sees it.
	c.mu.Lock()
	if err := c.err; err != nil {
		c.mu.Unlock()
		return 0, err
	}
	if c.sendClosed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.writing = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.writing = false
		c.mu.Unlock()
	}()

	var sent int
	err := c.writeFrame(func(fr *http2.Framer) error {
		// The proxy may have changed its settings since the reservation, and the SETTINGS ACK
		// gone out first: then the proxy applies them to these frames. Both writes hold wmu,
		// so the settings read here include all the acknowledged ones.
		c.mu.Lock()
		if c.streamSend < 0 {
			// A lower SETTINGS_INITIAL_WINDOW_SIZE took back part of the reservation.
			excess := min(int64(len(frame)), -c.streamSend)
			c.streamSend += excess
			c.connSend += excess
			frame = frame[:int64(len(frame))-excess]
		}
		c.mu.Unlock()
		for len(frame) > 0 {
			c.mu.Lock()
			n := min(len(frame), int(c.maxFrame))
			c.mu.Unlock()
			if err := fr.WriteData(http2StreamID, false, frame[:n]); err != nil {
				return err
			}
			frame = frame[n:]
			sent += n
		}
		return nil
	})
	if err != nil {
		return sent, c.failWrite(err)
	}
	return sent, nil
}

// CloseWrite ends the stream with an empty DATA frame.
func (b *clientBody) CloseWrite() error {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendClosed {
		return nil
	}
	c.sendClosed = true
	if err := c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteData(http2StreamID, true, nil) }); err != nil {
		c.failLocked(err)
		return err
	}
	return nil
}

// CloseRead drops the buffered data, and the data the proxy still sends, which it credits right away.
func (b *clientBody) CloseRead() {
	c := b.c
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recvClosed = true
	if err := c.consume(int64(c.recv.Len())); err != nil {
		c.failLocked(err)
	}
	c.recv.Reset()
	c.cond.Broadcast()
}

// Reset aborts the stream.
func (b *clientBody) Reset(code http2.ErrCode) { b.c.reset(code) }
