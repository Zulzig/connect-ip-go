package connectip

import (
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"io"
)

// writePreface opens the connection: the client preface, the settings of the client, and the
// connection-level window beyond the initial 65535 bytes, which no setting can change.
func (c *HTTP2ClientConn) writePreface(fr *http2.Framer) error {
	if _, err := io.WriteString(c.nc, http2.ClientPreface); err != nil {
		return err
	}
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(c.window)},
	); err != nil {
		return err
	}
	if c.window == http2InitialWindow {
		return nil
	}
	return fr.WriteWindowUpdate(0, uint32(c.window-http2InitialWindow))
}

// queueControlFrame queues a frame owed to the proxy, which goes out ahead of DATA frames.
// It refuses the frame once maxQueuedHTTP2ControlFrames wait: a proxy that doesn't read
// must not make them pile up, whether it asks for them or Ping does.
func (c *HTTP2ClientConn) queueControlFrame(write func(*http2.Framer) error) error {
	if len(c.control) >= maxQueuedHTTP2ControlFrames {
		return errors.New("connect-ip: the proxy doesn't read its control frames")
	}
	c.control = append(c.control, write)
	c.cond.Broadcast()
	return nil
}

// writeFrame writes frames with the Framer, one writer at a time.
func (c *HTTP2ClientConn) writeFrame(write func(*http2.Framer) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return write(c.fr)
}

// writeControlFrames writes the control frames in the order they were queued, until the connection fails.
func (c *HTTP2ClientConn) writeControlFrames() {
	for {
		c.mu.Lock()
		for len(c.control) == 0 && c.err == nil {
			c.cond.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		write := c.control[0]
		c.control[0] = nil
		c.control = c.control[1:]
		c.mu.Unlock()

		if err := c.writeFrame(write); err != nil {
			c.failWrite(err)
			return
		}
	}
}

// readFrames reads the frames of the proxy, which must start with its SETTINGS, until the connection fails.
func (c *HTTP2ClientConn) readFrames() {
	for first := true; ; first = false {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.fail(fmt.Errorf("connect-ip: reading from the proxy: %w", err))
			return
		}
		if settings, ok := f.(*http2.SettingsFrame); first && (!ok || settings.IsAck()) {
			c.fail(fmt.Errorf("connect-ip: expected a SETTINGS frame from the proxy, got %s", f.Header().Type))
			return
		}
		if err := c.handleFrame(f); err != nil {
			c.fail(err)
			return
		}
	}
}

// handleFrame applies a frame from the proxy. An error ends the connection.
func (c *HTTP2ClientConn) handleFrame(f http2.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch f := f.(type) {
	case *http2.SettingsFrame:
		return c.handleSettings(f)
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.WindowUpdateFrame:
		return c.handleWindowUpdate(f)
	case *http2.PingFrame:
		return c.handlePing(f)
	case *http2.RSTStreamFrame:
		return c.handleReset(f)
	case *http2.GoAwayFrame:
		// The proxy can drain its connections: the stream it didn't reject goes on until it ends.
		if f.ErrCode != http2.ErrCodeNo || f.LastStreamID < http2StreamID {
			return fmt.Errorf("connect-ip: GOAWAY from the proxy: %s", f.ErrCode)
		}
	case *http2.PushPromiseFrame:
		return errors.New("connect-ip: PUSH_PROMISE from the proxy, although disabled")
	}
	return nil
}

// handleSettings applies the settings of the proxy, and acknowledges them.
func (c *HTTP2ClientConn) handleSettings(f *http2.SettingsFrame) error {
	if f.IsAck() {
		return nil
	}
	err := f.ForeachSetting(func(s http2.Setting) error {
		if err := s.Valid(); err != nil {
			return fmt.Errorf("connect-ip: invalid setting from the proxy %s: %w", s, err)
		}
		switch s.ID {
		case http2.SettingInitialWindowSize:
			// RFC 9113, section 6.9.2: this applies to the stream, and can make its window negative.
			c.streamSend += int64(s.Val) - c.initialSend
			c.initialSend = int64(s.Val)
		case http2.SettingMaxFrameSize:
			c.maxFrame = int64(s.Val)
		case http2.SettingEnableConnectProtocol:
			c.extendedConnect = s.Val == 1
		case http2.SettingMaxConcurrentStreams:
			c.noStreams = s.Val == 0
		}
		return nil
	})
	if err != nil {
		return err
	}
	if c.streamSend > http2MaxWindow {
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	if err := c.queueControlFrame(func(fr *http2.Framer) error { return fr.WriteSettingsAck() }); err != nil {
		return err
	}
	if !c.sawSettings {
		c.sawSettings = true
		close(c.settings)
	}
	if !c.noStreams && c.streamsAllowed != nil {
		close(c.streamsAllowed)
		c.streamsAllowed = nil
	}
	return nil
}

// handlePing answers the PING frames of the proxy, and completes the Ping calls it acknowledges.
func (c *HTTP2ClientConn) handlePing(f *http2.PingFrame) error {
	if f.IsAck() {
		if ack, ok := c.pings[f.Data]; ok {
			close(ack)
			delete(c.pings, f.Data)
		}
		return nil
	}
	data := f.Data
	return c.queueControlFrame(func(fr *http2.Framer) error { return fr.WritePing(true, data) })
}
