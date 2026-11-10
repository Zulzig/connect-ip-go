package connectip

import (
	"bytes"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestHTTP2ClientRequest(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	req := newHTTP2TestRequest(t, t.Context())
	req.Header().Set("Authorization", "Bearer token")
	// Connection-specific header fields don't exist in HTTP/2: RFC 9113, section 8.2.2.
	// They include those that Connection names, RFC 9110, section 7.6.1.
	req.Header().Set("Connection", "keep-alive, X-Hop , TE")
	req.Header().Set("Keep-Alive", "timeout=5")
	req.Header().Set("X-Hop", "1")
	// Except TE, which can only say "trailers".
	req.Header().Set("Te", "gzip, trailers")
	go c.Dial(req)
	p.handshake(extendedConnectSetting)

	headers := nextFrame[*http2.MetaHeadersFrame](p)
	require.Equal(t, uint32(http2StreamID), headers.StreamID)
	require.False(t, headers.StreamEnded(), "the stream carries the capsules of the client")
	require.Equal(t, []hpack.HeaderField{
		{Name: ":method", Value: http.MethodConnect},
		{Name: ":protocol", Value: requestProtocol},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "proxy.example:443"},
		{Name: ":path", Value: "/connect-ip?epoch=1"},
	}, headers.PseudoFields())
	require.ElementsMatch(t, []hpack.HeaderField{
		{Name: "capsule-protocol", Value: capsuleProtocolHeaderValue},
		{Name: "authorization", Value: "Bearer token"},
		{Name: "te", Value: "trailers"},
	}, headers.RegularFields())
}

// TestHTTP2ClientDropsTEWithoutTrailers checks that a TE header field without "trailers" isn't sent.
func TestHTTP2ClientDropsTEWithoutTrailers(t *testing.T) {
	req := newHTTP2TestRequest(t, t.Context())
	req.Header().Set("Te", "gzip")
	block, err := encodeHTTP2Request(req.httpRequest())
	require.NoError(t, err)
	fields, err := hpack.NewDecoder(http2InitialTableSize, nil).DecodeFull(block)
	require.NoError(t, err)
	for _, field := range fields {
		require.NotEqual(t, "te", field.Name)
	}
}

// TestHTTP2ClientInvalidHeader checks that Dial refuses a header field that HTTP/2 can't carry.
func TestHTTP2ClientInvalidHeader(t *testing.T) {
	for name, header := range map[string][2]string{
		"name":  {"Bad Name", "value"},
		"value": {"Name", "bad\x00value"},
	} {
		t.Run(name, func(t *testing.T) {
			_, c := newFakeHTTP2Proxy(t, nil)
			req := newHTTP2TestRequest(t, t.Context())
			req.Header()[header[0]] = []string{header[1]}
			_, _, err := c.Dial(req)
			require.ErrorContains(t, err, "invalid")
		})
	}
}

func TestHTTP2ClientRequestHeadersTooLarge(t *testing.T) {
	_, c := newFakeHTTP2Proxy(t, nil)
	req := newHTTP2TestRequest(t, t.Context())
	req.Header().Set("Too-Large", string(bytes.Repeat([]byte("x"), 2*http2InitialMaxFrameSize)))
	_, _, err := c.Dial(req)
	require.ErrorContains(t, err, "request headers too large")
}

// TestHTTP2ClientInterimResponseEndingStream checks that an interim response can't end the stream.
func TestHTTP2ClientInterimResponseEndingStream(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("103", true)
	select {
	case r := <-result:
		require.ErrorIs(t, r.err, http2.ConnectionError(http2.ErrCodeProtocol))
	case <-time.After(fakeHTTP2Timeout):
		t.Fatal("Dial didn't return")
	}
}

func TestHTTP2ClientIgnoresInterimResponses(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	result := dialAsync(t, t.Context(), c)
	p.handshake(extendedConnectSetting)
	nextFrame[*http2.MetaHeadersFrame](p)
	p.writeResponse("103", false)
	p.writeResponse("200", false)
	r := <-result
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.rsp.StatusCode)
	p.drain()
	require.NoError(t, r.conn.Close())
}

// TestHTTP2ClientMalformed checks that the frames that break HTTP/2 end the connection.
func TestHTTP2ClientMalformed(t *testing.T) {
	for name, tc := range map[string]struct {
		send func(*fakeHTTP2Proxy)
		want string
	}{
		"PING before SETTINGS": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WritePing(false, [8]byte{})) },
			"expected a SETTINGS frame",
		},
		"SETTINGS ACK before SETTINGS": {
			func(p *fakeHTTP2Proxy) { require.NoError(p.t, p.fr.WriteSettingsAck()) },
			"expected a SETTINGS frame",
		},
		"invalid setting": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 2}))
			},
			"invalid setting",
		},
		"HEADERS without a request": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				p.writeResponse("200", false)
			},
			"unexpected HEADERS",
		},
		"DATA without a request": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteData(http2StreamID, false, []byte("data")))
			},
			"unexpected DATA",
		},
		"GOAWAY rejecting the stream": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteGoAway(0, http2.ErrCodeNo, nil))
			},
			"GOAWAY",
		},
		"GOAWAY with an error": {
			func(p *fakeHTTP2Proxy) {
				require.NoError(p.t, p.fr.WriteSettings())
				require.NoError(p.t, p.fr.WriteGoAway(http2StreamID, http2.ErrCodeProtocol, nil))
			},
			"GOAWAY",
		},
		"not HTTP/2": {
			func(p *fakeHTTP2Proxy) {
				// The client gives up after reading a frame header: this write can fail.
				_, _ = io.WriteString(p.conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
			},
			"reading from the proxy",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			p.drain()
			tc.send(p)
			require.ErrorContains(t, c.waitForFailure(t), tc.want)

			r := <-dialAsync(t, t.Context(), c)
			require.ErrorContains(t, r.err, tc.want)
		})
	}
}

// TestHTTP2ClientInvalidStatus checks that Dial rejects a :status that isn't 3 digits.
func TestHTTP2ClientInvalidStatus(t *testing.T) {
	// RFC 9113, section 8.3.2: a 3-digit code, which strconv alone would read more liberally.
	for _, status := range []string{"+20", "0200", "20", "2O0"} {
		t.Run(status, func(t *testing.T) {
			p, c := newFakeHTTP2Proxy(t, nil)
			result := dialAsync(t, t.Context(), c)
			p.handshake(extendedConnectSetting)
			nextFrame[*http2.MetaHeadersFrame](p)
			p.writeResponse(status, false)
			require.ErrorContains(t, (<-result).err, "invalid status")
		})
	}
}

func TestHTTP2ClientTrailers(t *testing.T) {
	p, c := newFakeHTTP2Proxy(t, nil)
	conn := p.establish(c)
	p.writeHeaders(true, hpack.HeaderField{Name: "x-trailer", Value: "1"})
	_, err := conn.ReadPacket(make([]byte, 1500))
	var closeErr *CloseError
	require.ErrorAs(t, err, &closeErr)
	require.True(t, closeErr.Remote)
	require.NoError(t, c.failure(), "the trailers were valid")
}
