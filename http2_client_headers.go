package connectip

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// encodeHTTP2Request encodes the HEADERS of an Extended CONNECT request, with its own pseudo-header
// fields and without the connection-specific ones, and checks that they fit in a single frame.
func encodeHTTP2Request(req *http.Request) ([]byte, error) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	var block bytes.Buffer
	enc := hpack.NewEncoder(&block)
	// There's only one request: the dynamic table couldn't be reused, and the proxy could have shrunk it.
	enc.SetMaxDynamicTableSize(0)
	// Writing to a bytes.Buffer doesn't fail.
	write := func(name, value string) { _ = enc.WriteField(hpack.HeaderField{Name: name, Value: value}) }
	write(":method", req.Method)
	write(":protocol", req.Proto)
	write(":scheme", req.URL.Scheme)
	write(":authority", host)
	write(":path", req.URL.RequestURI())
	// RFC 9110, section 7.6.1: Connection also names the fields that only concern this connection.
	nominated := make(map[string]bool)
	for name, values := range req.Header {
		if !strings.EqualFold(name, "connection") {
			continue
		}
		for _, value := range values {
			for token := range strings.SplitSeq(value, ",") {
				nominated[strings.ToLower(strings.TrimSpace(token))] = true
			}
		}
	}
	for name, values := range req.Header {
		if !httpguts.ValidHeaderFieldName(name) {
			return nil, fmt.Errorf("connect-ip: invalid header field name %q", name)
		}
		name = strings.ToLower(name)
		// RFC 9113, section 8.2.2: HTTP/2 has no connection-specific header fields.
		// net/http drops them, and a server rejects a request that carries them.
		switch name {
		case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade":
			continue
		case "te":
			// The exception, which can only say "trailers". HTTP/1.1 nominates it, which doesn't apply here.
			if httpguts.HeaderValuesContainsToken(values, "trailers") {
				write(name, "trailers")
			}
			continue
		}
		if nominated[name] {
			continue
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("connect-ip: invalid value for header field %q", name)
			}
			write(name, value)
		}
	}
	if block.Len() > http2InitialMaxFrameSize {
		return nil, errors.New("connect-ip: request headers too large")
	}
	return block.Bytes(), nil
}

// handleHeaders reads the response to the request, after any interim responses, and then its trailers.
func (c *HTTP2ClientConn) handleHeaders(f *http2.MetaHeadersFrame) error {
	if f.StreamID != http2StreamID || !c.dialed {
		return fmt.Errorf("connect-ip: unexpected HEADERS from the proxy on stream %d", f.StreamID)
	}
	if f.Truncated {
		return errors.New("connect-ip: response headers too large")
	}
	if c.recvEnded {
		return http2.ConnectionError(http2.ErrCodeStreamClosed)
	}
	if c.responded {
		// Trailers, which end the stream and carry no pseudo-header: RFC 9113, section 8.1.
		if !f.StreamEnded() || len(f.PseudoFields()) > 0 {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		c.recvEnded = true
		c.cond.Broadcast()
		return nil
	}
	status, err := parseHTTP2Status(f.PseudoValue("status"))
	if err != nil {
		return err
	}
	if status >= 100 && status <= 199 {
		// An interim response that ends the stream is malformed: RFC 9113, section 8.1.
		// Dial would otherwise wait for a final response that can't come.
		if f.StreamEnded() {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		return nil
	}
	if f.StreamEnded() {
		c.recvEnded = true
		c.cond.Broadcast()
	}
	header := make(http.Header)
	for _, field := range f.RegularFields() {
		header.Add(field.Name, field.Value)
	}
	c.responded = true
	c.response <- &http.Response{
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode: status,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		Body:       http.NoBody,
	}
	return nil
}

// parseHTTP2Status parses a :status pseudo-header, which RFC 9113, section 8.3.2 makes a 3-digit code.
func parseHTTP2Status(s string) (int, error) {
	if len(s) != 3 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("connect-ip: invalid status from the proxy: %q", s)
	}
	return strconv.Atoi(s)
}
