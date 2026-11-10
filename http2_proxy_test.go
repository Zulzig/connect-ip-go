package connectip

import (
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// responseWriterWithoutFlush can set deadlines, like the ResponseWriter of net/http, but not flush.
type responseWriterWithoutFlush struct{ http.ResponseWriter }

func (responseWriterWithoutFlush) SetWriteDeadline(time.Time) error { return nil }

func TestProxyHTTP2CannotFlush(t *testing.T) {
	_, err := proxyHTTP2(responseWriterWithoutFlush{httptest.NewRecorder()}, http.NoBody)
	require.ErrorContains(t, err, "failed to send response")
}

// responseWriterWithoutDeadline is a middleware that hides the ResponseWriter of net/http: no Unwrap.
type responseWriterWithoutDeadline struct{ http.ResponseWriter }

func (responseWriterWithoutDeadline) Flush() {}

func TestProxyHTTP2CannotSetWriteDeadline(t *testing.T) {
	_, err := proxyHTTP2(responseWriterWithoutDeadline{httptest.NewRecorder()}, http.NoBody)
	require.ErrorIs(t, err, http.ErrNotSupported)
	require.ErrorContains(t, err, "write deadlines")
}

func TestProxyBodyStopsAfterClose(t *testing.T) {
	rec := httptest.NewRecorder()
	b := &proxyBody{w: rec, rc: http.NewResponseController(rec), body: http.NoBody}
	n, err := b.Write([]byte("data"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.NoError(t, b.CloseWrite())
	_, err = b.Write([]byte("more"))
	require.ErrorIs(t, err, net.ErrClosed)
	b.Reset(http2.ErrCodeCancel) // must not touch the ResponseWriter after CloseWrite
	require.Equal(t, "data", rec.Body.String())
}
