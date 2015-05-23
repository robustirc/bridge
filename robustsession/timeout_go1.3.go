// +build go1.3

// TLSHandshakeTimeout was introduced in go1.3, see
// https://github.com/golang/go/commit/fd4b4b56

package robustsession

import (
	"net/http"
	"time"
)

func setupTLSHandshakeTimeout(transport *http.Transport, timeout time.Duration) {
	transport.TLSHandshakeTimeout = timeout
}
