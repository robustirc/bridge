//go:build !go1.3
// +build !go1.3

package robustsession

import (
	"net/http"
	"time"
)

func setupTLSHandshakeTimeout(transport *http.Transport, timeout time.Duration) {
}
