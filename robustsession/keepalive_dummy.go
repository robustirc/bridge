// +build !go1.2

package robustsession

import (
	"net"
	"time"
)

func setupKeepAlive(conn net.Conn, period time.Duration) {
}
