// +build !go1.2

package deadlineconn

import (
	"net"
	"time"
)

func setupKeepAlive(conn net.Conn, period time.Duration) {
}
