// +build go1.2

// While SetKeepAlive is available in go1, the default keepalive
// interval of most Linux distributions is 2h, which is not useful for
// our case. So we also need SetKeepAlivePeriod, which was introduced in
// go1.2, see https://github.com/golang/go/commit/918922cf

package deadlineconn

import (
	"net"
	"time"
)

func setupKeepAlive(conn net.Conn, period time.Duration) {
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(period)
	}
}
