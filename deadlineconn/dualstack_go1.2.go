// +build go1.2

package deadlineconn

import (
	"net"
	"time"
)

func dualStackDialTimeout(network, address string, dialTimeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout:   dialTimeout,
		DualStack: true,
	}
	return d.Dial(network, address)
}
