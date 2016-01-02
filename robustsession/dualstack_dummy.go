// +build !go1.2

package robustsession

import (
	"net"
	"time"
)

func dualStackDialTimeout(network, address string, dialTimeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, dialTimeout)
}
