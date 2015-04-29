package robustsession

import (
	"net"
	"time"
)

// deadlineConn wraps a net.Conn and calls SetReadDeadline or SetWriteDeadline
// before doing the actual Read and Write call, respectively. The deadline is
// set to now+|timeout|.
//
// This is useful for long-running connections (such as for the GetMessages
// request) which cannot have a timeout for the entire operation, but still
// benefit from timeouts for the individual Read and Write calls. This behavior
// is also called “idle timeout” sometimes.
//
// See http://stackoverflow.com/a/5509956/712014 for why a write deadline is
// necessary. If we did not have a write deadline, data could accumulate in the
// kernel socket buffer and just indefinitely block our Write() call.
type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func NewDeadlineConn(conn net.Conn, timeout time.Duration) *deadlineConn {
	return &deadlineConn{
		conn,
		timeout,
	}
}

func (d *deadlineConn) Read(b []byte) (int, error) {
	if err := d.SetReadDeadline(time.Now().Add(d.timeout)); err != nil {
		return 0, err
	}
	return d.Conn.Read(b)
}

func (d *deadlineConn) Write(b []byte) (int, error) {
	if err := d.SetWriteDeadline(time.Now().Add(d.timeout)); err != nil {
		return 0, err
	}
	return d.Conn.Write(b)
}

// DeadlineConnDialer returns a net.Dialer (actual interface type unused
// because it is not covered by go1) which wraps all net.Conns in a
// deadlineConn with the specified |timeout|, applied to both, Read and Write
// calls. The dialing itself must be done within |dialTimeout| and TCP
// keepalive is enabled (if compiled with go1.2+) with a period of
// |keepalivePeriod|.
func DeadlineConnDialer(dialTimeout, keepalivePeriod, timeout time.Duration) func(string, string) (net.Conn, error) {
	return func(network, address string) (net.Conn, error) {
		conn, err := net.DialTimeout(network, address, dialTimeout)
		if err != nil {
			return nil, err
		}

		// In addition to setting a read deadline to detect problems on the
		// application level (e.g. a server deadlock), we also enable TCP
		// keepalive on all connections. The additional benefit is that
		// keepalive packets are sent in a shorter interval and possibly with a
		// different start time due to net/http’s connection pooling and
		// re-use. Therefore, network layer problems might be detected more
		// quickly.
		setupKeepAlive(conn, keepalivePeriod)

		return NewDeadlineConn(conn, timeout), nil
	}
}
