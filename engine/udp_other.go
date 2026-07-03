//go:build !linux

package engine

import "net"

type udpConn struct {
	*net.UDPConn
	connected bool
	remote    *net.UDPAddr
}

func newUDPConn(conn *net.UDPConn) *udpConn {
	c := &udpConn{UDPConn: conn}
	// A connected socket (single-peer client) uses the kernel's fast path:
	// no per-send route lookup and no per-packet destination handling.
	if remote, ok := conn.RemoteAddr().(*net.UDPAddr); ok && remote != nil {
		c.connected = true
		c.remote = remote
	}
	return c
}

func (c *udpConn) batchSize() int { return 1 }

func (c *udpConn) readFrom(buf []byte) (int, *net.UDPAddr, net.IP, error) {
	if c.connected {
		n, err := c.Read(buf)
		return n, c.remote, nil, err
	}
	n, remote, err := c.ReadFromUDP(buf)
	return n, remote, nil, err
}

func (c *udpConn) readBatch(bufs [][]byte, sizes []int, remotes []*net.UDPAddr, locals []net.IP) (int, error) {
	n, remote, local, err := c.readFrom(bufs[0])
	if err != nil {
		return 0, err
	}
	sizes[0], remotes[0], locals[0] = n, remote, local
	return 1, nil
}

func (c *udpConn) writeTo(buf []byte, remote *net.UDPAddr, _ net.IP) (int, error) {
	if c.connected {
		return c.Write(buf)
	}
	return c.WriteToUDP(buf, remote)
}

func (c *udpConn) writeBatch(pkts [][]byte, remotes []*net.UDPAddr, locals []net.IP) error {
	var firstErr error
	for i := range pkts {
		// Keep the rest of the batch flowing past a transient per-packet
		// send error (e.g. WSAECONNRESET after an ICMP unreachable).
		if _, err := c.writeTo(pkts[i], remotes[i], locals[i]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
