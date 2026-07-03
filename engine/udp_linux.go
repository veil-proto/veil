//go:build linux

package engine

import (
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr mirrors the kernel's struct mmsghdr. Go's natural alignment matches
// the C layout on both 32- and 64-bit targets.
type mmsghdr struct {
	hdr unix.Msghdr
	n   uint32
}

type udpConn struct {
	*net.UDPConn
	raw       syscall.RawConn
	pktinfo   bool
	connected bool
	remote    *net.UDPAddr
	family    uint16
	readOOB   []byte

	// Persistent recvmmsg/sendmmsg state, reused across batches so the hot
	// path performs no per-packet allocations.
	rxMsgs   []mmsghdr
	rxIovs   []unix.Iovec
	rxNames  []unix.RawSockaddrInet6
	rxOOBs   [][]byte
	rxAddrs  []net.UDPAddr
	rxIPs    [][16]byte
	rxLocals [][4]byte

	txMsgs  []mmsghdr
	txIovs  []unix.Iovec
	txNames []unix.RawSockaddrInet6
	txOOBs  [][]byte
}

func newUDPConn(conn *net.UDPConn) *udpConn {
	c := &udpConn{UDPConn: conn}
	if remote, ok := conn.RemoteAddr().(*net.UDPAddr); ok && remote != nil {
		c.connected = true
		c.remote = remote
	}

	raw, err := conn.SyscallConn()
	if err != nil {
		log.Printf("UDP raw socket access unavailable: %v", err)
		return c
	}
	c.raw = raw

	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		var domain int
		domain, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
		if sockErr != nil {
			return
		}
		c.family = uint16(domain)
		sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
	}); err != nil {
		log.Printf("UDP pktinfo unavailable: %v", err)
		return c
	}
	if sockErr != nil {
		log.Printf("UDP pktinfo unavailable: %v", sockErr)
	} else {
		c.pktinfo = true
		c.readOOB = make([]byte, 128)
	}

	oobLen := syscall.CmsgSpace(syscall.SizeofInet4Pktinfo)
	c.rxMsgs = make([]mmsghdr, udpBatchSize)
	c.rxIovs = make([]unix.Iovec, udpBatchSize)
	c.rxNames = make([]unix.RawSockaddrInet6, udpBatchSize)
	c.rxOOBs = make([][]byte, udpBatchSize)
	c.rxAddrs = make([]net.UDPAddr, udpBatchSize)
	c.rxIPs = make([][16]byte, udpBatchSize)
	c.rxLocals = make([][4]byte, udpBatchSize)
	c.txMsgs = make([]mmsghdr, udpBatchSize)
	c.txIovs = make([]unix.Iovec, udpBatchSize)
	c.txNames = make([]unix.RawSockaddrInet6, udpBatchSize)
	c.txOOBs = make([][]byte, udpBatchSize)
	for i := 0; i < udpBatchSize; i++ {
		c.rxOOBs[i] = make([]byte, 128)
		c.txOOBs[i] = make([]byte, oobLen)
	}
	return c
}

func (c *udpConn) batchSize() int {
	if c.raw == nil {
		return 1
	}
	return udpBatchSize
}

func (c *udpConn) readFrom(buf []byte) (int, *net.UDPAddr, net.IP, error) {
	if !c.pktinfo {
		n, remote, err := c.ReadFromUDP(buf)
		return n, remote, nil, err
	}

	n, oobn, _, remote, err := c.ReadMsgUDP(buf, c.readOOB)
	if err != nil {
		return 0, nil, nil, err
	}
	return n, remote, parseLocalIP(c.readOOB[:oobn]), nil
}

// readBatch receives up to len(bufs) datagrams with a single recvmmsg call.
// The returned remote addresses point into reusable storage: callers must copy
// them before retaining (Peer.SetPath/NotePath already do).
func (c *udpConn) readBatch(bufs [][]byte, sizes []int, remotes []*net.UDPAddr, locals []net.IP) (int, error) {
	if c.raw == nil {
		n, remote, local, err := c.readFrom(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0], remotes[0], locals[0] = n, remote, local
		return 1, nil
	}

	count := min(len(bufs), len(c.rxMsgs))
	for i := 0; i < count; i++ {
		c.rxIovs[i].Base = &bufs[i][0]
		c.rxIovs[i].SetLen(len(bufs[i]))
		h := &c.rxMsgs[i].hdr
		h.Iov = &c.rxIovs[i]
		h.SetIovlen(1)
		h.Name = (*byte)(unsafe.Pointer(&c.rxNames[i]))
		h.Namelen = unix.SizeofSockaddrInet6
		h.Flags = 0
		if c.pktinfo {
			h.Control = &c.rxOOBs[i][0]
			h.SetControllen(len(c.rxOOBs[i]))
		} else {
			h.Control = nil
			h.SetControllen(0)
		}
		c.rxMsgs[i].n = 0
	}

	var got int
	var operr error
	err := c.raw.Read(func(fd uintptr) bool {
		for {
			r, _, e := unix.Syscall6(unix.SYS_RECVMMSG, fd,
				uintptr(unsafe.Pointer(&c.rxMsgs[0])), uintptr(count),
				unix.MSG_DONTWAIT, 0, 0)
			switch e {
			case 0:
				got = int(r)
				return true
			case unix.EINTR:
				continue
			case unix.EAGAIN:
				return false
			default:
				operr = e
				return true
			}
		}
	})
	if err != nil {
		return 0, err
	}
	if operr != nil {
		return 0, operr
	}

	for i := 0; i < got; i++ {
		sizes[i] = int(c.rxMsgs[i].n)
		remotes[i] = c.parseName(i)
		if c.pktinfo {
			locals[i] = parseLocalIPInto(c.rxOOBs[i][:c.rxMsgs[i].hdr.Controllen], c.rxLocals[i][:])
		} else {
			locals[i] = nil
		}
	}
	return got, nil
}

// parseName converts the raw sockaddr of message i into a reusable UDPAddr.
func (c *udpConn) parseName(i int) *net.UDPAddr {
	name := &c.rxNames[i]
	addr := &c.rxAddrs[i]
	switch name.Family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(name))
		ip := c.rxIPs[i][:4]
		copy(ip, sa.Addr[:])
		addr.IP, addr.Port, addr.Zone = ip, int(ntohs(sa.Port)), ""
	case unix.AF_INET6:
		ip := c.rxIPs[i][:16]
		copy(ip, name.Addr[:])
		addr.IP, addr.Port, addr.Zone = ip, int(ntohs(name.Port)), ""
	default:
		return nil
	}
	return addr
}

func (c *udpConn) writeTo(buf []byte, remote *net.UDPAddr, localIP net.IP) (int, error) {
	if c.connected {
		return c.Write(buf)
	}
	if !c.pktinfo {
		return c.WriteToUDP(buf, remote)
	}
	ip4 := localIP.To4()
	if ip4 == nil {
		n, _, err := c.WriteMsgUDP(buf, nil, remote)
		return n, err
	}

	oobLen := syscall.CmsgSpace(syscall.SizeofInet4Pktinfo)
	var oobBuf [64]byte
	oob := oobBuf[:oobLen]
	encodePktinfo(oob, ip4)

	n, _, err := c.WriteMsgUDP(buf, oob, remote)
	return n, err
}

// writeBatch sends the packets with as few sendmmsg calls as possible. A
// per-message failure drops that message and keeps the rest of the batch
// flowing, matching UDP's fire-and-forget contract.
func (c *udpConn) writeBatch(pkts [][]byte, remotes []*net.UDPAddr, locals []net.IP) error {
	if c.raw == nil {
		var firstErr error
		for i := range pkts {
			if _, err := c.writeTo(pkts[i], remotes[i], locals[i]); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	var firstErr error
	for off := 0; off < len(pkts); {
		n := min(len(pkts)-off, len(c.txMsgs))
		for i := 0; i < n; i++ {
			pkt := pkts[off+i]
			c.txIovs[i].Base = &pkt[0]
			c.txIovs[i].SetLen(len(pkt))
			h := &c.txMsgs[i].hdr
			h.Iov = &c.txIovs[i]
			h.SetIovlen(1)
			h.Flags = 0
			h.Control = nil
			h.SetControllen(0)
			if c.connected {
				h.Name = nil
				h.Namelen = 0
			} else {
				h.Name = (*byte)(unsafe.Pointer(&c.txNames[i]))
				h.Namelen = c.encodeName(i, remotes[off+i])
			}
			if c.pktinfo && locals[off+i] != nil {
				if ip4 := locals[off+i].To4(); ip4 != nil {
					encodePktinfo(c.txOOBs[i], ip4)
					h.Control = &c.txOOBs[i][0]
					h.SetControllen(len(c.txOOBs[i]))
				}
			}
			c.txMsgs[i].n = 0
		}

		sent := 0
		var operr error
		err := c.raw.Write(func(fd uintptr) bool {
			for sent < n {
				r, _, e := unix.Syscall6(unix.SYS_SENDMMSG, fd,
					uintptr(unsafe.Pointer(&c.txMsgs[sent])), uintptr(n-sent),
					unix.MSG_DONTWAIT, 0, 0)
				switch e {
				case 0:
					sent += int(r)
				case unix.EINTR:
					continue
				case unix.EAGAIN:
					return false
				default:
					// The head of the remaining slice failed; skip it so the
					// rest of the batch still goes out.
					if operr == nil {
						operr = e
					}
					sent++
				}
			}
			return true
		})
		if err != nil {
			return err
		}
		if operr != nil && firstErr == nil {
			firstErr = operr
		}
		off += n
	}
	return firstErr
}

// encodeName fills txNames[i] with a sockaddr for remote that matches the
// socket family (IPv4 addresses become v4-mapped on an AF_INET6 socket).
func (c *udpConn) encodeName(i int, remote *net.UDPAddr) uint32 {
	if c.family == unix.AF_INET {
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&c.txNames[i]))
		*sa = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: htons(uint16(remote.Port))}
		if ip4 := remote.IP.To4(); ip4 != nil {
			copy(sa.Addr[:], ip4)
		}
		return unix.SizeofSockaddrInet4
	}
	sa := &c.txNames[i]
	*sa = unix.RawSockaddrInet6{Family: unix.AF_INET6, Port: htons(uint16(remote.Port))}
	if ip4 := remote.IP.To4(); ip4 != nil {
		sa.Addr[10], sa.Addr[11] = 0xff, 0xff
		copy(sa.Addr[12:], ip4)
	} else if ip16 := remote.IP.To16(); ip16 != nil {
		copy(sa.Addr[:], ip16)
	}
	return unix.SizeofSockaddrInet6
}

// htons/ntohs convert between host order and the network-order Port field of
// raw sockaddrs, independent of host endianness.
func htons(port uint16) uint16 {
	var v uint16
	b := (*[2]byte)(unsafe.Pointer(&v))
	b[0] = byte(port >> 8)
	b[1] = byte(port)
	return v
}

func ntohs(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return uint16(b[0])<<8 | uint16(b[1])
}

// encodePktinfo writes an IP_PKTINFO cmsg selecting src as the source address.
func encodePktinfo(oob []byte, src net.IP) {
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	hdr.Level = syscall.IPPROTO_IP
	hdr.Type = syscall.IP_PKTINFO
	hdr.SetLen(syscall.CmsgLen(syscall.SizeofInet4Pktinfo))

	data := oob[syscall.CmsgLen(0):syscall.CmsgLen(syscall.SizeofInet4Pktinfo)]
	clear(data[:4])
	copy(data[4:8], src)  // ipi_spec_dst: source address for routing.
	copy(data[8:12], src) // ipi_addr: harmless for send, useful for symmetry.
}

func parseLocalIP(oob []byte) net.IP {
	return parseLocalIPInto(oob, make([]byte, 4))
}

// parseLocalIPInto extracts the IP_PKTINFO destination address into dst (a
// 4-byte reusable backing). The manual cmsg walk keeps the receive hot path
// allocation-free.
func parseLocalIPInto(oob, dst []byte) net.IP {
	for len(oob) >= syscall.CmsgLen(0) {
		hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
		cl := int(hdr.Len)
		if cl < syscall.CmsgLen(0) || cl > len(oob) {
			return nil
		}
		if hdr.Level == syscall.IPPROTO_IP && hdr.Type == syscall.IP_PKTINFO &&
			cl >= syscall.CmsgLen(syscall.SizeofInet4Pktinfo) {
			data := oob[syscall.CmsgLen(0):cl]
			ip := net.IP(dst[:4])
			copy(ip, data[8:12]) // ipi_addr: packet destination.
			if !ip.IsUnspecified() {
				return ip
			}
			copy(ip, data[4:8]) // ipi_spec_dst fallback.
			if !ip.IsUnspecified() {
				return ip
			}
			return nil
		}
		next := cmsgAlign(cl)
		if next <= 0 || next > len(oob) {
			return nil
		}
		oob = oob[next:]
	}
	return nil
}

func cmsgAlign(n int) int {
	const align = int(unsafe.Sizeof(uintptr(0)))
	return (n + align - 1) &^ (align - 1)
}
