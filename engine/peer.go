package engine

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-proto/veil/config"
	"github.com/veil-proto/veil/core"
)

type Peer struct {
	PublicKey []byte
	IfaceCfg  *config.InterfaceConfig

	// Static handshake material, captured once at startup.
	localPriv    [32]byte
	remotePub    [32]byte
	nid          []byte
	kNet         []byte
	presharedKey []byte // optional, 32 bytes when configured; nil otherwise
	isInitiator  bool

	// keepaliveOverride is this peer's configured PersistentKeepalive, or 0 to
	// use the engine-wide jittered default (see keepaliveInterval in engine.go).
	keepaliveOverride time.Duration

	mu       sync.RWMutex
	endpoint *net.UDPAddr
	localIP  net.IP
	current  *Session
	previous *Session

	// In-flight initiator handshake (initial or rekey).
	pendingHM *core.HandshakeMachine
	lastInit  time.Time

	// lastMsg1Timestamp is the highest Msg1 handshake timestamp accepted from
	// this peer so far (see core.CompareTimestamps). A responder rejects any
	// Msg1 that doesn't strictly exceed it, which is what stops a passively
	// captured handshake from being replayed later to fingerprint the server
	// as a VEIL endpoint — the timestamp is checked before anything else about
	// the message is trusted.
	lastMsg1Timestamp [12]byte
	hasMsg1Timestamp  bool

	// frameBudget is the largest wire frame size confirmed (via pmtu.go probing)
	// to survive this peer's outbound path. It starts at floorPlaintext, a size
	// assumed safe everywhere, so real traffic never risks a path-MTU black hole
	// while probing discovers whether a larger size also works.
	frameBudget atomic.Int32

	probeMu   sync.Mutex
	probeSize int
	probeCh   chan struct{}

	// probing serializes MTU probing: the post-handshake probe and the periodic
	// maintenance refresh share one per-peer probe channel (armProbe/probeCh),
	// so only one may run at a time. lastMTUCheckNano is the last time a periodic
	// refresh was scheduled, so maintenance doesn't launch one every tick.
	probing          atomic.Bool
	lastMTUCheckNano atomic.Int64

	// lastRecvNano is the last time a valid transport packet (or a handshake
	// response) was received from this peer. The maintenance watchdog uses it to
	// detect a silently dead tunnel — one where we keep sending keepalives but
	// nothing comes back (the peer rekeyed and we missed it, or the path died) —
	// and force a fresh handshake instead of waiting out the ~30 min rekey timer.
	lastRecvNano atomic.Int64

	// Traffic counters (inner/plaintext bytes and packet counts), reported by
	// Stats for the control channel / observability. Keepalives count as packets
	// with zero bytes.
	rxBytes   atomic.Uint64
	txBytes   atomic.Uint64
	rxPackets atomic.Uint64
	txPackets atomic.Uint64
}

// addRx / addTx accumulate this peer's received / sent traffic. Called from the
// data-plane hot loops, so they must stay lock-free.
func (p *Peer) addRx(bytes int) {
	p.rxBytes.Add(uint64(bytes))
	p.rxPackets.Add(1)
}

func (p *Peer) addTx(bytes int) {
	p.txBytes.Add(uint64(bytes))
	p.txPackets.Add(1)
}

func (p *Peer) Endpoint() *net.UDPAddr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endpoint
}

func (p *Peer) SetEndpoint(addr *net.UDPAddr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpoint = addr
}

func (p *Peer) LocalIP() net.IP {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.localIP
}

// Path returns the current endpoint and local source IP without copying.
// Callers must treat both values as read-only: SetPath/NotePath replace them
// wholesale instead of mutating in place.
func (p *Peer) Path() (*net.UDPAddr, net.IP) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.endpoint, p.localIP
}

// SetPath stores a copy of the remote/local pair, so callers may pass buffers
// that are reused for the next batch of packets.
func (p *Peer) SetPath(addr *net.UDPAddr, localIP net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endpoint = cloneUDPAddr(addr)
	p.localIP = append(net.IP(nil), localIP...)
}

// NotePath records the path a valid packet arrived on. It only takes the write
// lock (and only clones) when something actually changed, keeping the receive
// hot path allocation-free. It reports whether the remote endpoint moved.
func (p *Peer) NotePath(remote *net.UDPAddr, localIP net.IP) bool {
	p.mu.RLock()
	epSame := udpAddrEqual(p.endpoint, remote)
	ipSame := localIP == nil || p.localIP.Equal(localIP)
	p.mu.RUnlock()
	if epSame && ipSame {
		return false
	}
	p.mu.Lock()
	if !epSame {
		p.endpoint = cloneUDPAddr(remote)
	}
	if !ipSame {
		p.localIP = append(net.IP(nil), localIP...)
	}
	p.mu.Unlock()
	return !epSame
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.IP.Equal(b.IP) && a.Zone == b.Zone
}

func (p *Peer) Current() *Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// Promote installs sess as the current session. The old current becomes the
// previous (grace) session; any older previous is torn down first, evicting its
// route tokens from the shared table. confirmed marks whether the peer is already known
// to hold sess's keys (true for the initiator; false for the responder until it
// receives data on the session).
func (p *Peer) Promote(sess *Session, confirmed bool) {
	if confirmed {
		sess.markConfirmed()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.previous != nil && p.previous.recvTokenWindow != nil {
		p.previous.recvTokenWindow.Teardown()
	}
	p.previous = p.current
	p.current = sess
	p.pendingHM = nil
}

// SendSession returns the session data should be sent on: the current session
// once it is confirmed, otherwise the previous (still-valid) session during a
// rekey. Falling back to an unconfirmed current only when there is no previous
// keeps the initial handshake working while making rekeys seamless.
func (p *Peer) SendSession() *Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.current != nil && p.current.isConfirmed() {
		return p.current
	}
	if p.previous != nil {
		return p.previous
	}
	return p.current
}

func (p *Peer) SetPending(hm *core.HandshakeMachine, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pendingHM = hm
	p.lastInit = now
}

func (p *Peer) Pending() (*core.HandshakeMachine, time.Time) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pendingHM, p.lastInit
}

// ExpirePrevious tears down the previous session if it is older than
// rejectAfterTime, so its route tokens stop consuming table space.
func (p *Peer) ExpirePrevious(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.previous != nil && now.Sub(p.previous.establishedAt) > rejectAfterTime {
		if p.previous.recvTokenWindow != nil {
			p.previous.recvTokenWindow.Teardown()
		}
		p.previous = nil
	}
}

// CheckAndUpdateMsg1Timestamp reports whether ts is newer than every Msg1
// timestamp previously accepted from this peer, and if so records it as the
// new high-water mark. A caller must treat false exactly like any other
// handshake validation failure (silent drop) — the whole point is that a
// replayed packet is indistinguishable on the wire from noise.
func (p *Peer) CheckAndUpdateMsg1Timestamp(ts [12]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hasMsg1Timestamp && !core.CompareTimestamps(ts, p.lastMsg1Timestamp) {
		return false
	}
	p.lastMsg1Timestamp = ts
	p.hasMsg1Timestamp = true
	return true
}

// FrameBudget returns the largest wire frame size currently confirmed safe for
// this peer's outbound path (see pmtu.go). It defaults to floorPlaintext until
// probing raises it.
func (p *Peer) FrameBudget() int {
	v := p.frameBudget.Load()
	if v <= 0 {
		return floorPlaintext
	}
	return int(v)
}

// SetFrameBudget records a probe-confirmed safe frame size.
func (p *Peer) SetFrameBudget(v int) {
	p.frameBudget.Store(int32(v))
}

// tryStartProbe claims the peer's single probe slot, reporting whether the
// caller now owns it. The owner must call endProbe when done. This keeps the
// post-handshake probe and the periodic refresh from clobbering each other's
// probeCh.
func (p *Peer) tryStartProbe() bool { return p.probing.CompareAndSwap(false, true) }

// endProbe releases the probe slot claimed by tryStartProbe.
func (p *Peer) endProbe() { p.probing.Store(false) }

// lastMTUCheck / setLastMTUCheck track when maintenance last scheduled a
// periodic MTU refresh for this peer.
func (p *Peer) lastMTUCheck() time.Time     { return time.Unix(0, p.lastMTUCheckNano.Load()) }
func (p *Peer) setLastMTUCheck(t time.Time) { p.lastMTUCheckNano.Store(t.UnixNano()) }

// LastRecv reports when a valid packet was last received from this peer.
func (p *Peer) LastRecv() time.Time { return time.Unix(0, p.lastRecvNano.Load()) }

// markRecv records that a valid packet just arrived from this peer, resetting
// the silent-tunnel watchdog's clock.
func (p *Peer) markRecv(t time.Time) { p.lastRecvNano.Store(t.UnixNano()) }

// armProbe records that we're waiting for an ack of size and returns the
// channel that a matching notifyProbeAck closes.
func (p *Peer) armProbe(size int) chan struct{} {
	ch := make(chan struct{})
	p.probeMu.Lock()
	p.probeSize = size
	p.probeCh = ch
	p.probeMu.Unlock()
	return ch
}

// notifyProbeAck wakes up an in-flight probeSize call if size matches what
// it's currently waiting on.
func (p *Peer) notifyProbeAck(size int) {
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	if p.probeCh != nil && p.probeSize == size {
		close(p.probeCh)
		p.probeCh = nil
	}
}
