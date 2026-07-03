package engine

// Path MTU discovery for the data plane.
//
// The wire budget (maxOuterPayload/maxTransportPlaintext, fragment.go) assumes
// a full 1500-byte link end to end. Plenty of real paths are smaller (PPPoE,
// mobile links, corporate/cloud overlay networks, VPN-over-VPN, ...) and, worse,
// commonly black-hole rather than reply with ICMP "fragmentation needed": an
// oversized encapsulated packet is silently dropped with no signal at all. TCP
// data segments built to the old fixed ceiling then vanish wholesale, and the
// only recovery is repeated RTO doubling — which is exactly the collapse to a
// few Mbit/s this file exists to fix.
//
// Each peer starts at floorPlaintext, a size assumed safe on every real-world
// path (comfortably under the IPv6-mandated 1280-byte minimum link MTU once
// transport/UDP/IP overhead is subtracted), so no traffic is ever put at risk
// of the black hole. Right after a session is established, probeMTU walks a
// descending ladder of candidate sizes, sending each as an authenticated
// transport frame and waiting for the peer to echo it back; the first size
// that round-trips becomes the peer's confirmed FrameBudget. Because probing
// re-runs on every rekey but skips anything at or below the size already
// confirmed, it both converges fast on a fresh peer and keeps re-checking
// upward in case the path improves, at negligible steady-state cost.

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/veil-proto/veil/transport"
)

var (
	probeMagic    = [4]byte{'V', 'P', 'R', '1'}
	probeAckMagic = [4]byte{'V', 'P', 'A', '1'}
)

const (
	// floorPlaintext is the frame size every peer starts at and that never
	// needs probing: 1218 inner bytes encapsulate to a 1280-byte outer IP
	// packet (1218 + transportOverhead(34) + UDP(8) + IPv4(20) = 1280), the
	// smallest MTU every IPv6-capable link (and effectively every IPv4 one)
	// is guaranteed to carry.
	floorPlaintext = 1218

	probeTimeout = 250 * time.Millisecond
	probeRetries = 2

	// pmtuRefreshInterval is how often maintenance re-checks a peer's path MTU
	// mid-session. A path can change under a live session (WiFi roaming, mobile
	// handover, route flap); without this the budget would only ever be
	// re-evaluated at rekey (~30 min), long enough for a shrunken path to black
	// hole every full-size frame in between.
	pmtuRefreshInterval = 2 * time.Minute
)

// probeLadder lists candidate frame sizes to try, largest first. Entries at or
// below floorPlaintext are pointless (already assumed to work) and omitted.
var probeLadder = []int{maxTransportPlaintext, 1358, 1298, 1258}

// launchMTUUpdate runs updateMTU in the background under the peer's single
// probe slot, dropping the request if a probe is already in flight (the shared
// probeCh only supports one probe at a time). Used both right after a handshake
// and from the periodic maintenance refresh.
func (e *Engine) launchMTUUpdate(peer *Peer) {
	go func() {
		if !peer.tryStartProbe() {
			return
		}
		defer peer.endProbe()
		e.updateMTU(peer)
	}()
}

// updateMTU reconciles a peer's FrameBudget with what its current path actually
// carries, in three steps:
//
//  1. Grow: probe candidates larger than the current budget, largest first; the
//     first that round-trips becomes the new budget. On a fresh peer (budget at
//     floorPlaintext) this is the whole job and converges the same way the
//     original post-handshake probe did.
//  2. Verify: if nothing larger works, confirm the current budget still
//     survives the path. Unchanged paths pass here for near-zero cost.
//  3. Shrink: if the current budget no longer round-trips (the path degraded
//     mid-session), walk the ladder down to the largest size that still works,
//     falling back to floorPlaintext, which is assumed safe everywhere.
func (e *Engine) updateMTU(peer *Peer) {
	if peer.SendSession() == nil || peer.Endpoint() == nil {
		return
	}
	cur := peer.FrameBudget()

	// 1) Grow.
	for _, size := range probeLadder {
		if size <= cur {
			continue
		}
		if e.probeSize(peer, size) {
			peer.SetFrameBudget(size)
			return
		}
	}

	// 2) Verify the current budget (floor is assumed always safe, never probed).
	if cur <= floorPlaintext {
		return
	}
	if e.probeSize(peer, cur) {
		return
	}

	// 3) Shrink: the path got smaller. Find the largest candidate below cur that
	//    still round-trips, or drop to the floor.
	for _, size := range probeLadder {
		if size >= cur {
			continue
		}
		if e.probeSize(peer, size) {
			peer.SetFrameBudget(size)
			return
		}
	}
	peer.SetFrameBudget(floorPlaintext)
}

// probeSize sends a single candidate frame size to peer and reports whether it
// was echoed back within the retry budget.
func (e *Engine) probeSize(peer *Peer, size int) bool {
	sess := peer.SendSession()
	ep, localIP := peer.Path()
	if sess == nil || ep == nil {
		return false
	}

	inner := make([]byte, size)
	copy(inner[:4], probeMagic[:])
	binary.LittleEndian.PutUint16(inner[4:6], uint16(size))

	for attempt := 0; attempt <= probeRetries; attempt++ {
		ch := peer.armProbe(size)
		enc, err := transport.EncapsulateTransport(sess.keys, sess.nextPN(), inner, 0, 16)
		if err != nil {
			return false
		}
		if _, err := e.conn.writeTo(enc, ep, localIP); err != nil {
			return false
		}
		select {
		case <-ch:
			return true
		case <-time.After(probeTimeout):
		}
	}
	return false
}

// handleMTUProbe answers a peer's size probe by echoing the size back over the
// same session, proving a frame of exactly that size crossed the path intact.
func (e *Engine) handleMTUProbe(payload []byte, sess *Session, remote *net.UDPAddr, localIP net.IP) {
	if len(payload) < 6 {
		return
	}
	size := binary.LittleEndian.Uint16(payload[4:6])
	var ack [6]byte
	copy(ack[:4], probeAckMagic[:])
	binary.LittleEndian.PutUint16(ack[4:6], size)

	enc, err := transport.EncapsulateTransport(sess.keys, sess.nextPN(), ack[:], 0, 16)
	if err != nil {
		return
	}
	if _, err := e.conn.writeTo(enc, remote, localIP); err != nil {
		log.Printf("MTU probe ack send error: %v", err)
	}
}

// handleMTUProbeAck wakes up a matching in-flight probeSize call.
func handleMTUProbeAck(payload []byte, peer *Peer) {
	if len(payload) < 6 {
		return
	}
	size := int(binary.LittleEndian.Uint16(payload[4:6]))
	peer.notifyProbeAck(size)
}
