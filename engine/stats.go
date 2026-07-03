package engine

import "time"

// PeerStats is a point-in-time snapshot of one peer's state, the VEIL equivalent
// of a `wg show` peer block. It is a plain value (no live pointers) so it can be
// serialized straight onto the control channel.
type PeerStats struct {
	PublicKey     string    // hex
	Endpoint      string    // current remote endpoint, or "" if none yet
	Connected     bool      // a confirmed session exists and traffic is recent
	LastHandshake time.Time // when the current session was established (zero if none)
	LastReceived  time.Time // last valid inbound packet (zero if none)
	RxBytes       uint64    // inner bytes received
	TxBytes       uint64    // inner bytes sent
	RxPackets     uint64
	TxPackets     uint64
	FrameBudget   int // current probed frame budget (pmtu.go)
}

// Stats returns a snapshot of every peer's counters and session state. Safe to
// call concurrently with the data plane; every field is read via the peer's own
// synchronization (atomics / RWMutex).
func (e *Engine) Stats() []PeerStats {
	now := time.Now()
	peers := e.peerTable.GetAllPeers()
	out := make([]PeerStats, 0, len(peers))
	for _, p := range peers {
		s := PeerStats{
			PublicKey:    hexKey(p.PublicKey),
			LastReceived: p.LastRecv(),
			RxBytes:      p.rxBytes.Load(),
			TxBytes:      p.txBytes.Load(),
			RxPackets:    p.rxPackets.Load(),
			TxPackets:    p.txPackets.Load(),
			FrameBudget:  p.FrameBudget(),
		}
		if ep := p.Endpoint(); ep != nil {
			s.Endpoint = ep.String()
		}
		if cur := p.Current(); cur != nil {
			s.LastHandshake = cur.establishedAt
			// Connected: the session is confirmed and we've heard from the peer
			// within the silent-tunnel watchdog window.
			s.Connected = cur.isConfirmed() && !tunnelSilent(cur, p.LastRecv(), now)
		}
		out = append(out, s)
	}
	return out
}

func hexKey(k []byte) string {
	const hexdigits = "0123456789abcdef"
	b := make([]byte, len(k)*2)
	for i, c := range k {
		b[i*2] = hexdigits[c>>4]
		b[i*2+1] = hexdigits[c&0x0f]
	}
	return string(b)
}
