package engine

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"time"

	"github.com/veil-proto/veil/internal/ratelog"
)

const (
	// maxOuterPayload sizes the encrypted UDP payload so a full frame plus
	// UDP/IP headers exactly fills a 1500-byte link even over IPv6:
	// 1452 + 8 (UDP) + 40 (IPv6) = 1500 (IPv4 leaves 20 bytes spare).
	// This mirrors WireGuard's tunnel-MTU math with VEIL's 34-byte overhead;
	// the wire-format spec constrains only handshake bucket padding, not
	// data-plane length.
	maxOuterPayload       = 1452
	transportOverhead     = 34 // tag(16) + Poly1305(16) + pad_len(2)
	fragmentHeaderLen     = 12
	maxTransportPlaintext = maxOuterPayload - transportOverhead // 1418 = ceiling a peer's frame budget can probe up to
	fragmentTTL           = 30 * time.Second

	// maxConcurrentFragBuffers is a backstop against a degenerate
	// many-tiny-buffers case (lots of distinct fragment IDs each holding
	// very little data). maxFragReassemblyBytes below is the primary limit
	// in practice — a real high-throughput transfer (e.g. saturating a link
	// during a speed test, over a full-tunnel 0.0.0.0/0 route) can easily
	// have dozens of large packets fragmenting concurrently, one fragment
	// set per oversized TUN read; this count exists only to bound memory
	// under a flood of many *small* fragment sets, not to limit legitimate
	// concurrency, so it's set high enough to not matter in the common case.
	maxConcurrentFragBuffers = 4096

	// maxFragReassemblyBytes bounds total in-flight reassembly memory per
	// session across every concurrent fragment buffer (sum of each buffer's
	// declared total). This is the limit that actually matters for
	// legitimate traffic: it's sized to comfortably cover many concurrent
	// large-packet reassemblies during a sustained high-throughput transfer,
	// while still bounding worst-case memory from a hostile flood of
	// many/large declared totals that never complete.
	maxFragReassemblyBytes = 64 << 20 // 64 MiB
)

var fragmentMagic = [4]byte{'V', 'F', 'R', '1'}

// fragCapLog rate-limits the "fragment reassembly cap reached" log line —
// see ratelog's package doc for why any packet-triggered log line needs
// this (an attacker, or just a saturated link, can otherwise generate this
// line as fast as packets arrive).
var fragCapLog = ratelog.NewLimiter(5 * time.Second)

// fragRange is a half-open byte range [start,end) covered by one received
// fragment chunk.
type fragRange struct {
	start, end uint16
}

type fragmentBuffer struct {
	total   int
	ranges  []fragRange // sorted, non-overlapping; see insertRange
	data    []byte
	created time.Time
}

// insertRange attempts to add [start,end) to the buffer's coverage. It
// returns false, leaving ranges unchanged, if [start,end) overlaps an
// existing range without being an exact duplicate of it (spec 14.2: reject
// overlapping fragments rather than letting one silently last-write-win over
// another). An exact duplicate — the same range received twice, e.g. a
// retransmit — is accepted as a no-op.
func (buf *fragmentBuffer) insertRange(start, end uint16) bool {
	for _, r := range buf.ranges {
		if start == r.start && end == r.end {
			return true
		}
		if start < r.end && r.start < end {
			return false
		}
	}
	buf.ranges = append(buf.ranges, fragRange{start, end})
	sort.Slice(buf.ranges, func(i, j int) bool { return buf.ranges[i].start < buf.ranges[j].start })
	return true
}

// covered reports whether the accumulated ranges fully cover [0,total) with
// no gaps — true range-coverage completion, not a byte-count heuristic (a
// byte count can be satisfied by overlapping/duplicate chunks that still
// leave a gap elsewhere).
func (buf *fragmentBuffer) covered() bool {
	if len(buf.ranges) == 0 || buf.ranges[0].start != 0 {
		return false
	}
	end := buf.ranges[0].end
	for _, r := range buf.ranges[1:] {
		if r.start > end {
			return false
		}
		if r.end > end {
			end = r.end
		}
	}
	return end >= uint16(buf.total)
}

// makeTransportFrames splits inner into wire frames no larger than budget, the
// peer's currently-confirmed-safe frame size (see pmtu.go). Using a per-peer
// budget instead of a fixed constant keeps fragmentation itself safe on paths
// with a smaller MTU than the ceiling: fragments only ever land at a size that
// probing already proved gets through, so bulk data doesn't get stuck behind
// oversized fragments regardless of the fragmentation reassembly all-or-nothing
// (VFR1) contract.
func makeTransportFrames(inner []byte, budget int) [][]byte {
	if len(inner) == 0 || len(inner) <= budget {
		return [][]byte{inner}
	}

	var idBuf [4]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		binary.LittleEndian.PutUint32(idBuf[:], uint32(time.Now().UnixNano()))
	}

	maxFragmentData := budget - fragmentHeaderLen
	frames := make([][]byte, 0, (len(inner)+maxFragmentData-1)/maxFragmentData)
	for offset := 0; offset < len(inner); offset += maxFragmentData {
		end := offset + maxFragmentData
		if end > len(inner) {
			end = len(inner)
		}

		frame := make([]byte, fragmentHeaderLen+end-offset)
		copy(frame[0:4], fragmentMagic[:])
		copy(frame[4:8], idBuf[:])
		binary.LittleEndian.PutUint16(frame[8:10], uint16(offset))
		binary.LittleEndian.PutUint16(frame[10:12], uint16(len(inner)))
		copy(frame[fragmentHeaderLen:], inner[offset:end])
		frames = append(frames, frame)
	}
	return frames
}

// fragReassemblyBytes sums the declared total size of every in-flight
// fragment buffer, i.e. the reassembly memory currently committed for this
// session. Called only when opening a *new* fragment set (not per fragment
// chunk), so its O(n) cost is bounded by how many distinct concurrent
// fragment sets exist, not by total fragment volume.
func fragReassemblyBytes(frags map[uint32]*fragmentBuffer) int {
	total := 0
	for _, b := range frags {
		total += b.total
	}
	return total
}

// handleTransportFrame consumes one decrypted transport frame. For a complete
// packet it returns (pkt, full, true): pkt is the inner IP packet, and full is
// non-nil only for reassembled fragments, in which case it is a buffer holding
// pkt at offset tunWriteOffset so the caller can hand it to a batched TUN write
// without another copy. For keepalives and incomplete fragments ok is false.
func (s *Session) handleTransportFrame(frame []byte, now time.Time) (pkt, full []byte, ok bool) {
	if len(frame) == 0 {
		return nil, nil, false
	}
	if len(frame) < fragmentHeaderLen || string(frame[0:4]) != string(fragmentMagic[:]) {
		return frame, nil, true
	}

	id := binary.LittleEndian.Uint32(frame[4:8])
	offset := binary.LittleEndian.Uint16(frame[8:10])
	total := int(binary.LittleEndian.Uint16(frame[10:12]))
	chunk := frame[fragmentHeaderLen:]
	if total <= 0 || total > 65535 || len(chunk) == 0 || int(offset)+len(chunk) > total {
		return nil, nil, false
	}

	s.fragMu.Lock()
	defer s.fragMu.Unlock()
	if s.frags == nil {
		s.frags = make(map[uint32]*fragmentBuffer)
	}
	for key, buf := range s.frags {
		if now.Sub(buf.created) > fragmentTTL {
			delete(s.frags, key)
		}
	}

	buf := s.frags[id]
	if buf == nil || buf.total != total {
		if buf == nil {
			if n := len(s.frags); n >= maxConcurrentFragBuffers {
				fragCapLog.Printf("fragment reassembly buffer count cap reached (%d), dropping new fragment set", n)
				return nil, nil, false
			}
			if inFlight := fragReassemblyBytes(s.frags); inFlight+total > maxFragReassemblyBytes {
				fragCapLog.Printf("fragment reassembly byte cap reached (%d+%d > %d), dropping new fragment set", inFlight, total, maxFragReassemblyBytes)
				return nil, nil, false
			}
		}
		buf = &fragmentBuffer{
			total: total,
			// tunWriteOffset headroom lets the reassembled packet go straight
			// into a batched TUN write alongside unfragmented packets.
			data:    make([]byte, tunWriteOffset+total),
			created: now,
		}
		s.frags[id] = buf
	}

	end := int(offset) + len(chunk)
	if !buf.insertRange(offset, uint16(end)) {
		// Overlaps a previously-accepted, non-identical range: reject this
		// fragment instead of letting it silently corrupt the reassembly.
		return nil, nil, false
	}
	copy(buf.data[tunWriteOffset+int(offset):], chunk)
	if !buf.covered() {
		return nil, nil, false
	}

	delete(s.frags, id)
	return buf.data[tunWriteOffset:], buf.data, true
}
