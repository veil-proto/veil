package engine

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"time"
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

	// maxConcurrentFragBuffers bounds how many distinct in-flight fragment
	// sets one session will reassemble at once, so a burst of packets with
	// many different (random) fragment IDs can't grow s.frags unboundedly
	// between TTL sweeps. Each buffer is at most 65535 bytes (total is
	// capped at a uint16), so this bounds worst-case reassembly memory to
	// roughly maxConcurrentFragBuffers*64KiB per session.
	maxConcurrentFragBuffers = 64
)

var fragmentMagic = [4]byte{'V', 'F', 'R', '1'}

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
		if buf == nil && len(s.frags) >= maxConcurrentFragBuffers {
			// Too many distinct in-flight fragment sets already; drop this
			// fragment rather than let reassembly memory grow unboundedly.
			return nil, nil, false
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
