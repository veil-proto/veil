package engine

import (
	"crypto/rand"
	"encoding/binary"
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
)

var fragmentMagic = [4]byte{'V', 'F', 'R', '1'}

type fragmentBuffer struct {
	total    int
	seen     map[uint16]uint16
	received int
	data     []byte
	created  time.Time
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
		buf = &fragmentBuffer{
			total: total,
			seen:  make(map[uint16]uint16),
			// tunWriteOffset headroom lets the reassembled packet go straight
			// into a batched TUN write alongside unfragmented packets.
			data:    make([]byte, tunWriteOffset+total),
			created: now,
		}
		s.frags[id] = buf
	}

	if _, dup := buf.seen[offset]; !dup {
		copy(buf.data[tunWriteOffset+int(offset):], chunk)
		buf.seen[offset] = uint16(len(chunk))
		buf.received += len(chunk)
	}
	if buf.received < buf.total {
		return nil, nil, false
	}

	delete(s.frags, id)
	return buf.data[tunWriteOffset:], buf.data, true
}
