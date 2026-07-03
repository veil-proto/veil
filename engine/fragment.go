package engine

import (
	"crypto/rand"
	"encoding/binary"
	"sort"
	"time"

	"github.com/veil-proto/veil/internal/ratelog"
	recordv1 "github.com/veil-proto/veil/record/v1"
)

const (
	// maxOuterPayload sizes the encrypted UDP payload so a full frame plus
	// UDP/IP headers exactly fills a 1500-byte link even over IPv6:
	// 1452 + 8 (UDP) + 40 (IPv6) = 1500 (IPv4 leaves 20 bytes spare).
	maxOuterPayload = 1452

	recordOverhead        = 40 // route_token(16) + seq_protected(8) + Poly1305(16)
	frameOverhead         = 6  // frame_type/flags/body_len(4) + pad_len(2)
	fragmentHeaderLen     = 17 // frag_id(8) + frag_offset(4) + total_len(4) + flags(1)
	maxTransportPlaintext = maxOuterPayload - recordOverhead
	fragmentTTL           = 30 * time.Second

	// maxConcurrentFragBuffers is a backstop against a degenerate
	// many-tiny-buffers case (lots of distinct fragment IDs each holding
	// very little data). maxFragReassemblyBytes below is the primary limit
	// in practice.
	maxConcurrentFragBuffers = 4096

	// maxFragReassemblyBytes bounds total in-flight reassembly memory per
	// session across every concurrent fragment buffer (sum of each buffer's
	// declared total).
	maxFragReassemblyBytes = 64 << 20 // 64 MiB
)

// fragCapLog rate-limits the "fragment reassembly cap reached" log line.
var fragCapLog = ratelog.NewLimiter(5 * time.Second)

// fragRange is a half-open byte range [start,end) covered by one received
// fragment chunk.
type fragRange struct {
	start, end uint32
}

type fragmentBuffer struct {
	total   int
	ranges  []fragRange // sorted, non-overlapping; see insertRange
	data    []byte
	created time.Time
}

// insertRange attempts to add [start,end) to the buffer's coverage. It
// returns false, leaving ranges unchanged, if [start,end) overlaps an
// existing range without being an exact duplicate of it.
func (buf *fragmentBuffer) insertRange(start, end uint32) bool {
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
// no gaps.
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
	return end >= uint32(buf.total)
}

// makeTransportFrames wraps an inner IP packet into VEIL-RECORD-1 inner frames
// no larger than budget. Oversized packets use INNER_FRAGMENT frames with the
// target v1 fragment body grammar.
func makeTransportFrames(inner []byte, budget int) [][]byte {
	minFragmentBudget := frameOverhead + fragmentHeaderLen + 1
	if budget < minFragmentBudget {
		budget = minFragmentBudget
	}
	if len(inner) == 0 {
		return [][]byte{mustMarshalFrame(recordv1.Frame{Type: recordv1.FramePadOnly})}
	}
	if len(inner)+frameOverhead <= budget {
		return [][]byte{mustMarshalDataFrame(inner)}
	}

	var idBuf [8]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		binary.BigEndian.PutUint64(idBuf[:], uint64(time.Now().UnixNano()))
	}

	maxFragmentData := budget - frameOverhead - fragmentHeaderLen
	frames := make([][]byte, 0, (len(inner)+maxFragmentData-1)/maxFragmentData)
	for offset := 0; offset < len(inner); offset += maxFragmentData {
		end := offset + maxFragmentData
		if end > len(inner) {
			end = len(inner)
		}

		body := make([]byte, fragmentHeaderLen+end-offset)
		copy(body[0:8], idBuf[:])
		binary.BigEndian.PutUint32(body[8:12], uint32(offset))
		binary.BigEndian.PutUint32(body[12:16], uint32(len(inner)))
		body[16] = 0
		copy(body[fragmentHeaderLen:], inner[offset:end])
		frames = append(frames, mustMarshalFrame(recordv1.Frame{Type: recordv1.FrameInnerFragment, Body: body}))
	}
	return frames
}

func mustMarshalDataFrame(inner []byte) []byte {
	ft := recordv1.FrameDataIP4
	if len(inner) > 0 && inner[0]>>4 == 6 {
		ft = recordv1.FrameDataIP6
	}
	return mustMarshalFrame(recordv1.Frame{Type: ft, Body: inner})
}

func mustMarshalFrame(f recordv1.Frame) []byte {
	wire, err := recordv1.MarshalFrame(f)
	if err != nil {
		panic(err)
	}
	return wire
}

func marshalFrameWithPadding(frame []byte, padLen uint16) []byte {
	if padLen == 0 {
		return frame
	}
	out := make([]byte, len(frame)+int(padLen))
	copy(out, frame[:len(frame)-2])
	binary.BigEndian.PutUint16(out[len(out)-2:], padLen)
	return out
}

// fragReassemblyBytes sums the declared total size of every in-flight
// fragment buffer.
func fragReassemblyBytes(frags map[uint32]*fragmentBuffer) int {
	total := 0
	for _, b := range frags {
		total += b.total
	}
	return total
}

// handleTransportFrame consumes one decrypted VEIL-RECORD-1 inner frame. For a
// complete user packet it returns (pkt, full, true). For keepalives, controls,
// malformed frames, and incomplete fragments, ok is false.
func (s *Session) handleTransportFrame(frame []byte, now time.Time) (pkt, full []byte, ok bool) {
	r := s.handleRecordFrame(frame, now)
	if !r.ok || (r.typ != recordv1.FrameDataIP4 && r.typ != recordv1.FrameDataIP6) {
		return nil, nil, false
	}
	return r.payload, r.full, true
}

type recordFrameResult struct {
	typ     recordv1.FrameType
	payload []byte
	full    []byte
	ok      bool
}

func (s *Session) handleRecordFrame(plaintext []byte, now time.Time) recordFrameResult {
	frame, err := recordv1.ParseFrame(plaintext)
	if err != nil {
		return recordFrameResult{}
	}
	switch frame.Type {
	case recordv1.FramePadOnly:
		return recordFrameResult{}
	case recordv1.FrameDataIP4, recordv1.FrameDataIP6, recordv1.FrameControl:
		return recordFrameResult{typ: frame.Type, payload: frame.Body, ok: true}
	case recordv1.FrameInnerFragment:
		pkt, full, ok := s.handleInnerFragment(frame.Body, now)
		if !ok {
			return recordFrameResult{}
		}
		ft := recordv1.FrameDataIP4
		if len(pkt) > 0 && pkt[0]>>4 == 6 {
			ft = recordv1.FrameDataIP6
		}
		return recordFrameResult{typ: ft, payload: pkt, full: full, ok: true}
	default:
		return recordFrameResult{}
	}
}

func (s *Session) handleInnerFragment(body []byte, now time.Time) (pkt, full []byte, ok bool) {
	if len(body) < fragmentHeaderLen {
		return nil, nil, false
	}
	id64 := binary.BigEndian.Uint64(body[0:8])
	id := uint32(id64 ^ (id64 >> 32))
	offset := binary.BigEndian.Uint32(body[8:12])
	total := int(binary.BigEndian.Uint32(body[12:16]))
	chunk := body[fragmentHeaderLen:]
	if total <= 0 || total > 65535 || len(chunk) == 0 || uint64(offset)+uint64(len(chunk)) > uint64(total) {
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
			total:   total,
			data:    make([]byte, tunWriteOffset+total),
			created: now,
		}
		s.frags[id] = buf
	}

	end := int(offset) + len(chunk)
	if !buf.insertRange(offset, uint32(end)) {
		return nil, nil, false
	}
	copy(buf.data[tunWriteOffset+int(offset):], chunk)
	if !buf.covered() {
		return nil, nil, false
	}

	delete(s.frags, id)
	return buf.data[tunWriteOffset:], buf.data, true
}
