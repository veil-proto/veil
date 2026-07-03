package engine

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// buildFragment constructs one raw VFR1 fragment frame by hand, so tests can
// control offset/total/id precisely (makeTransportFrames always produces
// full, non-overlapping, in-order coverage — the interesting range-coverage
// cases need frames it wouldn't naturally emit).
func buildFragment(id uint32, offset, total uint16, chunk []byte) []byte {
	frame := make([]byte, fragmentHeaderLen+len(chunk))
	copy(frame[0:4], fragmentMagic[:])
	binary.LittleEndian.PutUint32(frame[4:8], id)
	binary.LittleEndian.PutUint16(frame[8:10], offset)
	binary.LittleEndian.PutUint16(frame[10:12], total)
	copy(frame[fragmentHeaderLen:], chunk)
	return frame
}

func TestFragment_RoundTripViaMakeTransportFrames(t *testing.T) {
	inner := bytes.Repeat([]byte{0x42}, 3000)
	frames := makeTransportFrames(inner, 500)
	if len(frames) < 2 {
		t.Fatalf("expected multiple fragments, got %d", len(frames))
	}

	s := &Session{}
	var got []byte
	for _, f := range frames {
		pkt, _, ok := s.handleTransportFrame(f, time.Now())
		if ok {
			got = pkt
		}
	}
	if got == nil {
		t.Fatal("reassembly never completed")
	}
	if !bytes.Equal(got, inner) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(inner))
	}
}

func TestFragment_OutOfOrderStillReassembles(t *testing.T) {
	inner := bytes.Repeat([]byte{0x7A}, 2500)
	frames := makeTransportFrames(inner, 400)
	if len(frames) < 3 {
		t.Fatalf("expected several fragments, got %d", len(frames))
	}
	// Reverse delivery order.
	for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
		frames[i], frames[j] = frames[j], frames[i]
	}

	s := &Session{}
	var got []byte
	for _, f := range frames {
		pkt, _, ok := s.handleTransportFrame(f, time.Now())
		if ok {
			got = pkt
		}
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("out-of-order reassembly did not reconstruct the original payload")
	}
}

func TestFragment_ExactDuplicateIsHarmless(t *testing.T) {
	inner := bytes.Repeat([]byte{0x11}, 900)
	frames := makeTransportFrames(inner, 300)

	s := &Session{}
	// Deliver every fragment twice; either delivery of the completing
	// fragment may be the one that observes ok==true, since the first one
	// through deletes the buffer immediately on completion.
	var got []byte
	for _, f := range frames {
		if pkt, _, ok := s.handleTransportFrame(f, time.Now()); ok {
			got = pkt
		}
		if pkt, _, ok := s.handleTransportFrame(f, time.Now()); ok {
			got = pkt
		}
	}
	if !bytes.Equal(got, inner) {
		t.Fatal("duplicate-fragment delivery corrupted reassembly")
	}
}

func TestFragment_OverlappingDifferentChunkRejected(t *testing.T) {
	const id = 0xAAAA0001
	const total = 20

	s := &Session{}

	// First chunk covers [0,10).
	f1 := buildFragment(id, 0, total, bytes.Repeat([]byte{0x01}, 10))
	if _, _, ok := s.handleTransportFrame(f1, time.Now()); ok {
		t.Fatal("should not be complete after one of two fragments")
	}

	// A second chunk covering [5,15) overlaps [0,10) without being an exact
	// duplicate of any accepted range — must be rejected, not merged.
	f2 := buildFragment(id, 5, total, bytes.Repeat([]byte{0x02}, 10))
	if _, _, ok := s.handleTransportFrame(f2, time.Now()); ok {
		t.Fatal("overlapping non-identical fragment must not be accepted")
	}

	// The legitimate second half, [10,20), must still complete reassembly
	// correctly — proving the rejected overlap didn't corrupt buffer state.
	f3 := buildFragment(id, 10, total, bytes.Repeat([]byte{0x03}, 10))
	pkt, _, ok := s.handleTransportFrame(f3, time.Now())
	if !ok {
		t.Fatal("expected reassembly to complete after the legitimate second half")
	}
	want := append(bytes.Repeat([]byte{0x01}, 10), bytes.Repeat([]byte{0x03}, 10)...)
	if !bytes.Equal(pkt, want) {
		t.Fatalf("reassembled payload corrupted by rejected overlap: got %x want %x", pkt, want)
	}
}

func TestFragment_ConcurrentBufferCapEnforced(t *testing.T) {
	s := &Session{}
	now := time.Now()

	// Open more distinct fragment IDs than the cap allows, each with an
	// incomplete first chunk so none get cleaned up by completing.
	for i := 0; i < maxConcurrentFragBuffers+10; i++ {
		f := buildFragment(uint32(i), 0, 20, bytes.Repeat([]byte{byte(i)}, 10))
		s.handleTransportFrame(f, now)
	}

	s.fragMu.Lock()
	n := len(s.frags)
	s.fragMu.Unlock()
	if n > maxConcurrentFragBuffers {
		t.Fatalf("fragment buffer count %d exceeds cap %d", n, maxConcurrentFragBuffers)
	}
}

// TestFragment_ByteCapEnforced verifies the primary limit in practice: total
// declared reassembly bytes across all in-flight buffers, not raw buffer
// count. Regression test for the bug where the old low buffer-count cap
// (64) was exhausted within seconds by a real multi-flow transfer (e.g. a
// speed test opening several parallel large downloads at once over a
// full-tunnel route), silently dropping large packets with zero visible
// symptom other than "throughput stalls" — see maxFragReassemblyBytes.
func TestFragment_ByteCapEnforced(t *testing.T) {
	s := &Session{}
	now := time.Now()

	// Each fragment set declares a near-max total (65535), so it doesn't
	// take anywhere near maxConcurrentFragBuffers distinct sets to exceed
	// maxFragReassemblyBytes — this is what actually happens under a real
	// high-throughput transfer long before the buffer-count backstop would
	// ever matter.
	const total = 65535
	opened := 0
	for i := 0; i < maxConcurrentFragBuffers; i++ {
		f := buildFragment(uint32(i), 0, total, bytes.Repeat([]byte{byte(i)}, 10))
		s.handleTransportFrame(f, now)
		s.fragMu.Lock()
		_, exists := s.frags[uint32(i)]
		s.fragMu.Unlock()
		if !exists {
			break
		}
		opened++
	}

	wantMaxOpened := maxFragReassemblyBytes/total + 1 // +1 for rounding slack
	if opened > wantMaxOpened {
		t.Fatalf("opened %d fragment sets of %d bytes each (%d total) before the byte cap kicked in; want at most ~%d", opened, total, opened*total, wantMaxOpened)
	}
	if opened == maxConcurrentFragBuffers {
		t.Fatalf("byte cap never triggered even after opening the full buffer-count cap (%d sets of %d bytes = %d bytes, want cap at %d)", opened, total, opened*total, maxFragReassemblyBytes)
	}

	s.fragMu.Lock()
	n := len(s.frags)
	s.fragMu.Unlock()
	if n != opened {
		t.Fatalf("expected exactly %d buffers to have been admitted, found %d", opened, n)
	}
}

// TestFragment_ManyConcurrentFlowsSucceedWithinByteCap verifies a burst of
// many concurrent large-packet flows — the exact real-world pattern a speed
// test's parallel connections produce over a full-tunnel route — all
// reassemble successfully as long as they stay within maxFragReassemblyBytes,
// which is sized with generous headroom for exactly this case (regression
// guard for the old 64-buffer-count cap that this scenario blew through
// almost immediately).
func TestFragment_ManyConcurrentFlowsSucceedWithinByteCap(t *testing.T) {
	s := &Session{}
	now := time.Now()

	const flows = 200 // far more than the old 64-buffer-count cap
	const chunkSize = 500
	const total = 4 * chunkSize // 2000 bytes per flow, well within the byte cap even at 200 flows (400000 bytes)

	// Interleave: send chunk 0 of every flow, then chunk 1 of every flow,
	// etc., so all 200 fragment sets are genuinely concurrent (open at once)
	// rather than completing one at a time.
	payload := bytes.Repeat([]byte{0xAB}, chunkSize)
	for chunkIdx := 0; chunkIdx < total/chunkSize; chunkIdx++ {
		for flow := 0; flow < flows; flow++ {
			offset := uint16(chunkIdx * chunkSize)
			f := buildFragment(uint32(flow), offset, total, payload)
			if _, _, ok := s.handleTransportFrame(f, now); ok && chunkIdx != total/chunkSize-1 {
				t.Fatalf("flow %d completed early after chunk %d", flow, chunkIdx)
			}
		}
	}

	s.fragMu.Lock()
	remaining := len(s.frags)
	s.fragMu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected all %d concurrent flows to complete and be cleared, %d still buffered (dropped by the cap)", flows, remaining)
	}
}
