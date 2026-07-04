package recordv1

import (
	"testing"
	"time"
)

// TestReplayWindowCommitLargeJumpIsO1 is a regression guard for P1.3
// (VEIL-Combined-Roadmap.md): Commit used to clear its bitmap word-by-bit in
// a loop bounded by the sequence delta (`for i := maxSeen+1; i <= seq; i++`),
// so an authenticated packet (route-token lookup + AEAD already verified)
// carrying a huge sequence number could pin the receiver in a
// multi-second/near-unbounded loop. Commit's cost must depend only on the
// fixed bitmap width, not on the attacker-chosen sequence value.
func TestReplayWindowCommitLargeJumpIsO1(t *testing.T) {
	rw := NewReplayWindow()

	if !rw.Commit(10) {
		t.Fatal("accept 10")
	}

	start := time.Now()
	if !rw.Commit(^uint64(0) - 1) {
		t.Fatal("accept huge forward jump")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Commit with a huge sequence jump took %v, want O(1)", elapsed)
	}

	// The window has slid all the way to the new maxSeen; the old sequence
	// number is now unconditionally too old.
	if rw.Commit(10) {
		t.Fatal("old sequence number must be rejected as too-old after the jump")
	}
}
