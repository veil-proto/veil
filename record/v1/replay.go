package recordv1

import "sync"

const replayBits = 8192

type ReplayWindow struct {
	mu      sync.Mutex
	replay  []uint64
	maxSeen uint64
	started bool
}

func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{replay: make([]uint64, replayBits/64)}
}

func (rw *ReplayWindow) PreCheck(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return !rw.isReplay(seq)
}

// Commit marks seq as seen. Cost is bounded by len(rw.replay) (a fixed 128
// words), never by seq itself: the previous version cleared the bitmap in a
// loop bounded by the sequence delta (`for i := maxSeen+1; i <= seq; i++`),
// so an authenticated packet (route-token lookup + AEAD already verified)
// carrying an attacker-chosen huge sequence number — e.g. seq near
// math.MaxUint64 — could pin the receiver in a near-unbounded loop (P1.3,
// VEIL-Combined-Roadmap.md).
func (rw *ReplayWindow) Commit(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.isReplay(seq) {
		return false
	}
	if !rw.started || seq > rw.maxSeen {
		firstCommit := !rw.started
		rw.started = true
		wordDelta := (seq / 64) - (rw.maxSeen / 64)
		if firstCommit || wordDelta >= uint64(len(rw.replay)) {
			for i := range rw.replay {
				rw.replay[i] = 0
			}
		} else {
			word := (rw.maxSeen / 64) % uint64(len(rw.replay))
			for i := uint64(0); i < wordDelta; i++ {
				word = (word + 1) % uint64(len(rw.replay))
				rw.replay[word] = 0
			}
		}
		rw.maxSeen = seq
	}
	idx := (seq / 64) % uint64(len(rw.replay))
	rw.replay[idx] |= uint64(1) << (seq % 64)
	return true
}

func (rw *ReplayWindow) isReplay(seq uint64) bool {
	if !rw.started {
		return false
	}
	if seq > rw.maxSeen {
		return false
	}
	if rw.maxSeen-seq >= replayBits {
		return true
	}
	idx := (seq / 64) % uint64(len(rw.replay))
	bit := uint64(1) << (seq % 64)
	return rw.replay[idx]&bit != 0
}
