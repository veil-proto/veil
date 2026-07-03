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

func (rw *ReplayWindow) Commit(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if rw.isReplay(seq) {
		return false
	}
	if !rw.started || seq > rw.maxSeen {
		if !rw.started {
			rw.started = true
		}
		for i := rw.maxSeen + 1; i <= seq; i++ {
			idx := (i / 64) % uint64(len(rw.replay))
			if i%64 == 0 {
				rw.replay[idx] = 0
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
