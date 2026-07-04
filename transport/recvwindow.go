package transport

import (
	"sync"
)

// RecvWindow manages the sliding set of precomputed receive tags for one peer
// session, plus an anti-replay bitmap. It replaces the old "precompute a fixed
// 2048 tags once" scheme, under which a session went dark after ~2048 packets
// (~2.4 MB at 1200 MTU) because no further tags were ever installed.
//
// Invariant: the global TagTable always holds tags for packet numbers in
// [lo, hi) for this session. As packets arrive, the window slides forward:
// future tags are installed ahead of maxSeen and stale tags behind it are
// evicted, so the table size stays bounded regardless of session length.
const (
	tagWindowFuture = 2048 // tags kept ahead of the highest seen packet number
	tagWindowPast   = 1024 // tags kept behind it, to tolerate reordering
	tagSlideBatch   = 512  // install/evict tags in batches to keep the packet path smooth
	replayBits      = 8192 // anti-replay bitmap width, per spec
)

type RecvWindow struct {
	mu         sync.Mutex
	peerCtx    interface{}
	sessionCtx interface{}
	keys       *TransportKeys
	table      *TagTable

	lo        uint64 // lowest packet number currently installed
	hi        uint64 // one past the highest packet number currently installed
	installed map[uint64]tagKey

	// Anti-replay (RFC 6479-style sliding bitmap).
	replay  []uint64
	maxSeen uint64
	started bool
}

func NewRecvWindow(peerCtx interface{}, sessionCtx interface{}, keys *TransportKeys, table *TagTable) *RecvWindow {
	rw := &RecvWindow{
		peerCtx:    peerCtx,
		sessionCtx: sessionCtx,
		keys:       keys,
		table:      table,
		installed:  make(map[uint64]tagKey),
		replay:     make([]uint64, replayBits/64),
	}
	// Prime the window with [0, tagWindowFuture).
	rw.install(0, tagWindowFuture)
	return rw
}

// install adds tags for [from, to) to the global table and tracks them.
// Caller holds rw.mu (or is the constructor before publication).
func (rw *RecvWindow) install(from, to uint64) {
	for n := from; n < to; n++ {
		if _, ok := rw.installed[n]; ok {
			continue
		}
		var tagFull [32]byte
		tag := deriveTagInto(tagFull[:0], rw.keys.KTagRecv, n, rw.keys.SessionContext)[:16]
		key, ok := makeTagKey(tag)
		if !ok {
			continue
		}
		rw.table.AddTag(tag, rw.peerCtx, rw.sessionCtx, n)
		rw.installed[n] = key
	}
	if to > rw.hi {
		rw.hi = to
	}
}

// Teardown removes all of this window's tags from the shared table. Called when
// a previous (post-rekey) session ages out.
func (rw *RecvWindow) Teardown() {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	for _, key := range rw.installed {
		rw.table.removeKey(key)
	}
	rw.installed = make(map[uint64]tagKey)
}

// evict removes tags for [from, to) from the global table.
func (rw *RecvWindow) evict(from, to uint64) {
	for n := from; n < to; n++ {
		if key, ok := rw.installed[n]; ok {
			rw.table.removeKey(key)
			delete(rw.installed, n)
		}
	}
	if from <= rw.lo && to > rw.lo {
		rw.lo = to
	}
}

// isReplay reports whether packet number n is a replay or too old to accept.
// It does not modify state.
func (rw *RecvWindow) isReplay(n uint64) bool {
	if !rw.started {
		return false
	}
	if n > rw.maxSeen {
		return false
	}
	if rw.maxSeen-n >= replayBits {
		return true // outside the bitmap: treat as replay/too-old
	}
	idx := (n / 64) % uint64(len(rw.replay))
	bit := uint64(1) << (n % 64)
	return rw.replay[idx]&bit != 0
}

// commit marks n as seen and slides the tag window forward around it. Call only
// after the packet's AEAD has verified. Returns false if n was a replay.
func (rw *RecvWindow) Commit(n uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.isReplay(n) {
		return false
	}

	// Advance the replay bitmap, clearing bits for the newly-exposed range.
	// Must be O(len(rw.replay)) (a fixed 128 words), never O(n-maxSeen): an
	// authenticated packet (mac1/AEAD already passed) with an attacker-chosen
	// huge sequence number, e.g. n = maxUint64-1, would otherwise spin a loop
	// proportional to that attacker-controlled delta instead of the bitmap's
	// fixed width.
	if !rw.started || n > rw.maxSeen {
		firstCommit := !rw.started
		rw.started = true
		wordDelta := (n / 64) - (rw.maxSeen / 64)
		if firstCommit || wordDelta >= uint64(len(rw.replay)) {
			for i := range rw.replay {
				rw.replay[i] = 0
			}
		} else {
			// Clear only the words newly exposed by sliding the window forward,
			// at most len(rw.replay) iterations regardless of how large the
			// underlying sequence jump is.
			word := (rw.maxSeen / 64) % uint64(len(rw.replay))
			for i := uint64(0); i < wordDelta; i++ {
				word = (word + 1) % uint64(len(rw.replay))
				rw.replay[word] = 0
			}
		}
		rw.maxSeen = n
	}
	idx := (n / 64) % uint64(len(rw.replay))
	rw.replay[idx] |= uint64(1) << (n % 64)

	// Slide the tag window in batches. Installing one future tag for every
	// accepted packet puts keyed hash work and global table writes directly in
	// the receive hot path; batched refill keeps most packets to replay bitmap
	// work only.
	desiredHi := rw.maxSeen + tagWindowFuture
	var desiredLo uint64
	if rw.maxSeen > tagWindowPast {
		desiredLo = rw.maxSeen - tagWindowPast
	}
	if desiredLo >= rw.hi {
		// The entire previously-installed window is now stale: a forward jump
		// moved maxSeen past it completely. install(rw.hi, desiredHi) here
		// would derive one BLAKE2s tag per packet number across the whole
		// jump distance — attacker-controlled and unbounded (same O(delta)
		// class of bug as the replay bitmap above, just in the tag table
		// instead). Discard the stale window and reinstall a fresh one, which
		// costs at most tagWindowFuture+tagWindowPast tag derivations
		// regardless of how large the jump was.
		for _, key := range rw.installed {
			rw.table.removeKey(key)
		}
		rw.installed = make(map[uint64]tagKey)
		rw.lo = desiredLo
		rw.hi = desiredLo
		rw.install(desiredLo, desiredHi)
	} else {
		if rw.hi <= rw.maxSeen+tagWindowFuture-tagSlideBatch {
			rw.install(rw.hi, desiredHi)
		}
		if desiredLo >= rw.lo+tagSlideBatch {
			rw.evict(rw.lo, desiredLo)
		}
	}
	return true
}

// PreCheck is a cheap replay pre-filter used before the (more expensive) AEAD
// open, so obvious replays are dropped without decryption work.
func (rw *RecvWindow) PreCheck(n uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return !rw.isReplay(n)
}
