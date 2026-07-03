package engine

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/veil-proto/veil/transport"
)

// Rekey / keepalive timing (VEIL spec §20-21).
const (
	rekeyAfterTime   = 30 * time.Minute // initiator starts a new handshake past this age
	rejectAfterTime  = 35 * time.Minute // a session is considered dead past this age
	rekeyTimeout     = 5 * time.Second  // min gap between handshake (re)tries
	keepaliveDefault = 25 * time.Second // used when a peer sets no PersistentKeepalive

	// watchdogTimeout is how long an initiator will keep sending into silence
	// before forcing a fresh handshake. Both sides send keepalives every
	// ~keepaliveDefault, so on a healthy path inbound traffic never pauses this
	// long; crossing it means the session went one-way (peer rekeyed and we
	// missed it, or the path died). Set to a few missed keepalives so ordinary
	// jitter doesn't trip it.
	watchdogTimeout = 90 * time.Second
)

// Session is one established key epoch with a peer. A peer keeps a current
// session for sending and, briefly after a rekey, a previous session that can
// still decrypt in-flight packets sent under the old keys.
type Session struct {
	keys          *transport.TransportKeys
	recv          *transport.RecvWindow
	isInitiator   bool
	establishedAt time.Time

	// confirmed is set once we know the peer also holds this session's keys:
	// true immediately for the initiator (it drove the handshake), and for the
	// responder only after the first transport packet is received on it. We
	// never send data on an unconfirmed session while an older confirmed one is
	// still usable, which keeps rekeys seamless (no downstream drop).
	confirmed atomic.Bool

	sendPN       uint64 // atomic
	lastSentNano int64  // atomic: unixnano of the last packet we sent on this session
	paddingMode  string

	fragMu sync.Mutex
	frags  map[uint32]*fragmentBuffer
}

func newSession(keys *transport.TransportKeys, isInitiator bool, now time.Time, paddingModes ...string) *Session {
	paddingMode := "light"
	if len(paddingModes) > 0 {
		paddingMode = paddingModes[0]
	}
	return &Session{
		keys:          keys,
		isInitiator:   isInitiator,
		establishedAt: now,
		lastSentNano:  now.UnixNano(),
		paddingMode:   paddingMode,
	}
}

func (s *Session) markConfirmed()    { s.confirmed.Store(true) }
func (s *Session) isConfirmed() bool { return s.confirmed.Load() }

func (s *Session) nextPN() uint64 { return atomic.AddUint64(&s.sendPN, 1) - 1 }

func (s *Session) markSent(t time.Time) { atomic.StoreInt64(&s.lastSentNano, t.UnixNano()) }

func (s *Session) lastSent() time.Time { return time.Unix(0, atomic.LoadInt64(&s.lastSentNano)) }

func (s *Session) age(now time.Time) time.Duration { return now.Sub(s.establishedAt) }

// tunnelSilent reports whether an established tunnel has gone quiet long enough
// to be treated as silently dead: there is a current session (so we've
// connected at least once) but nothing valid has arrived from the peer for
// longer than the effective watchdog timeout. Pure function of its inputs so
// it can be tested without the maintenance loop's real-time clock.
func tunnelSilent(cur *Session, lastRecv, now time.Time, keepaliveOverride time.Duration) bool {
	return cur != nil && now.Sub(lastRecv) > effectiveWatchdogTimeout(keepaliveOverride)
}

// effectiveWatchdogTimeout scales the watchdog with a peer's configured
// PersistentKeepalive: a peer that keeps alive every 120s can go silent for
// close to that long as ordinary jitter, not a dead tunnel, so watchdogTimeout
// alone would misfire for anyone with a keepalive interval longer than about
// watchdogTimeout/4. Peers using the default keepalive get the unmodified
// constant.
func effectiveWatchdogTimeout(keepaliveOverride time.Duration) time.Duration {
	if scaled := keepaliveOverride * 4; scaled > watchdogTimeout {
		return scaled
	}
	return watchdogTimeout
}
