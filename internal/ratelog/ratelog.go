// Package ratelog provides a rate-limited logger for wire-triggered log
// lines: anything logged in response to a packet from the network, where an
// attacker or a misconfigured peer controls how often the line fires.
// Without this, one line of unauthenticated-input logging is itself a
// remote log-flood / disk-fill vector.
package ratelog

import (
	"log"
	"sync"
	"time"
)

// Limiter emits at most one message per interval; anything else in that
// window is counted and folded into the next line that does get emitted, so
// no information is silently lost, only its frequency is capped.
type Limiter struct {
	interval time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed uint64
}

// NewLimiter returns a Limiter that emits at most one line per interval.
func NewLimiter(interval time.Duration) *Limiter {
	return &Limiter{interval: interval}
}

// Printf logs format/args now if interval has elapsed since the last emitted
// line; otherwise it silently counts this call as suppressed.
func (l *Limiter) Printf(format string, args ...any) {
	l.mu.Lock()
	now := time.Now()
	if !l.last.IsZero() && now.Sub(l.last) < l.interval {
		l.suppressed++
		l.mu.Unlock()
		return
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.last = now
	l.mu.Unlock()

	if suppressed > 0 {
		log.Printf(format+" (+%d similar messages suppressed in the preceding %s)",
			append(append([]any{}, args...), suppressed, l.interval)...)
		return
	}
	log.Printf(format, args...)
}
