package engine

import (
	"testing"
	"time"
)

// TestTunnelSilent covers the silent-tunnel watchdog predicate: it fires only
// once a session exists and inbound traffic has been absent longer than
// watchdogTimeout.
func TestTunnelSilent(t *testing.T) {
	now := time.Now()
	sess := &Session{establishedAt: now.Add(-10 * time.Minute)}

	cases := []struct {
		name     string
		cur      *Session
		lastRecv time.Time
		want     bool
	}{
		{"no session yet", nil, now.Add(-time.Hour), false},
		{"just received", sess, now, false},
		{"within timeout", sess, now.Add(-(watchdogTimeout - time.Second)), false},
		{"exactly at timeout", sess, now.Add(-watchdogTimeout), false},
		{"past timeout", sess, now.Add(-(watchdogTimeout + time.Second)), true},
	}
	for _, c := range cases {
		if got := tunnelSilent(c.cur, c.lastRecv, now); got != c.want {
			t.Errorf("%s: tunnelSilent = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestMarkRecvUpdatesClock confirms markRecv/LastRecv round-trip so the watchdog
// clock actually resets on receive.
func TestMarkRecvUpdatesClock(t *testing.T) {
	p := &Peer{}
	if !p.LastRecv().IsZero() && p.LastRecv().UnixNano() != 0 {
		// zero value is fine either way; just ensure markRecv changes it
	}
	stamp := time.Now().Add(-time.Minute)
	p.markRecv(stamp)
	if got := p.LastRecv(); got.UnixNano() != stamp.UnixNano() {
		t.Errorf("LastRecv = %v, want %v", got, stamp)
	}
}
