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
		if got := tunnelSilent(c.cur, c.lastRecv, now, 0); got != c.want {
			t.Errorf("%s: tunnelSilent = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTunnelSilentScalesWithKeepaliveOverride verifies a peer with a
// PersistentKeepalive longer than watchdogTimeout/4 gets a proportionally
// longer watchdog, so its own configured keepalive cadence isn't mistaken
// for a dead tunnel.
func TestTunnelSilentScalesWithKeepaliveOverride(t *testing.T) {
	now := time.Now()
	sess := &Session{establishedAt: now.Add(-10 * time.Minute)}
	override := 60 * time.Second // 4x = 240s, well past the 90s default watchdog

	// Silent for 100s: past the fixed default watchdog, but within this
	// peer's scaled-up watchdog — must not fire.
	if tunnelSilent(sess, now.Add(-100*time.Second), now, override) {
		t.Fatal("watchdog fired before the scaled timeout for a long-keepalive peer")
	}
	// Silent well past 4x the override: must fire.
	if !tunnelSilent(sess, now.Add(-250*time.Second), now, override) {
		t.Fatal("watchdog did not fire once truly silent past the scaled timeout")
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
