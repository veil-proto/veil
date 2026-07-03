package engine

import (
	"testing"
	"time"
)

// TestSeamlessRekeySendSession pins the responder-side rekey behaviour that
// keeps the tunnel gap-free: while a freshly promoted session is unconfirmed,
// data must keep flowing on the previous (still-valid) session, and only switch
// once the peer proves it holds the new keys.
func TestSeamlessRekeySendSession(t *testing.T) {
	peer := &Peer{PublicKey: []byte{0x01}}
	now := time.Unix(1000, 0)

	a := newSession(testTransportKeys(0x10), true, now)
	peer.Promote(a, true) // initial session, confirmed
	if peer.SendSession() != a {
		t.Fatal("initial: SendSession should be the confirmed current session A")
	}

	// Responder-style rekey: B becomes current but is not yet confirmed.
	b := newSession(testTransportKeys(0x20), false, now)
	peer.Promote(b, false)
	if peer.Current() != b || peer.previous != a {
		t.Fatal("promotion did not set current=B, previous=A")
	}
	if peer.SendSession() != a {
		t.Fatal("during rekey: must keep sending on previous confirmed session A")
	}

	// Peer sends data on B -> confirmed; sending switches to B seamlessly.
	b.markConfirmed()
	if peer.SendSession() != b {
		t.Fatal("after confirmation: sending should switch to B")
	}
}
