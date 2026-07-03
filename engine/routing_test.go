package engine

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	return ipnet
}

// TestRoutingLongestPrefixMatch verifies Lookup returns the most-specific route
// regardless of insertion order — the multi-router bug the LPM fix closes.
func TestRoutingLongestPrefixMatch(t *testing.T) {
	broad := &Peer{PublicKey: []byte("broad")}
	specific := &Peer{PublicKey: []byte("specific")}

	// Insert the broad /16 first and the specific /24 second: a first-match
	// linear scan would (wrongly) return broad for an address inside the /24.
	rt := NewRoutingTable()
	rt.AddRoute(mustCIDR(t, "10.8.0.0/16"), broad)
	rt.AddRoute(mustCIDR(t, "10.8.1.0/24"), specific)

	if got := rt.Lookup(net.ParseIP("10.8.1.5")); got != specific {
		t.Errorf("10.8.1.5: got %q, want specific /24 peer", peerName(got))
	}
	if got := rt.Lookup(net.ParseIP("10.8.2.5")); got != broad {
		t.Errorf("10.8.2.5: got %q, want broad /16 peer", peerName(got))
	}
	if got := rt.Lookup(net.ParseIP("10.9.0.1")); got != nil {
		t.Errorf("10.9.0.1: got %q, want no match", peerName(got))
	}
}

// TestRoutingLPMReverseInsertion confirms the result does not depend on the
// order routes were added.
func TestRoutingLPMReverseInsertion(t *testing.T) {
	broad := &Peer{PublicKey: []byte("broad")}
	specific := &Peer{PublicKey: []byte("specific")}

	rt := NewRoutingTable()
	rt.AddRoute(mustCIDR(t, "10.8.1.0/24"), specific) // specific first this time
	rt.AddRoute(mustCIDR(t, "10.8.0.0/16"), broad)

	if got := rt.Lookup(net.ParseIP("10.8.1.5")); got != specific {
		t.Errorf("10.8.1.5: got %q, want specific /24 peer", peerName(got))
	}
}

func peerName(p *Peer) string {
	if p == nil {
		return "<nil>"
	}
	return string(p.PublicKey)
}
