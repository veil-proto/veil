package engine

import (
	"net"
	"sync"
)

type RoutingTable struct {
	// A linear scan with longest-prefix-match selection. Fine for the handful of
	// routes a typical deployment has; a production kmod-scale table would swap
	// this for an LPM trie (see docs/v1/VEIL-v1-kmod-design.md), but the match
	// semantics below — most-specific prefix wins — must stay identical.
	//
	// mu guards routes. Routes are installed once at startup (New) with no
	// concurrent readers yet, but Engine.AddPeer/RemovePeer can add or remove
	// routes at runtime while the tunToUDP hot loop is concurrently calling
	// Lookup, so both paths must go through the lock.
	mu     sync.RWMutex
	routes []RouteEntry
}

type RouteEntry struct {
	Network *net.IPNet
	Peer    *Peer
}

func NewRoutingTable() *RoutingTable {
	return &RoutingTable{
		routes: make([]RouteEntry, 0),
	}
}

func (rt *RoutingTable) AddRoute(network *net.IPNet, peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes = append(rt.routes, RouteEntry{
		Network: network,
		Peer:    peer,
	})
}

// RemoveRoutesForPeer drops every route pointing at peer. Used by
// Engine.RemovePeer to undo AddPeer's route installation.
func (rt *RoutingTable) RemoveRoutesForPeer(peer *Peer) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	w := 0
	for _, r := range rt.routes {
		if r.Peer == peer {
			continue
		}
		rt.routes[w] = r
		w++
	}
	rt.routes = rt.routes[:w]
}

// Lookup returns the peer owning the most-specific (longest-prefix) route that
// contains ip. Selecting by prefix length rather than insertion order is what
// makes a multi-router deployment correct: when one peer advertises 10.8.0.0/16
// and another the more specific 10.8.1.0/24, a packet to 10.8.1.5 must go to the
// /24's peer regardless of which route was configured first.
func (rt *RoutingTable) Lookup(ip net.IP) *Peer {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	var best *Peer
	bestOnes := -1
	for i := range rt.routes {
		entry := &rt.routes[i]
		if !entry.Network.Contains(ip) {
			continue
		}
		ones, _ := entry.Network.Mask.Size()
		if ones > bestOnes {
			bestOnes = ones
			best = entry.Peer
		}
	}
	return best
}

// ExtractDstIP extracts the destination IP address from a raw IP packet, handling optional PI headers.
func ExtractDstIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}

	offset := 0
	// Check for PI header (usually 4 bytes, starting with 0x00 0x00)
	if packet[0] == 0x00 && packet[1] == 0x00 && (packet[2] == 0x08 || packet[2] == 0x86) {
		offset = 4
	}

	if len(packet) < offset+20 {
		return nil
	}

	version := packet[offset] >> 4
	if version == 4 {
		return net.IP(packet[offset+16 : offset+20])
	} else if version == 6 && len(packet) >= offset+40 {
		return net.IP(packet[offset+24 : offset+40])
	}
	return nil
}
